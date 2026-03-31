const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const setupDB = require('./db');
const { generateKeyPair, encryptText, decryptText } = require('./crypto_engine');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'umg_analisis_sistemas_tarea3_2026';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

let db;

// Middleware de autenticación
const authenticate = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).send('Acceso denegado');
    try {
        const decoded = jwt.verify(token.split(' ')[1], SECRET_KEY);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(400).send('Token inválido');
    }
};

// Rutas de Usuario
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    try {
        await db.run('INSERT INTO usuarios (username, password) VALUES (?, ?)', [username, password]);
        res.status(201).json({ message: 'Usuario registrado' });
    } catch (err) {
        res.status(400).json({ error: 'Error al registrar usuario' });
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await db.get('SELECT * FROM usuarios WHERE username = ? AND password = ?', [username, password]);
    if (user) {
        const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY);
        res.json({ token });
    } else {
        res.status(401).json({ error: 'Credenciales inválidas' });
    }
});

// Cifrar Mensaje
app.post('/api/messages', authenticate, async (req, res) => {
    const { texto, bits } = req.body;
    const bitSize = parseInt(bits) || 2048;

    // 1. Generar Llaves
    const keys = generateKeyPair(bitSize);
    
    // 2. Cifrar
    const encrypted = encryptText(texto, keys.public);
    
    // 3. Guardar en Base de Datos
    const result = await db.run(
        'INSERT INTO mensajes (id_usuario, contenido_cifrado, llave_publica, llave_privada, bits) VALUES (?, ?, ?, ?, ?)',
        [req.user.id, encrypted, keys.public, keys.private, bitSize]
    );
    const mensajeId = result.lastID;

    // 4. Generar Token
    const tokenValor = uuidv4().substring(0, 8).toUpperCase();
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7); // 1 semana

    await db.run(
        'INSERT INTO tokens (token_valor, id_mensaje, fecha_expiracion) VALUES (?, ?, ?)',
        [tokenValor, mensajeId, expiresAt.toISOString()]
    );

    // 5. Auditoría
    await db.run(
        'INSERT INTO auditoria (id_mensaje, accion, ip_origen, user_agent, detalles) VALUES (?, ?, ?, ?, ?)',
        [mensajeId, 'CIFRADO', req.ip, req.headers['user-agent'], `Mensaje cifrado con ${bitSize} bits por ${req.user.username}`]
    );

    res.json({ token: tokenValor });
});

// Historial del Usuario
app.get('/api/messages', authenticate, async (req, res) => {
    const historical = await db.all(`
        SELECT m.*, t.token_valor, t.es_usado, t.fecha_expiracion 
        FROM mensajes m
        JOIN tokens t ON m.id = t.id_mensaje
        WHERE m.id_usuario = ?
        ORDER BY m.fecha_creacion DESC
    `, [req.user.id]);
    res.json(historical);
});

// Auditoría por mensaje
app.get('/api/messages/:id/audit', authenticate, async (req, res) => {
    const logs = await db.all('SELECT * FROM auditoria WHERE id_mensaje = ? ORDER BY timestamp DESC', [req.params.id]);
    res.json(logs);
});

// Descifrar (Público mediante Token)
app.get('/api/decrypt/:token', async (req, res) => {
    const tokenData = await db.get(`
        SELECT t.*, m.contenido_cifrado, m.llave_privada, m.activo, u.username as emisor
        FROM tokens t
        JOIN mensajes m ON t.id_mensaje = m.id
        JOIN usuarios u ON m.id_usuario = u.id
        WHERE t.token_valor = ?
    `, [req.params.token]);

    if (!tokenData) {
        return res.status(404).json({ error: 'Token no encontrado' });
    }

    if (!tokenData.activo) {
        return res.status(403).json({ error: 'Mensaje inactivado' });
    }

    if (tokenData.es_usado) {
        await db.run(
            'INSERT INTO auditoria (id_mensaje, accion, ip_origen, user_agent, detalles) VALUES (?, ?, ?, ?, ?)',
            [tokenData.id_mensaje, 'INTENTO_FALLIDO', req.ip, req.headers['user-agent'], 'Token ya utilizado anteriormente']
        );
        return res.status(403).json({ error: 'Token de un solo uso ya consumido' });
    }

    if (new Date(tokenData.fecha_expiracion) < new Date()) {
        return res.status(403).json({ error: 'Token expirado (más de 1 semana)' });
    }

    // Descifrar
    const originalText = decryptText(tokenData.contenido_cifrado, tokenData.llave_privada);

    // Marcar como usado
    await db.run('UPDATE tokens SET es_usado = 1 WHERE id = ?', [tokenData.id]);

    // Registrar Auditoría
    await db.run(
        'INSERT INTO auditoria (id_mensaje, accion, ip_origen, user_agent, detalles) VALUES (?, ?, ?, ?, ?)',
        [tokenData.id_mensaje, 'LECTURA', req.ip, req.headers['user-agent'], 'Descifrado exitoso']
    );

    res.json({
        texto: originalText,
        emisor: tokenData.emisor,
        fecha: new Date().toISOString()
    });
});

// Inactivar Mensaje
app.put('/api/messages/:id/inactivate', authenticate, async (req, res) => {
    await db.run('UPDATE mensajes SET activo = 0 WHERE id = ? AND id_usuario = ?', [req.params.id, req.user.id]);
    
    await db.run(
        'INSERT INTO auditoria (id_mensaje, accion, ip_origen, user_agent, detalles) VALUES (?, ?, ?, ?, ?)',
        [req.params.id, 'INACTIVACION', req.ip, req.headers['user-agent'], 'Mensaje inactivado por el usuario']
    );

    res.json({ message: 'Mensaje inactivado' });
});

// Inicialización de DB y Servidor
setupDB().then(database => {
    db = database;
    app.listen(PORT, () => {
        console.log(`Servidor ejecutándose en http://localhost:${PORT}`);
    });
});
