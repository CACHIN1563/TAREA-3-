const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const path = require('path');

async function setupDB() {
    const db = await open({
        filename: path.join(__dirname, '..', 'data', 'database.sqlite'),
        driver: sqlite3.Database
    });

    // Crear tablas
    await db.exec(`
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        );

        CREATE TABLE IF NOT EXISTS mensajes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            id_usuario INTEGER,
            contenido_cifrado TEXT,
            llave_publica TEXT,
            llave_privada TEXT,
            bits INTEGER,
            fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP,
            activo BOOLEAN DEFAULT 1,
            FOREIGN KEY(id_usuario) REFERENCES usuarios(id)
        );

        CREATE TABLE IF NOT EXISTS tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_valor TEXT UNIQUE,
            id_mensaje INTEGER,
            es_usado BOOLEAN DEFAULT 0,
            fecha_expiracion DATETIME,
            FOREIGN KEY(id_mensaje) REFERENCES mensajes(id)
        );

        CREATE TABLE IF NOT EXISTS auditoria (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            id_mensaje INTEGER,
            accion TEXT, -- CIFRADO, LECTURA, INTENTO_FALLIDO, INACTIVACION
            ip_origen TEXT,
            user_agent TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            detalles TEXT,
            FOREIGN KEY(id_mensaje) REFERENCES mensajes(id)
        );
    `);

    return db;
}

module.exports = setupDB;
