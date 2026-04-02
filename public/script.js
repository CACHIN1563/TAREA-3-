let token = localStorage.getItem('rsa_token') || null;
let user = JSON.parse(localStorage.getItem('rsa_user')) || null;
let allMessages = [];
let currentFilter = 'all';

const API_URL = ''; // Relative to the server

document.addEventListener('DOMContentLoaded', () => {
    if (token) {
        showApp();
    }
});

function showTab(tab) {
    document.querySelectorAll('.tab-content, .tab-btn').forEach(el => el.classList.remove('active'));
    document.getElementById(`${tab}-form`).classList.add('active');
    event.target.classList.add('active');
}

async function register() {
    const user = document.getElementById('reg-user').value;
    const pass = document.getElementById('reg-pass').value;
    const res = await fetch(`${API_URL}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: user, password: pass })
    });
    if (res.ok) {
        alert('Registro exitoso. Ahora puedes ingresar.');
        showTab('login');
    } else {
        alert('Error al registrar');
    }
}

async function login() {
    const username = document.getElementById('login-user').value;
    const pass = document.getElementById('login-pass').value;
    const res = await fetch(`${API_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password: pass })
    });
    const data = await res.json();
    if (res.ok) {
        token = data.token;
        user = { username };
        localStorage.setItem('rsa_token', token);
        localStorage.setItem('rsa_user', JSON.stringify(user));
        showApp();
    } else {
        alert('Credenciales incorrectas');
    }
}

function showApp() {
    document.getElementById('auth-container').classList.add('hidden');
    document.getElementById('app-container').classList.remove('hidden');
    document.getElementById('user-display').innerText = user.username;
    loadHistory();
}

function logout() {
    localStorage.clear();
    location.reload();
}

async function encryptMessage() {
    const texto = document.getElementById('encrypt-text').value;
    if (!texto) return alert('Escribe algo');

    const res = await fetch(`${API_URL}/api/messages`, {
        method: 'POST',
        headers: { 
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ texto, bits: 2048 }) // Se envía por defecto, aunque backend lo ignora
    });
    const data = await res.json();
    if (res.ok) {
        showModal(`
            <div class="success-box">
                <h3>✅ ¡Texto Cifrado con Éxito!</h3>
                <p>Comparte este token para que alguien pueda leerlo una sola vez:</p>
                <div class="token-display">${data.token}</div>
                <button class="btn-copy" onclick="copyToken('${data.token}')">Copiar al portapapeles</button>
                <a href="mailto:?subject=Mensaje Cifrado Confidencial&body=Tengo un mensaje cifrado para ti. Ingresa a la plataforma y usa este Token para descifrarlo:%0A%0A${data.token}" class="btn-secondary" style="display:inline-block; text-align:center; text-decoration:none; margin-top:10px;">📧 Enviar Token por Correo</a>
                <p class="warning-txt">⚠️ El token expirará en 7 días y solo sirve para 1 lectura.</p>
            </div>
        `);
        document.getElementById('encrypt-text').value = '';
        loadHistory();
    }
}

async function loadHistory() {
    const res = await fetch(`${API_URL}/api/messages`, {
        headers: { 'Authorization': `Bearer ${token}` }
    });
    const messages = await res.json();
    allMessages = messages;
    renderHistory();
}

function applyFilter(filter) {
    currentFilter = filter;
    document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
    renderHistory();
}

async function renderHistory() {
    const container = document.getElementById('history-list');
    container.innerHTML = '';

    let limitador = allMessages;
    
    if (currentFilter === 'unread') limitador = allMessages.filter(m => m.activo && !m.es_usado);
    if (currentFilter === 'read') limitador = allMessages.filter(m => m.es_usado);
    if (currentFilter === 'deleted') limitador = allMessages.filter(m => !m.activo);

    if (limitador.length === 0) {
        container.innerHTML = '<p class="empty-msg">No hay registros aún para esta vista.</p>';
        return;
    }

    limitador.forEach(async msg => {
        const auditRes = await fetch(`${API_URL}/api/messages/${msg.id}/audit`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const auditLogs = await auditRes.json();

        const card = document.createElement('div');
        card.className = 'history-card';
        card.innerHTML = `
            <div class="card-header">
                <span class="badge ${msg.activo ? (msg.es_usado ? 'badge-used' : 'badge-active') : 'badge-inactive'}">
                    ${msg.activo ? (msg.es_usado ? 'USADO/LEÍDO' : 'DISPONIBLE') : 'ELIMINADO'}
                </span>
                <span class="date">${new Date(msg.fecha_creacion).toLocaleDateString()}</span>
            </div>
            <h3>Token: <code>${msg.token_valor}</code></h3>
            
            <div class="audit-logs">
                <strong>Auditoría:</strong>
                ${auditLogs.map(log => `
                    <div class="audit-item">
                        [${log.accion}] ${new Date(log.timestamp).toLocaleTimeString()} - ${log.detalles}
                    </div>
                `).join('')}
            </div>
            
            <div style="margin-top: 10px; display: flex; gap: 10px;">
                <button class="btn-secondary" style="width:auto; padding:5px 15px; font-size:0.8rem;" onclick="viewMyContent(${msg.id})">👁️ Ver Contenido</button>
                ${msg.activo ? `<button class="btn-small-danger" style="margin-top:0;" onclick="inactivate(${msg.id})">🗑️ Eliminar</button>` : ''}
            </div>
        `;
        container.appendChild(card);
    });
}

function exportHistory() {
    if (allMessages.length === 0) return alert('No hay historial para exportar.');
    
    let content = "REPORTE DE HISTORIAL DE CIFRADO\n================================\n\n";
    allMessages.forEach(msg => {
        let estado = msg.activo ? (msg.es_usado ? 'USADO/LEÍDO' : 'DISPONIBLE') : 'ELIMINADO';
        content += `Fecha: ${new Date(msg.fecha_creacion).toLocaleString()}\n`;
        content += `Token: ${msg.token_valor}\n`;
        content += `Estado: ${estado}\n`;
        content += `--------------------------------\n`;
    });

    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Historial_Cifrado_${new Date().getTime()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

async function viewMyContent(id) {
    const res = await fetch(`${API_URL}/api/messages/${id}/decrypt_owner`, {
        headers: { 'Authorization': `Bearer ${token}` }
    });
    const data = await res.json();
    if (res.ok) {
        showModal(`
            <div class="decrypt-result">
                <h3>Tu Mensaje Original</h3>
                <div class="original-text">${data.texto}</div>
                <hr>
                <p><small>Este es tu texto propietario, puedes verlo cuantas veces quieras.</small></p>
            </div>
        `);
    } else {
        alert(data.error || 'Error al obtener tu mensaje');
    }
}


async function inactivate(id) {
    if (!confirm('¿Deseas eliminar este mensaje? Ya no podrá ser descifrado por terceros.')) return;
    const res = await fetch(`${API_URL}/api/messages/${id}/inactivate`, {
        method: 'PUT',
        headers: { 'Authorization': `Bearer ${token}` }
    });
    if (res.ok) loadHistory();
}

async function decryptWithToken() {
    const tokenVal = document.getElementById('token-input').value;
    if (!tokenVal) return alert('Ingresa un token');

    const res = await fetch(`${API_URL}/api/decrypt/${tokenVal}`);
    const data = await res.json();

    if (res.ok) {
        showModal(`
            <div class="decrypt-result">
                <h3>🔓 Mensaje Descifrado</h3>
                <div class="original-text">${data.texto}</div>
                <hr>
                <p><strong>Enviado por:</strong> ${data.emisor}</p>
                <p><strong>Fecha de lectura:</strong> ${new Date(data.fecha).toLocaleString()}</p>
                <p class="warning-txt">Este token ha sido "quemado" y no podrá usarse otra vez.</p>
            </div>
        `);
    } else {
        alert(data.error || 'Token inválido');
    }
}

function showModal(content) {
    document.getElementById('modal-body').innerHTML = content;
    document.getElementById('modal-result').classList.remove('hidden');
}

function closeModal(id) {
    document.getElementById(id).classList.add('hidden');
}

function copyToken(text) {
    navigator.clipboard.writeText(text);
    alert('Token copiado al portapapeles');
}
