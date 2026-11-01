'use strict';

const http = require('http');
const crypto = require('crypto');
const { WebSocketServer, WebSocket } = require('ws');

/* ───────────────────────── Config ───────────────────────── */

const PORT = parseInt(process.env.PORT || '8000', 10);
const PROXY_PASSWORD = process.env.PROXY_PASSWORD; // password jo browser/AdsPower mein dalna hai
const DEVICE_SECRET = process.env.DEVICE_SECRET;   // per-device token banane ke liye HMAC secret

if (!PROXY_PASSWORD || !DEVICE_SECRET) {
    console.error('PROXY_PASSWORD aur DEVICE_SECRET environment variables set karna zaroori hai.');
    process.exit(1);
}

const MAX_TUNNELS_PER_DEVICE = 200;
const MAX_REQUEST_BODY = 10 * 1024 * 1024;     // plain-HTTP request body limit
const MAX_WS_PAYLOAD = 16 * 1024 * 1024;       // phone se aane wale ek message ki limit
const HTTP_TIMEOUT_MS = 60_000;
const CONNECT_TIMEOUT_MS = 30_000;
const TUNNEL_IDLE_MS = 10 * 60_000;
const WS_HIGH_WATER = 1024 * 1024;             // itna buffer jama ho to client socket pause
const WS_LOW_WATER = 256 * 1024;
const AUTH_FAIL_LIMIT = 20;                    // is window mein itne galat attempts -> block
const AUTH_FAIL_WINDOW_MS = 10 * 60_000;
const DEVICE_ID_RE = /^[A-Za-z0-9._-]{1,64}$/;
const HOST_PORT_RE = /^(?:\[[0-9a-fA-F:.]+\]|[A-Za-z0-9._-]+):\d{1,5}$/;

const HOP_BY_HOP = new Set([
    'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
    'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'upgrade', 'host',
]);

/* ───────────────────────── State ───────────────────────── */

// deviceId -> { ws, tunnels:Set<tunnelId> }
const nodes = new Map();
// tunnelId -> tunnel object (kind: 'http' | 'connect')
const tunnels = new Map();
// ip -> { count, resetAt }
const authFailures = new Map();

/* ───────────────────────── Helpers ───────────────────────── */

function sha256(s) {
    return crypto.createHash('sha256').update(s).digest();
}

function safeEqual(a, b) {
    // Dono ko hash karke compare karte hain taaki length leak na ho
    return crypto.timingSafeEqual(sha256(String(a)), sha256(String(b)));
}

function deviceToken(deviceId) {
    return crypto.createHmac('sha256', DEVICE_SECRET).update(deviceId).digest('hex');
}

function clientIp(req) {
    return req.socket.remoteAddress || 'unknown';
}

function isBlocked(ip) {
    const e = authFailures.get(ip);
    if (!e) return false;
    if (Date.now() > e.resetAt) { authFailures.delete(ip); return false; }
    return e.count >= AUTH_FAIL_LIMIT;
}

function recordFailure(ip) {
    const now = Date.now();
    const e = authFailures.get(ip);
    if (!e || now > e.resetAt) authFailures.set(ip, { count: 1, resetAt: now + AUTH_FAIL_WINDOW_MS });
    else e.count++;
}

setInterval(() => {
    const now = Date.now();
    for (const [ip, e] of authFailures) if (now > e.resetAt) authFailures.delete(ip);
}, 60_000).unref();

/**
 * Proxy-Authorization: Basic base64(deviceId:PROXY_PASSWORD)
 * Returns { deviceId } | { error: 'missing' | 'invalid' }
 */
function authenticateProxy(req) {
    const header = req.headers['proxy-authorization'];
    if (!header || !header.startsWith('Basic ')) return { error: 'missing' };
    try {
        const creds = Buffer.from(header.slice(6), 'base64').toString('utf8');
        const idx = creds.indexOf(':'); // password mein ':' ho sakta hai
        if (idx < 1) return { error: 'invalid' };
        const deviceId = creds.slice(0, idx);
        const password = creds.slice(idx + 1);
        if (!DEVICE_ID_RE.test(deviceId) || !safeEqual(password, PROXY_PASSWORD)) return { error: 'invalid' };
        return { deviceId };
    } catch {
        return { error: 'invalid' };
    }
}

function wsSend(ws, obj) {
    if (ws.readyState !== WebSocket.OPEN) return false;
    try { ws.send(JSON.stringify(obj)); return true; } catch { return false; }
}

function wsSendFrame(ws, tunnelId, chunk) {
    if (ws.readyState !== WebSocket.OPEN) return false;
    try {
        const idBytes = Buffer.from(tunnelId, 'utf8');
        const packet = Buffer.allocUnsafe(4 + idBytes.length + chunk.length);
        packet.writeUInt32BE(idBytes.length, 0);
        idBytes.copy(packet, 4);
        chunk.copy(packet, 4 + idBytes.length);
        ws.send(packet);
        return true;
    } catch {
        return false;
    }
}

function cleanRequestHeaders(headers) {
    const out = {};
    for (const [k, v] of Object.entries(headers)) {
        const lk = k.toLowerCase();
        if (HOP_BY_HOP.has(lk) || lk === 'content-length') continue;
        out[lk] = v;
    }
    return out;
}

function proxyAuthRequired(res) {
    res.writeHead(407, { 'Proxy-Authenticate': 'Basic realm="Device ID as username"', 'Content-Length': 0 });
    res.end();
}

function registerTunnel(node, tunnel) {
    tunnels.set(tunnel.id, tunnel);
    node.tunnels.add(tunnel.id);
}

/**
 * Tunnel ko ek jagah se close karo: timers, maps, sockets sab saaf.
 * notify  -> phone ko CLOSE bhejo
 * graceful-> client socket pe end() (pending data flush ho jaye), warna destroy()
 */
function closeTunnel(id, { notify = false, graceful = false } = {}) {
    const t = tunnels.get(id);
    if (!t) return;
    tunnels.delete(id);
    t.node.tunnels.delete(id);
    clearTimeout(t.timer);
    clearTimeout(t.drainTimer);
    if (notify) wsSend(t.ws, { type: 'CLOSE', tunnelId: id });

    if (t.kind === 'connect') {
        if (graceful) t.socket.end(); else t.socket.destroy();
    } else if (t.res && !t.res.headersSent && !t.res.writableEnded) {
        try { t.res.writeHead(502); t.res.end('Bad Gateway'); } catch { /* ignore */ }
    }
}

// CONNECT tunnel: pause/resume logic (phone ne PAUSE bola ya ws buffer bhar gaya)
function applyPause(t) {
    if (t.socket.destroyed) return;
    if (t.phonePaused || t.wsBusy || !t.established) t.socket.pause();
    else t.socket.resume();
}

function pollDrain(t) {
    t.drainTimer = setTimeout(() => {
        if (!tunnels.has(t.id)) return;
        if (t.ws.bufferedAmount > WS_LOW_WATER) return pollDrain(t);
        t.wsBusy = false;
        applyPause(t);
    }, 25);
}

/* ───────────────────────── 1. Plain HTTP proxy ───────────────────────── */

const server = http.createServer();

server.on('clientError', (err, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
});

server.on('request', (req, res) => {
    const ip = clientIp(req);
    if (isBlocked(ip)) { res.writeHead(429); res.end('Too Many Requests'); return; }

    const auth = authenticateProxy(req);
    if (!auth.deviceId) {
        if (auth.error === 'invalid') recordFailure(ip);
        return proxyAuthRequired(res);
    }

    const node = nodes.get(auth.deviceId);
    if (!node) { res.writeHead(503); res.end('Device offline'); return; }
    if (node.tunnels.size >= MAX_TUNNELS_PER_DEVICE) { res.writeHead(503); res.end('Too many tunnels'); return; }
    if (!/^https?:\/\//i.test(req.url)) { res.writeHead(400); res.end('Absolute URL required'); return; }

    const chunks = [];
    let size = 0;
    let rejected = false;

    req.on('data', (c) => {
        if (rejected) return;
        size += c.length;
        if (size > MAX_REQUEST_BODY) {
            rejected = true;
            res.writeHead(413); res.end('Payload Too Large');
            req.destroy();
            return;
        }
        chunks.push(c);
    });

    req.on('end', () => {
        if (rejected || res.writableEnded) return;

        const id = crypto.randomUUID();
        const t = { kind: 'http', id, node, ws: node.ws, res, method: req.method };
        registerTunnel(node, t);

        t.timer = setTimeout(() => {
            if (!res.headersSent) { res.writeHead(504); res.end('Gateway Timeout'); }
            closeTunnel(id, { notify: true });
        }, HTTP_TIMEOUT_MS);

        // Client ne beech mein connection tod diya -> phone ko cancel bolo
        res.on('close', () => closeTunnel(id, { notify: true }));

        const msg = {
            type: 'HTTP',
            tunnelId: id,
            method: req.method,
            url: req.url,
            headers: cleanRequestHeaders(req.headers),
        };
        if (chunks.length) msg.body = Buffer.concat(chunks).toString('base64');

        if (!wsSend(node.ws, msg)) {
            if (!res.headersSent) { res.writeHead(502); res.end('Device unavailable'); }
            closeTunnel(id);
        }
    });
});

function handleHttpResponse(t, msg) {
    const res = t.res;
    if (!res || res.headersSent || res.writableEnded) return;

    const status = Number.isInteger(msg.statusCode) && msg.statusCode >= 200 && msg.statusCode <= 599
        ? msg.statusCode : 502;
    const body = msg.body ? Buffer.from(msg.body, 'base64') : Buffer.alloc(0);

    const headers = {};
    let originLength;
    for (const [k, v] of Object.entries(msg.headers || {})) {
        const lk = k.toLowerCase();
        if (lk === 'content-length') { originLength = Array.isArray(v) ? v[0] : v; continue; }
        if (HOP_BY_HOP.has(lk)) continue;
        headers[lk] = v; // Set-Cookie jaise multi-value headers array rehte hain
    }

    const noBody = t.method === 'HEAD' || status === 204 || status === 304;
    if (t.method === 'HEAD' || status === 304) {
        if (originLength !== undefined) headers['content-length'] = String(originLength);
    } else if (status !== 204) {
        headers['content-length'] = String(body.length);
    }

    try {
        res.writeHead(status, headers);
        res.end(noBody ? undefined : body);
    } catch {
        try { res.writeHead(502); res.end('Invalid upstream response'); } catch { /* ignore */ }
    }
    closeTunnel(t.id);
}

/* ───────────────────────── 2. HTTPS CONNECT tunnel ───────────────────────── */

server.on('connect', (req, clientSocket, head) => {
    clientSocket.on('error', () => { /* 'close' handler cleanup karega */ });

    const ip = clientIp(req);
    const reject = (line, extra = '') => {
        clientSocket.write(`HTTP/1.1 ${line}\r\n${extra}Connection: close\r\n\r\n`);
        clientSocket.end();
    };

    if (isBlocked(ip)) return reject('429 Too Many Requests');

    const auth = authenticateProxy(req);
    if (!auth.deviceId) {
        if (auth.error === 'invalid') recordFailure(ip);
        return reject('407 Proxy Authentication Required', 'Proxy-Authenticate: Basic realm="Device ID as username"\r\n');
    }

    const node = nodes.get(auth.deviceId);
    if (!node) return reject('503 Device Offline');
    if (node.tunnels.size >= MAX_TUNNELS_PER_DEVICE) return reject('503 Too Many Tunnels');
    if (!HOST_PORT_RE.test(req.url)) return reject('400 Bad Request');

    const id = crypto.randomUUID();
    const t = {
        kind: 'connect', id, node, ws: node.ws, socket: clientSocket,
        established: false, phonePaused: false, wsBusy: false, pausedByUs: false,
        head: head && head.length ? head : null,
    };
    registerTunnel(node, t);

    clientSocket.pause(); // 200 se pehle data forward nahi karna
    clientSocket.setTimeout(TUNNEL_IDLE_MS, () => clientSocket.destroy());

    // Phone ko 30s mein destination connect karna hai, warna 504
    t.timer = setTimeout(() => {
        if (!t.established && tunnels.has(id)) {
            clientSocket.write('HTTP/1.1 504 Gateway Timeout\r\n\r\n');
            closeTunnel(id, { notify: true, graceful: true });
        }
    }, CONNECT_TIMEOUT_MS);

    clientSocket.on('data', (chunk) => {
        if (!t.established) return;
        if (!wsSendFrame(t.ws, id, chunk)) return closeTunnel(id, { notify: true });
        if (t.ws.bufferedAmount > WS_HIGH_WATER && !t.wsBusy) {
            t.wsBusy = true;
            applyPause(t);
            pollDrain(t);
        }
    });

    clientSocket.on('close', () => closeTunnel(id, { notify: true }));

    if (!wsSend(node.ws, { type: 'CONNECT', tunnelId: id, host: req.url })) {
        reject('502 Bad Gateway');
        closeTunnel(id);
    }
});

function handleConnectAck(t, msg) {
    if (t.established) return;
    clearTimeout(t.timer);

    if (msg.success) {
        t.established = true;
        t.socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (t.head) { wsSendFrame(t.ws, t.id, t.head); t.head = null; } // CONNECT ke saath aaya early data
        applyPause(t);
    } else {
        const code = String(msg.error || 'UPSTREAM_ERROR').replace(/[^A-Z_]/g, '');
        const status = code === 'TIMEOUT' ? '504 Gateway Timeout'
            : code === 'TARGET_BLOCKED' || code === 'PORT_BLOCKED' ? '403 Forbidden'
            : '502 Bad Gateway';
        t.socket.write(`HTTP/1.1 ${status}\r\nX-Proxy-Error: ${code}\r\n\r\n`);
        closeTunnel(t.id, { graceful: true });
    }
}

/* ───────────────────────── 3. WebSocket (phone) side ───────────────────────── */

const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_WS_PAYLOAD, perMessageDeflate: false });

server.on('upgrade', (req, socket, head) => {
    socket.on('error', () => {});
    const ip = clientIp(req);
    const deny = (line) => { socket.write(`HTTP/1.1 ${line}\r\nConnection: close\r\n\r\n`); socket.destroy(); };

    if (isBlocked(ip)) return deny('429 Too Many Requests');

    let u;
    try { u = new URL(req.url, 'http://localhost'); } catch { return deny('400 Bad Request'); }
    if (u.pathname !== '/ws') return deny('404 Not Found');

    const deviceId = u.searchParams.get('device_id') || '';
    const token = req.headers['x-device-token'] || '';
    if (!DEVICE_ID_RE.test(deviceId) || !safeEqual(token, deviceToken(deviceId))) {
        recordFailure(ip);
        return deny('401 Unauthorized');
    }

    wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req, deviceId));
});

wss.on('connection', (ws, req, deviceId) => {
    // Same device dobara connect kare to purana connection hata do
    const old = nodes.get(deviceId);
    if (old) {
        for (const id of [...old.tunnels]) closeTunnel(id);
        old.ws.close(4000, 'Replaced by new connection');
    }

    const node = { ws, tunnels: new Set() };
    nodes.set(deviceId, node);
    ws.isAlive = true;
    ws.on('pong', () => { ws.isAlive = true; });
    ws.on('error', () => {});
    console.log(`[+] Phone connected: ${deviceId}`);

    ws.on('message', (message, isBinary) => {
        if (isBinary) onPhoneBinary(ws, Buffer.from(message));
        else onPhoneText(ws, message.toString());
    });

    ws.on('close', () => {
        if (nodes.get(deviceId) === node) nodes.delete(deviceId);
        for (const id of [...node.tunnels]) closeTunnel(id); // http ko 502 milega, connect sockets destroy
        console.log(`[-] Phone disconnected: ${deviceId}`);
    });
});

function onPhoneBinary(ws, data) {
    if (data.length < 4) return;
    const idLen = data.readUInt32BE(0);
    if (idLen === 0 || idLen > 128 || data.length < 4 + idLen) return;

    const id = data.toString('utf8', 4, 4 + idLen);
    const t = tunnels.get(id);
    if (!t || t.ws !== ws || t.kind !== 'connect' || !t.established || t.socket.destroyed) return;

    const ok = t.socket.write(data.subarray(4 + idLen));
    if (!ok && !t.pausedByUs) {
        // Browser slow hai -> phone ko destination se padhna rokne bolo
        t.pausedByUs = true;
        wsSend(ws, { type: 'PAUSE', tunnelId: id });
        t.socket.once('drain', () => {
            t.pausedByUs = false;
            wsSend(ws, { type: 'RESUME', tunnelId: id });
        });
    }
}

function onPhoneText(ws, text) {
    let msg;
    try { msg = JSON.parse(text); } catch { return; }
    const t = tunnels.get(msg.tunnelId);
    if (!t || t.ws !== ws) return; // sirf apne tunnels par kaam

    switch (msg.type) {
        case 'CONNECT_ACK': if (t.kind === 'connect') handleConnectAck(t, msg); break;
        case 'HTTP_RES': if (t.kind === 'http') handleHttpResponse(t, msg); break;
        case 'PAUSE': if (t.kind === 'connect') { t.phonePaused = true; applyPause(t); } break;
        case 'RESUME': if (t.kind === 'connect') { t.phonePaused = false; applyPause(t); } break;
        case 'CLOSED': closeTunnel(t.id, { graceful: true }); break; // destination ne band kiya
        default: break;
    }
}

// Dead phone connections detect karne ke liye heartbeat
setInterval(() => {
    for (const ws of wss.clients) {
        if (!ws.isAlive) { ws.terminate(); continue; }
        ws.isAlive = false;
        try { ws.ping(); } catch { /* ignore */ }
    }
}, 30_000).unref();

/* ───────────────────────── Start / shutdown ───────────────────────── */

server.listen(PORT, () => console.log(`Mobile proxy gateway listening on :${PORT}`));

function shutdown() {
    console.log('Shutting down...');
    for (const id of [...tunnels.keys()]) closeTunnel(id);
    for (const ws of wss.clients) ws.close(1001, 'Server restarting');
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
process.on('unhandledRejection', (e) => console.error('unhandledRejection', e));
process.on('uncaughtException', (e) => console.error('uncaughtException', e));
