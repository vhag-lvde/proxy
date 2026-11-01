const http = require('http');
const net = require('net');
const { WebSocketServer } = require('ws');
const url = require('url');
const crypto = require('crypto');

const server = http.createServer();
const wss = new WebSocketServer({ noServer: true });

const connectedNodes = new Map(); // deviceId -> ws connection
const pendingSockets = new Map(); // tunnelId -> { clientSocket or res, ws }

// Secure Proxy Authentication helper (Username + Password validation agar chahiye ho)
function authenticateProxy(req) {
    const authHeader = req.headers['proxy-authorization'];
    if (!authHeader || !authHeader.startsWith('Basic ')) return null;
    
    try {
        const base64Credentials = authHeader.split(' ')[1];
        const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
        const [username, password] = credentials.split(':');
        // Yahan aap password bhi validate kar sakte hain agar zaroorat ho
        return username; // deviceId
    } catch (e) {
        return null;
    }
}

// 1. Handle Standard HTTP Proxy Requests
server.on('request', (req, res) => {
    const deviceId = authenticateProxy(req);
    if (!deviceId || !connectedNodes.has(deviceId)) {
        res.writeHead(407, { 'Proxy-Authenticate': 'Basic realm="Enter Device ID as Username"' });
        res.end('Proxy Authentication Required');
        return;
    }

    const ws = connectedNodes.get(deviceId);
    const tunnelId = crypto.randomUUID();
    pendingSockets.set(tunnelId, { target: res, ws });

    ws.send(JSON.stringify({
        type: 'HTTP',
        tunnelId,
        method: req.method,
        url: req.url,
        headers: req.headers
    }));

    let bodyChunks = [];
    req.on('data', chunk => bodyChunks.push(chunk));
    req.on('end', () => {
        if (bodyChunks.length > 0) {
            const body = Buffer.concat(bodyChunks).toString('base64');
            ws.send(JSON.stringify({ type: 'HTTP_BODY', tunnelId, body }));
        }
    });

    req.on('close', () => {
        pendingSockets.delete(tunnelId);
    });
});

// 2. Handle HTTPS CONNECT Tunneling with ACK Handshake
server.on('connect', (req, clientSocket, head) => {
    const deviceId = authenticateProxy(req);
    if (!deviceId || !connectedNodes.has(deviceId)) {
        clientSocket.write('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Enter Device ID"\r\n\r\n');
        clientSocket.end();
        return;
    }

    const ws = connectedNodes.get(deviceId);
    const tunnelId = crypto.randomUUID();
    
    // Store socket temporarily; 200 response sent ONLY after Android ACKs connection success
    pendingSockets.set(tunnelId, { target: clientSocket, ws, established: false });

    // Tell Android phone to open a TCP socket to the target host via Mobile Data
    ws.send(JSON.stringify({
        type: 'CONNECT',
        tunnelId,
        host: req.url // e.g. "example.com:443"
    }));

    clientSocket.on('data', (chunk) => {
        const tunnelObj = pendingSockets.get(tunnelId);
        if (tunnelObj && tunnelObj.established && ws.readyState === ws.OPEN) {
            const idBytes = Buffer.from(tunnelId, 'utf-8');
            const packet = Buffer.alloc(4 + idBytes.length + chunk.length);
            packet.writeUInt32BE(idBytes.length, 0);
            idBytes.copy(packet, 4);
            chunk.copy(packet, 4 + idBytes.length);
            ws.send(packet);
        }
    });

    clientSocket.on('close', () => {
        pendingSockets.delete(tunnelId);
        if (ws.readyState === ws.OPEN) {
            ws.send(JSON.stringify({ type: 'CLOSE', tunnelId }));
        }
    });

    clientSocket.on('error', () => {
        pendingSockets.delete(tunnelId);
    });
});

// 3. WebSocket Upgrade & Routing
server.on('upgrade', (req, socket, head) => {
    const parsedUrl = url.parse(req.url, true);
    const deviceId = parsedUrl.query.device_id;

    if (parsedUrl.pathname === '/ws' && deviceId) {
        wss.handleUpgrade(req, socket, head, (ws) => {
            wss.emit('connection', ws, req, deviceId);
        });
    } else {
        socket.destroy();
    }
});

wss.on('connection', (ws, req, deviceId) => {
    connectedNodes.set(deviceId, ws);
    console.log(`[+] Phone Connected: Device ID -> ${deviceId}`);

    ws.on('message', (message, isBinary) => {
        if (isBinary) {
            try {
                const data = Buffer.from(message);
                if (data.length < 4) return;
                const idLen = data.readUInt32BE(0);
                const tunnelId = data.toString('utf8', 4, 4 + idLen);
                const rawData = data.subarray(4 + idLen);

                const tunnelObj = pendingSockets.get(tunnelId);
                if (tunnelObj && tunnelObj.target instanceof net.Socket && !tunnelObj.target.destroyed) {
                    tunnelObj.target.write(rawData);
                }
            } catch (e) {
                console.error('Binary relay error:', e);
            }
        } else {
            try {
                const data = JSON.parse(message.toString());
                const { type, tunnelId, statusCode, headers, body, success, error } = data;
                const tunnelObj = pendingSockets.get(tunnelId);

                if (!tunnelObj) return;

                if (type === 'CONNECT_ACK') {
                    if (success) {
                        tunnelObj.established = true;
                        if (tunnelObj.target instanceof net.Socket) {
                            // Now send 200 Connection Established to AdsPower/Browser
                            tunnelObj.target.write('HTTP/1.1 200 Connection Established\r\n\r\n');
                        }
                    } else {
                        if (tunnelObj.target instanceof net.Socket) {
                            tunnelObj.target.write('HTTP/1.1 502 Bad Gateway\r\n\r\n');
                            tunnelObj.target.end();
                        }
                        pendingSockets.delete(tunnelId);
                    }
                } else if (type === 'HTTP_RES') {
                    const res = tunnelObj.target;
                    if (res && typeof res.writeHead === 'function') {
                        res.writeHead(statusCode || 200, headers || {});
                        res.end(body ? Buffer.from(body, 'base64') : '');
                        pendingSockets.delete(tunnelId);
                    }
                }
            } catch (e) {}
        }
    });

    ws.on('close', () => {
        connectedNodes.delete(deviceId);
        // Clean up all pending sockets associated with this phone
        for (const [tunnelId, tunnelObj] of pendingSockets.entries()) {
            if (tunnelObj.ws === ws) {
                if (tunnelObj.target instanceof net.Socket) tunnelObj.target.destroy();
                else if (tunnelObj.target && typeof tunnelObj.target.end === 'function') tunnelObj.target.end();
                pendingSockets.delete(tunnelId);
            }
        }
        console.log(`[-] Phone Disconnected: Device ID -> ${deviceId}`);
    });
});

const PORT = process.env.PORT || 8000;
server.listen(PORT, () => {
    console.log(`Production Mobile Proxy Server running on port ${PORT}`);
});
