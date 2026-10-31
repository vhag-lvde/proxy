const http = require('http');
const net = require('net');
const { WebSocketServer } = require('ws');
const url = require('url');
const crypto = require('crypto');

const server = http.createServer();
const wss = new WebSocketServer({ noServer: true });

const connectedNodes = new Map(); // deviceId -> ws connection
const pendingSockets = new Map(); // tunnelId -> socket/res

// Authentication helper
function authenticateProxy(req) {
    const authHeader = req.headers['proxy-authorization'];
    if (!authHeader || !authHeader.startsWith('Basic ')) return null;
    
    try {
        const base64Credentials = authHeader.split(' ')[1];
        const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
        return credentials.split(':')[0]; // Username is deviceId
    } catch (e) {
        return null;
    }
}

// 1. Handle Standard HTTP Requests
server.on('request', (req, res) => {
    const deviceId = authenticateProxy(req);
    if (!deviceId || !connectedNodes.has(deviceId)) {
        res.writeHead(407, { 'Proxy-Authenticate': 'Basic realm="Enter Device ID as Username"' });
        res.end('Proxy Authentication Required');
        return;
    }

    const ws = connectedNodes.get(deviceId);
    const tunnelId = crypto.randomUUID();
    pendingSockets.set(tunnelId, res);

    ws.send(JSON.stringify({
        type: 'HTTP',
        tunnelId,
        method: req.method,
        url: req.url,
        headers: req.headers
    }));

    req.on('close', () => {
        pendingSockets.delete(tunnelId);
    });
});

// 2. Handle HTTPS CONNECT Tunneling (AdsPower HTTPS check)
server.on('connect', (req, clientSocket, head) => {
    const deviceId = authenticateProxy(req);
    if (!deviceId || !connectedNodes.has(deviceId)) {
        clientSocket.write('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Enter Device ID"\r\n\r\n');
        clientSocket.end();
        return;
    }

    const ws = connectedNodes.get(deviceId);
    const tunnelId = crypto.randomUUID();
    
    // Store both the client socket and tunnel info
    pendingSockets.set(tunnelId, clientSocket);

    // Tell AdsPower/Client that connection is established successfully
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

    // Tell Android phone to open a TCP socket to the target host
    ws.send(JSON.stringify({
        type: 'CONNECT',
        tunnelId,
        host: req.url // e.g. "ipapi.co:443" or target domain
    }));

    clientSocket.on('data', (chunk) => {
        // AdsPower se aane wala encrypted data phone ko bhejna
        const idBytes = tunnelId.toByteArray ? null : Buffer.from(tunnelId, 'utf-8');
        // Pack: [4 bytes length] + [tunnelId] + [payload]
        const packet = Buffer.alloc(4 + idBytes.length + chunk.length);
        packet.writeUInt32BE(idBytes.length, 0);
        idBytes.copy(packet, 4);
        chunk.copy(packet, 4 + idBytes.length);
        
        if (ws.readyState === ws.OPEN) {
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

// 3. Handle WebSocket Connection from Android Phones
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

                const socketObj = pendingSockets.get(tunnelId);
                if (socketObj instanceof net.Socket && !socketObj.destroyed) {
                    socketObj.write(rawData);
                }
            } catch (e) {
                console.error('Error handling binary data from phone:', e);
            }
        } else {
            try {
                const data = JSON.parse(message.toString());
                const { tunnelId, statusCode, body } = data;
                const res = pendingSockets.get(tunnelId);

                if (res && typeof res.writeHead === 'function') {
                    res.writeHead(statusCode || 200, { 'Content-Type': 'text/html' });
                    res.end(body);
                    pendingSockets.delete(tunnelId);
                }
            } catch (e) {}
        }
    });

    ws.on('close', () => {
        connectedNodes.delete(deviceId);
        console.log(`[-] Phone Disconnected: Device ID -> ${deviceId}`);
    });
});

const PORT = process.env.PORT || 8000;
server.listen(PORT, () => {
    console.log(`Proxy Server running on port ${PORT}`);
});
