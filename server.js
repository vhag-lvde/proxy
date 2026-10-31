const http = require('http');
const net = require('net');
const { WebSocketServer } = require('ws');
const url = require('url');
const crypto = require('crypto');

const server = http.createServer();
const wss = new WebSocketServer({ noServer: true });

const connectedNodes = new Map(); // deviceId -> ws connection
const pendingSockets = new Map(); // tunnelId -> net.Socket or http.ServerResponse

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

    // Send HTTP request details to Android phone
    ws.send(JSON.stringify({
        type: 'HTTP',
        tunnelId,
        method: req.method,
        url: req.url,
        headers: req.headers
    }));

    req.on('data', chunk => {
        // Agar POST request me body hai to forward karein (agar zaroorat ho)
    });

    req.on('close', () => {
        pendingSockets.delete(tunnelId);
    });
});

// 2. Handle HTTPS CONNECT Tunneling (Crucial for AdsPower)
server.on('connect', (req, clientSocket, head) => {
    const deviceId = authenticateProxy(req);
    if (!deviceId || !connectedNodes.has(deviceId)) {
        clientSocket.write('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Enter Device ID"\r\n\r\n');
        clientSocket.end();
        return;
    }

    const ws = connectedNodes.get(deviceId);
    const tunnelId = crypto.randomUUID();
    pendingSockets.set(tunnelId, clientSocket);

    // Tell Android phone to open a TCP socket to the target HTTPS host
    ws.send(JSON.stringify({
        type: 'CONNECT',
        tunnelId,
        host: req.url // e.g. "example.com:443"
    }));

    clientSocket.on('close', () => {
        pendingSockets.delete(tunnelId);
        ws.send(JSON.stringify({ type: 'CLOSE', tunnelId }));
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
        // Phone se data binary ya JSON me aa sakta hai (TCP Tunnel data)
        if (isBinary) {
            // Binary data for CONNECT tunnels
            // Format: [4 bytes tunnelId length] + [tunnelId string] + [raw binary data]
            try {
                const idLen = message.readUInt32BE(0);
                const tunnelId = message.toString('utf8', 4, 4 + idLen);
                const rawData = message.subarray(4 + idLen);

                const socketObj = pendingSockets.get(tunnelId);
                if (socketObj instanceof net.Socket || socketObj && typeof socketObj.write === 'function') {
                    socketObj.write(rawData);
                }
            } catch (e) {
                console.error('Error parsing binary tunnel data:', e);
            }
        } else {
            // JSON response for standard HTTP requests
            try {
                const data = JSON.parse(message.toString());
                const { tunnelId, statusCode, headers, body } = data;
                const res = pendingSockets.get(tunnelId);

                if (res && typeof res.writeHead === 'function') {
                    res.writeHead(statusCode || 200, headers || {});
                    res.end(body);
                    pendingSockets.delete(tunnelId);
                }
            } catch (e) {
                // Might be tunnel established confirmation
            }
        }
    });

    ws.on('close', () => {
        connectedNodes.delete(deviceId);
        console.log(`[-] Phone Disconnected: Device ID -> ${deviceId}`);
    });
});

const PORT = process.env.PORT || 8000;
server.listen(PORT, () => {
    console.log(`Full HTTP/HTTPS Proxy Tunnel Server running on port ${PORT}`);
});
