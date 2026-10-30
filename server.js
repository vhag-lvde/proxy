const http = require('http');
const { WebSocketServer } = require('ws');
const url = require('url');
const crypto = require('crypto');

const server = http.createServer((req, res) => {
    const targetUrl = req.url;

    if (!targetUrl || targetUrl === '/' || targetUrl.startsWith('/ws')) {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('Multi-Device Mobile Proxy Server is Running!\n');
        return;
    }

    // AdsPower proxy authentication header se deviceId (username) nikalna
    const authHeader = req.headers['proxy-authorization'];
    let deviceId = null;

    if (authHeader && authHeader.startsWith('Basic ')) {
        const base64Credentials = authHeader.split(' ')[1];
        const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
        // Format: username:password hota hai, hum username ko deviceId maan rahe hain
        deviceId = credentials.split(':')[0];
    }

    if (!deviceId || !connectedNodes.has(deviceId)) {
        res.writeHead(407, { 
            'Content-Type': 'text/plain',
            'Proxy-Authenticate': 'Basic realm="Enter your Device ID as Proxy Username"'
        });
        res.end('Proxy Error: Invalid or Missing Device ID in Proxy Username');
        return;
    }

    const nodeWs = connectedNodes.get(deviceId);
    const requestId = crypto.randomUUID();
    pendingRequests.set(requestId, res);

    // Specific phone node ko target URL bhejo
    nodeWs.send(JSON.stringify({ requestId, targetUrl }));

    // 30 seconds Timeout
    setTimeout(() => {
        if (pendingRequests.has(requestId)) {
            pendingRequests.get(requestId).writeHead(504, { 'Content-Type': 'text/plain' });
            pendingRequests.get(requestId).end('Gateway Timeout: Phone took too long to respond');
            pendingRequests.delete(requestId);
        }
    }, 30000);
});

const wss = new WebSocketServer({ server });
const connectedNodes = new Map();
const pendingRequests = new Map();

wss.on('connection', (ws, req) => {
    const parameters = url.parse(req.url, true).query;
    const deviceId = parameters.device_id;

    if (!deviceId) {
        ws.close();
        return;
    }

    connectedNodes.set(deviceId, ws);
    console.log(`[+] Phone Connected: Device ID -> ${deviceId}`);

    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message.toString());
            const { requestId, responseBody, error } = data;

            const clientRes = pendingRequests.get(requestId);
            if (clientRes) {
                if (error) {
                    clientRes.writeHead(500, { 'Content-Type': 'text/plain' });
                    clientRes.end(error);
                } else {
                    clientRes.writeHead(200, { 'Content-Type': 'text/html' });
                    clientRes.end(responseBody);
                }
                pendingRequests.delete(requestId);
            }
        } catch (e) {
            console.error('Failed to parse phone response:', e);
        }
    });

    ws.on('close', () => {
        connectedNodes.delete(deviceId);
        console.log(`[-] Phone Disconnected: Device ID -> ${deviceId}`);
    });
});

const PORT = process.env.PORT || 8000;
server.listen(PORT, () => {
    console.log(`Multi-Device Proxy Server running on port ${PORT}`);
});
