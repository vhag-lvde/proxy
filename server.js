const http = require('http');
const { WebSocketServer } = require('ws');
const url = require('url');
const crypto = require('crypto');

const server = http.createServer((req, res) => {
    // AdsPower jab proxy ke through request bhejta hai, toh req.url me poora absolute URL hota hai (jaise http://ip-api.com/json)
    const targetUrl = req.url;

    if (!targetUrl || targetUrl === '/' || targetUrl.startsWith('/ws')) {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('Mobile Proxy Server for AdsPower is Running!\n');
        return;
    }

    // Connected phone node ko fetch karein (abhi ke liye jo phone connected hai)
    const deviceId = Array.from(connectedNodes.keys())[0];
    const nodeWs = connectedNodes.get(deviceId);

    if (!deviceId || !nodeWs) {
        res.writeHead(503, { 'Content-Type': 'text/plain' });
        res.end('Proxy Error: No phone node connected online');
        return;
    }

    const requestId = crypto.randomUUID();
    pendingRequests.set(requestId, res);

    // Phone ko WebSocket ke zariye target URL bhejo
    nodeWs.send(JSON.stringify({ requestId, targetUrl }));

    // 30 seconds Timeout
    setTimeout(() => {
        if (pendingRequests.has(requestId)) {
            pendingRequests.get(requestId).writeHead(504, { 'Content-Type': 'text/plain' });
            pendingRequests.get(requestId).end('Gateway Timeout: Phone took too long');
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
                    // Website ka data wapas AdsPower/Browser ko bhej do
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
    console.log(`AdsPower HTTP Proxy Server running on port ${PORT}`);
});
