const express = require('express');
const { WebSocketServer } = require('ws');
const http = require('http');
const url = require('url');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// Map mein sabhi connected phones ki list store hogi { deviceId: wsConnection }
const connectedNodes = new Map();

wss.on('connection', (ws, req) => {
    const parameters = url.parse(req.url, true).query;
    const deviceId = parameters.device_id || 'unknown_device';

    // Phone ko list mein save kar liya
    connectedNodes.set(deviceId, ws);
    console.log(`[+] Phone Connected: Device ID -> ${deviceId}`);

    // Jab phone se koi response wapas aaye
    ws.on('message', (message) => {
        console.log(`[Data] Received response from device ${deviceId}`);
        // Yahan aap us data ko apne client/scraper ko bhej sakte hain
    });

    // Jab phone disconnect ho jaye
    ws.on('close', () => {
        connectedNodes.delete(deviceId);
        console.log(`[-] Phone Disconnected: Device ID -> ${deviceId}`);
    });
});

// Ek API endpoint jisse aap baahar se request bhej sakein ki kis phone ke through data chahiye
app.get('/proxy', express.json(), async (req, res) => {
    const { deviceId, targetUrl } = req.query;

    if (!deviceId || !targetUrl) {
        return res.status(400).send({ error: 'Please provide deviceId and targetUrl' });
    }

    const nodeWs = connectedNodes.get(deviceId);
    if (!nodeWs) {
        return res.status(404).send({ error: 'Target phone node is offline!' });
    }

    // Request ko phone ke WebSocket par bhej do
    nodeWs.send(targetUrl);
    res.send({ status: 'Request sent to phone node, waiting for response...' });
});

const PORT = process.env.PORT || 8000;
server.listen(PORT, () => {
    console.log(`Proxy Relay Server running on port ${PORT}`);
});
