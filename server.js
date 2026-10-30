const express = require('express');
const { WebSocketServer } = require('ws');
const http = require('http');
const url = require('url');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const connectedNodes = new Map();
const pendingRequests = new Map();

wss.on('connection', (ws, req) => {
    const parameters = url.parse(req.url, true).query;
    const deviceId = parameters.device_id || 'unknown_device';

    connectedNodes.set(deviceId, ws);
    console.log(`[+] Phone Connected: Device ID -> ${deviceId}`);

    // Jab phone se website ka data wapas aayega
    ws.on('message', (message) => {
        console.log(`[Data] Received response from device ${deviceId}`);
        
        const resObj = pendingRequests.get(deviceId);
        if (resObj) {
            resObj.send(message.toString()); // Asli website ka data browser ko bhej diya
            pendingRequests.delete(deviceId);
        }
    });

    ws.on('close', () => {
        connectedNodes.delete(deviceId);
        const resObj = pendingRequests.get(deviceId);
        if (resObj) {
            resObj.status(500).send({ error: 'Phone disconnected before sending response' });
            pendingRequests.delete(deviceId);
        }
        console.log(`[-] Phone Disconnected: Device ID -> ${deviceId}`);
    });
});

// Proxy endpoint
app.get('/proxy', (req, res) => {
    const { deviceId, targetUrl } = req.query;

    if (!deviceId || !targetUrl) {
        return res.status(400).send({ error: 'Please provide deviceId and targetUrl' });
    }

    const nodeWs = connectedNodes.get(deviceId);
    if (!nodeWs) {
        return res.status(404).send({ error: 'Target phone node is offline!' });
    }

    // Agar pehle ki koi request pending hai toh use close kar do
    if (pendingRequests.has(deviceId)) {
        const oldRes = pendingRequests.get(deviceId);
        oldRes.status(500).send({ error: 'New request replaced old one' });
    }

    // Browser ke response object ko save karke rakho jab tak phone jawab na de
    pendingRequests.set(deviceId, res);

    // Phone ke WebSocket par target URL bhej do
    nodeWs.send(targetUrl);
});

const PORT = process.env.PORT || 8000;
server.listen(PORT, () => {
    console.log(`Proxy Relay Server running on port ${PORT}`);
});
