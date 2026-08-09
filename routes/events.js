const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/authMiddleware');

let clients = [];

// SSE endpoint for live activity feed
router.get('/feed', protect, (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  // Send initial connection event
  res.write(`data: ${JSON.stringify({ type: 'connected', timestamp: new Date() })}\n\n`);

  const clientId = Date.now();
  const newClient = {
    id: clientId,
    response: res,
    userId: req.user._id
  };
  clients.push(newClient);

  req.on('close', () => {
    clients = clients.filter(c => c.id !== clientId);
  });
});

// Broadcast function to send events to all connected clients
function broadcast(event) {
  const data = `data: ${JSON.stringify(event)}\n\n`;
  clients.forEach(client => {
    try {
      client.response.write(data);
    } catch (e) {
      // Client disconnected, will be cleaned up on next broadcast
    }
  });
}

// Clean up dead connections periodically
setInterval(() => {
  clients = clients.filter(client => {
    try {
      client.response.write(`:keepalive\n\n`);
      return true;
    } catch (e) {
      return false;
    }
  });
}, 30000);

module.exports = { router, broadcast };