const express = require('express');
const router = express.Router();

// ---------------------------------------------------------------------------
// In-memory store of connected SSE response objects
// ---------------------------------------------------------------------------
const clients = new Set();

// ---------------------------------------------------------------------------
// broadcast() — push a JSON event to every connected SSE client.
// Exported on the router object so other modules can call it via:
//   require('../routes/events').broadcast({ type: '...' })
// ---------------------------------------------------------------------------
function broadcast(eventData) {
  const msg = `data: ${JSON.stringify(eventData)}\n\n`;
  clients.forEach(res => {
    try {
      res.write(msg);
    } catch (e) {
      // Dead connection — clean up
      clients.delete(res);
    }
  });
}

// ---------------------------------------------------------------------------
// @route  GET /api/events/feed
// @desc   Server-Sent Events stream for live dashboard updates
// @access Public (auth can be added if needed)
// ---------------------------------------------------------------------------
router.get('/feed', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.flushHeaders();

  // Confirm connection to the client
  res.write(`data: ${JSON.stringify({ type: 'connected', message: 'CyberShield Live Feed Active' })}\n\n`);

  clients.add(res);

  // Remove the client when they disconnect
  req.on('close', () => clients.delete(res));
});

// Attach broadcast as a property so callers can do: eventsRouter.broadcast(...)
router.broadcast = broadcast;

module.exports = router;
