/**
 * Aegis Guard - Express + Socket.IO Backend Server
 *
 * Responsibilities:
 *  - Serve the frontend static files
 *  - POST /analyze  – on-demand URL scan triggered by the user
 *  - GET  /status   – health check
 *  - Spawn the Python ML predict.py script for each URL
 *  - Emit real-time scan results to all connected clients via Socket.IO
 *  - Maintain a rolling scan log accessible via GET /logs
 */

"use strict";

const path = require("path");
const http = require("http");
const { execFile } = require("child_process");

const express = require("express");
const { Server } = require("socket.io");
const cors = require("cors");
const rateLimit = require("express-rate-limit");

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const PORT = process.env.PORT || 3000;
const PYTHON_BIN = process.env.PYTHON_BIN || "python3";
const PREDICT_SCRIPT = path.join(__dirname, "..", "ml_model", "predict.py");
const FRONTEND_DIR = path.join(__dirname, "..", "frontend");

// Maximum number of log entries kept in memory
const MAX_LOG_SIZE = 200;

// ---------------------------------------------------------------------------
// App setup
// ---------------------------------------------------------------------------

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*", methods: ["GET", "POST"] },
});

app.use(cors());
app.use(express.json());

// Serve the frontend as static files
app.use(express.static(FRONTEND_DIR));

// In-memory scan log (newest first)
const scanLog = [];

// ---------------------------------------------------------------------------
// Helper: call Python ML model
// ---------------------------------------------------------------------------

/**
 * Analyze a URL using the Python Random Forest model.
 * @param {string} url
 * @returns {Promise<object>} Parsed JSON result from predict.py
 */
function analyzeURL(url) {
  return new Promise((resolve, reject) => {
    execFile(
      PYTHON_BIN,
      [PREDICT_SCRIPT, url],
      { timeout: 30_000 },
      (err, stdout, stderr) => {
        if (err) {
          return reject(new Error(stderr || err.message));
        }
        try {
          resolve(JSON.parse(stdout.trim()));
        } catch (parseErr) {
          reject(new Error(`Failed to parse ML output: ${stdout}`));
        }
      }
    );
  });
}

/**
 * Run a URL through the ML model, append to log, and broadcast via Socket.IO.
 * @param {string} url
 * @returns {Promise<object>} scan result
 */
async function scanAndBroadcast(url) {
  let result;
  try {
    result = await analyzeURL(url);
  } catch (err) {
    result = {
      url,
      risk_score: 0,
      status: "error",
      error: err.message,
    };
  }

  // Stamp the result with a server-side timestamp
  result.timestamp = new Date().toISOString();

  // Prepend to log (keep bounded)
  scanLog.unshift(result);
  if (scanLog.length > MAX_LOG_SIZE) {
    scanLog.length = MAX_LOG_SIZE;
  }

  // Broadcast to all connected Socket.IO clients
  io.emit("scan_result", result);

  return result;
}

// ---------------------------------------------------------------------------
// REST endpoints
// ---------------------------------------------------------------------------

/** Health check */
app.get("/status", (_req, res) => {
  res.json({ status: "running", uptime: process.uptime() });
});

/** Return the rolling scan log */
app.get("/logs", (_req, res) => {
  res.json(scanLog);
});

/**
 * Manual / on-demand scan
 * Body: { "url": "https://..." }
 * Rate-limited to 30 requests per minute per IP to prevent abuse.
 */
const analyzeLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many scan requests. Please try again in a minute." },
});

app.post("/analyze", analyzeLimiter, async (req, res) => {
  const { url } = req.body;

  if (!url || typeof url !== "string" || url.trim() === "") {
    return res.status(400).json({ error: "A valid url field is required." });
  }

  const trimmedUrl = url.trim();

  // Basic URL sanity check – must start with http:// or https://
  if (!/^https?:\/\//i.test(trimmedUrl)) {
    return res
      .status(400)
      .json({ error: "URL must start with http:// or https://" });
  }

  try {
    const result = await scanAndBroadcast(trimmedUrl);
    return res.json(result);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// Socket.IO connection handling
// ---------------------------------------------------------------------------

io.on("connection", (socket) => {
  console.log(`[Socket.IO] Client connected: ${socket.id}`);

  // Send the current log to the newly connected client
  socket.emit("log_history", scanLog);

  // Accept scan requests via WebSocket as well
  socket.on("scan_url", async (data) => {
    const url = typeof data === "string" ? data : data?.url;
    if (!url) return;
    await scanAndBroadcast(url.trim());
  });

  socket.on("disconnect", () => {
    console.log(`[Socket.IO] Client disconnected: ${socket.id}`);
  });
});

// ---------------------------------------------------------------------------
// Background scanning service (imported after io is ready)
// ---------------------------------------------------------------------------

// Pass io and scanAndBroadcast to the background scanner
const backgroundScanner = require("./scanner");
backgroundScanner.start(scanAndBroadcast);

// ---------------------------------------------------------------------------
// Start server
// ---------------------------------------------------------------------------

server.listen(PORT, () => {
  console.log(`[Aegis Guard] Server running on http://localhost:${PORT}`);
  console.log(`[Aegis Guard] Frontend: http://localhost:${PORT}/`);
  console.log(`[Aegis Guard] Analyze endpoint: POST http://localhost:${PORT}/analyze`);
});

module.exports = { app, server, io, scanAndBroadcast };
