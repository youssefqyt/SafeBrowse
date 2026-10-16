/**
 * SafeBrowse Express Server Entry Point
 * Orchestrates security middleware, routes, and error handling.
 */

require("dotenv").config();

const express = require("express");
const helmet = require("helmet");

const { createCorsMiddleware } = require("./middleware/corsConfig");
const { scanRateLimiter } = require("./middleware/rateLimiter");
const { errorHandler } = require("./middleware/errorHandler");

const scanRouter = require("./routes/scan");
const healthRouter = require("./routes/health");

const app = express();
const PORT = process.env.PORT || 5000;

// Security Headers (configured safely for API endpoints)
app.use(
  helmet({
    contentSecurityPolicy: false, // APIs returning JSON do not require HTML CSP
    crossOriginResourcePolicy: { policy: "cross-origin" }
  })
);

// CORS Management
app.use(createCorsMiddleware());

// Body Parser with strict payload limit
app.use(express.json({ limit: "16kb" }));

// Root welcome / info endpoint
app.get("/", (req, res) => {
  res.json({
    service: "SafeBrowse Security API",
    status: "online",
    endpoints: {
      health: "/api/health",
      scan: "/api/scan (POST)"
    },
    version: "1.2.0"
  });
});

// Health check endpoint
app.use("/api", healthRouter);

// Scan endpoint with rate limiting
app.use("/api", scanRateLimiter, scanRouter);

// 404 Handler for undefined routes
app.use((req, res) => {
  res.status(404).json({
    error: `Route ${req.method} ${req.originalUrl} not found.`
  });
});

// Centralized error handler
app.use(errorHandler);

// Start server if executed directly
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`[SafeBrowse API] Server actively listening on port ${PORT}`);
    console.log(`[SafeBrowse API] Health endpoint: http://localhost:${PORT}/api/health`);
    console.log(`[SafeBrowse API] AI Provider configured: ${process.env.AI_PROVIDER || "groq"}`);
  });
}

module.exports = app;
