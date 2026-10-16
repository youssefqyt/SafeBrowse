/**
 * SafeBrowse CORS Configuration Middleware
 * Safely permits requests originating from Chromium/Edge extensions and local development.
 */

const cors = require("cors");

function createCorsMiddleware() {
  const allowedOriginsEnv = process.env.ALLOWED_ORIGINS || "*";

  // If set to '*', allow all while respecting extension contexts
  if (allowedOriginsEnv === "*") {
    return cors({
      origin: true,
      methods: ["GET", "POST", "OPTIONS"],
      allowedHeaders: ["Content-Type", "Authorization"],
      credentials: false
    });
  }

  const explicitOrigins = allowedOriginsEnv.split(",").map(o => o.trim()).filter(Boolean);

  return cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (e.g. mobile apps, curl, extension content scripts)
      if (!origin) return callback(null, true);

      // Check browser extension protocols
      if (
        origin.startsWith("chrome-extension://") ||
        origin.startsWith("ms-browser-extension://") ||
        origin.startsWith("moz-extension://")
      ) {
        return callback(null, true);
      }

      // Check explicit allowed origins or localhost
      if (
        explicitOrigins.includes(origin) ||
        origin.includes("localhost") ||
        origin.includes("127.0.0.1")
      ) {
        return callback(null, true);
      }

      return callback(new Error("Blocked by SafeBrowse CORS policy."));
    },
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
  });
}

module.exports = {
  createCorsMiddleware
};
