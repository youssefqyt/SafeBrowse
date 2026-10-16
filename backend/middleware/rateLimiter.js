/**
 * SafeBrowse Rate Limiter Middleware
 * Protects public scan endpoints against denial of service, resource exhaustion,
 * and AI budget draining.
 */

const rateLimit = require("express-rate-limit");

const windowMs = Number(process.env.RATE_LIMIT_WINDOW_MS) || 60 * 1000; // 1 minute
const max = Number(process.env.RATE_LIMIT_MAX_REQUESTS) || 60; // 60 requests per minute

const scanRateLimiter = rateLimit({
  windowMs,
  max,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Rate limit exceeded. Please wait before submitting more URL scans.",
    retryAfterSeconds: Math.ceil(windowMs / 1000)
  }
});

module.exports = {
  scanRateLimiter
};
