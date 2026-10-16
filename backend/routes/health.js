/**
 * SafeBrowse Health Check Route
 * Reports service health, version, and integration readiness without exposing secrets.
 */

const express = require("express");
const router = express.Router();

router.get("/health", (req, res) => {
  const aiProvider = (process.env.AI_PROVIDER || "groq").toLowerCase();
  const hasGroqKey = Boolean(process.env.GROQ_API_KEY && process.env.GROQ_API_KEY !== "your_groq_api_key_here");
  const hasGeminiKey = Boolean(process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== "your_gemini_api_key_here");
  const hasUrlhausKey = Boolean(process.env.URLHAUS_AUTH_KEY && process.env.URLHAUS_AUTH_KEY !== "your_urlhaus_api_key_here");

  const aiConfigured = (aiProvider === "groq" && hasGroqKey) ||
                       (aiProvider === "gemini" && hasGeminiKey) ||
                       (aiProvider === "none");

  res.json({
    status: "ok",
    service: "SafeBrowse API",
    version: "1.2.0",
    uptimeSeconds: Math.floor(process.uptime()),
    environment: process.env.NODE_ENV || "development",
    integrations: {
      ai: {
        provider: aiProvider,
        configured: aiConfigured,
        model: aiProvider === "gemini"
          ? (process.env.GEMINI_MODEL || "gemini-1.5-flash")
          : (process.env.GROQ_MODEL || "llama-3.3-70b-versatile")
      },
      threatIntel: {
        provider: "URLhaus",
        configured: hasUrlhausKey
      }
    },
    timestamp: new Date().toISOString()
  });
});

module.exports = router;
