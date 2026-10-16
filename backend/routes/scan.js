/**
 * SafeBrowse Scan Route
 * Coordinates URL analysis, threat intelligence lookup, and AI security explanation.
 */

const express = require("express");
const router = express.Router();

const { analyseUrl } = require("../services/urlAnalyzer");
const { checkUrlhaus } = require("../services/urlhausService");
const { generateSecurityExplanation } = require("../services/aiExplanationService");

router.post("/scan", async (req, res, next) => {
  try {
    const rawUrl = req.body?.url;

    // 1. Validate Input Presence and Type
    if (typeof rawUrl !== "string" || rawUrl.trim().length === 0) {
      return res.status(400).json({
        error: "Missing URL: please provide a valid 'url' string in the JSON request body."
      });
    }

    const trimmedUrl = rawUrl.trim();

    // 2. Validate URL Length
    if (trimmedUrl.length > 2048) {
      return res.status(400).json({
        error: "URL length exceeds maximum limit of 2048 characters."
      });
    }

    // 3. Execute Heuristic URL Analysis
    let analysis;
    try {
      analysis = analyseUrl(trimmedUrl);
    } catch (parseErr) {
      return res.status(400).json({
        error: parseErr.message
      });
    }

    // 4. Query Threat Intelligence (URLhaus) using sanitized URL
    const threatIntel = await checkUrlhaus(analysis.sanitizedUrl);

    // 5. Integrate Threat Intelligence Findings if listed
    if (threatIntel.status === "listed") {
      analysis.findings.unshift({
        type: "threat_intelligence",
        severity: "high",
        message: `URLhaus lists this URL as active ${threatIntel.threat || "malware"}.`,
        explanation: "This URL has been actively confirmed by abuse.ch threat intelligence researchers as distributing malicious content or hosting phishing."
      });
    }

    // 6. Recalculate Composite Heuristic Score
    const weights = { low: 10, medium: 20, high: 40 };
    const compositeScore = Math.min(
      analysis.findings.reduce((total, f) => total + (weights[f.severity] || 10), 0),
      100
    );

    // Any listed threat intelligence automatically escalates risk to "High"
    const compositeRisk = threatIntel.status === "listed" || compositeScore >= 60
      ? "High"
      : compositeScore >= 20
        ? "Medium"
        : "Low";

    // 7. Generate Contextual AI Security Explanation
    const aiResult = await generateSecurityExplanation({
      hostname: analysis.hostname,
      protocol: analysis.protocol,
      score: compositeScore,
      risk: compositeRisk,
      findings: analysis.findings,
      threatIntel
    });

    // 8. Return Comprehensive Response
    return res.json({
      url: analysis.url,
      sanitizedUrl: analysis.sanitizedUrl,
      hostname: analysis.hostname,
      score: compositeScore,
      risk: compositeRisk,
      features: analysis.features,
      findings: analysis.findings,
      threatIntel,
      explanation: aiResult.explanation,
      explanationSource: aiResult.explanationSource,
      providerModel: aiResult.providerModel,
      aiStatus: aiResult.status,
      timestamp: new Date().toISOString(),
      note: "This heuristic score is not a probability. A low score or absence of records does not guarantee that a website is safe."
    });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
