/**
 * SafeBrowse Client-Side Heuristic Scanner
 * Provides an offline local heuristic analysis matching the backend analyzer.
 */

const LOCAL_SUSPICIOUS_KEYWORDS = [
  "login",
  "verify",
  "account",
  "password",
  "secure",
  "banking",
  "update",
  "wallet"
];

const LOCAL_KNOWN_SHORTENERS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "is.gd",
  "cutt.ly",
  "rebrand.ly",
  "ow.ly"
]);

const LOCAL_IPV4_PATTERN = /^(?:\d{1,3}\.){3}\d{1,3}$/;

/**
 * Scan a URL locally using heuristic rules when backend is unreachable.
 * @param {string} rawUrl - Target URL string.
 * @returns {object} Local scan analysis result.
 */
function scanUrlLocally(rawUrl) {
  let url;

  try {
    url = new URL(rawUrl.trim());
  } catch {
    return {
      score: 40,
      risk: "Unknown",
      hostname: "Unknown",
      findings: [{
        type: "malformed_url",
        severity: "high",
        message: "Invalid or malformed URL.",
        explanation: "The supplied target cannot be parsed as a standard web URL."
      }]
    };
  }

  const findings = [];
  const hostname = url.hostname.toLowerCase();

  // 1. Transport / HTTPS Check
  if (url.protocol !== "https:") {
    findings.push({
      type: "transport",
      severity: "low",
      message: "The URL does not use HTTPS.",
      explanation: "Connection is unencrypted. Anyone on the local network can inspect or tamper with traffic."
    });
  }

  // 2. IP Address Hostname Check
  if (LOCAL_IPV4_PATTERN.test(hostname)) {
    findings.push({
      type: "hostname_ip",
      severity: "medium",
      message: "The hostname is a raw IP address.",
      explanation: "Legitimate domains almost always use domain names. IP-based destinations are often used in malicious hosting."
    });
  }

  // 3. Embedded Credentials Check
  if (url.username || url.password) {
    findings.push({
      type: "embedded_credentials",
      severity: "high",
      message: "The URL contains embedded user credentials.",
      explanation: "Credentials in URLs (e.g. user@site.com) are historically used to obscure the actual host destination."
    });
  }

  // 4. URL Length Check
  if (rawUrl.length > 200) {
    findings.push({
      type: "url_length",
      severity: "low",
      message: "The URL is unusually long (> 200 characters).",
      explanation: "Excessive URL length is frequently used to obscure malicious parameters or redirects."
    });
  }

  // 5. Suspicious Keywords in Hostname
  const matchedKeywords = LOCAL_SUSPICIOUS_KEYWORDS.filter(kw => hostname.includes(kw));
  if (matchedKeywords.length > 0) {
    findings.push({
      type: "suspicious_keywords",
      severity: "low",
      message: `The hostname contains sensitive keywords: ${matchedKeywords.join(", ")}.`,
      explanation: "Phishing domains frequently include security keywords to trick users. Always verify the root domain."
    });
  }

  // 6. Punycode Label Detection
  const labels = hostname.split(".");
  const hasPunycode = labels.some(l => l.startsWith("xn--"));
  if (hasPunycode) {
    findings.push({
      type: "punycode_label",
      severity: "medium",
      message: "The hostname contains internationalized Punycode ('xn--').",
      explanation: "Punycode can be used in IDN homograph attacks to impersonate well-known domains."
    });
  }

  // 7. Excessive Subdomains Check
  const subdomainCount = Math.max(0, labels.length - 2);
  if (subdomainCount >= 4) {
    findings.push({
      type: "excessive_subdomains",
      severity: "low",
      message: `The hostname has ${subdomainCount} subdomains.`,
      explanation: "Unusually deep subdomain structures can obscure the actual parent domain."
    });
  }

  // 8. Known Shortener Check
  if (LOCAL_KNOWN_SHORTENERS.has(hostname)) {
    findings.push({
      type: "url_shortener",
      severity: "low",
      message: "The URL uses a known link-shortening service.",
      explanation: "Short links hide their actual destination. Verify the target before entering credentials."
    });
  }

  // 9. Digit-Heavy Hostname Check
  const digitCount = (hostname.match(/\d/g) || []).length;
  const digitRatio = hostname.length > 0 ? digitCount / hostname.length : 0;
  if (hostname.length >= 10 && digitRatio > 0.3) {
    findings.push({
      type: "digit_heavy_hostname",
      severity: "low",
      message: `The hostname is digit-heavy (${Math.round(digitRatio * 100)}% numbers).`,
      explanation: "High numeric density in hostnames is frequently associated with disposable phishing infrastructure."
    });
  }

  // Score calculation
  const weights = { low: 10, medium: 20, high: 40 };
  const score = Math.min(
    findings.reduce((total, f) => total + (weights[f.severity] || 10), 0),
    100
  );

  const risk = score >= 60 ? "High" : score >= 20 ? "Medium" : "Low";

  return {
    score,
    risk,
    hostname,
    findings
  };
}

// Support both browser and Node/testing environments
if (typeof module !== "undefined" && module.exports) {
  module.exports = { scanUrlLocally };
}
