/**
 * SafeBrowse URL Analyzer Service
 * Evaluates structural and heuristic risk indicators for a given URL.
 */

const SUSPICIOUS_KEYWORDS = [
  "login",
  "verify",
  "account",
  "password",
  "secure",
  "banking",
  "update",
  "wallet"
];

const KNOWN_SHORTENERS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "is.gd",
  "cutt.ly",
  "rebrand.ly",
  "ow.ly"
]);

const IPV4_PATTERN = /^(?:\d{1,3}\.){3}\d{1,3}$/;

/**
 * Validate and analyze a raw URL.
 * @param {string} rawUrl - Full URL string to analyze.
 * @returns {object} Analysis results with score, risk, features, and findings.
 */
function analyseUrl(rawUrl) {
  if (typeof rawUrl !== "string" || !rawUrl.trim()) {
    throw new Error("A valid URL string is required.");
  }

  let parsed;
  try {
    parsed = new URL(rawUrl.trim());
  } catch (err) {
    throw new Error("Invalid URL format: unable to parse.");
  }

  // Enforce protocol restriction
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error(`Unsupported protocol '${parsed.protocol}'. Only HTTP and HTTPS are permitted.`);
  }

  const hostname = parsed.hostname.toLowerCase();
  if (!hostname) {
    throw new Error("URL must contain a valid hostname.");
  }

  const findings = [];

  function addFinding(type, severity, message, explanation) {
    findings.push({
      type,
      severity,
      message,
      explanation
    });
  }

  // 1. Protocol / Transport Check
  if (parsed.protocol !== "https:") {
    addFinding(
      "transport",
      "low",
      "The website connection does not use HTTPS.",
      "Data sent to this website is unencrypted and vulnerable to eavesdropping. HTTPS alone does not prove a site is safe, but HTTP is insecure."
    );
  }

  // 2. IP Address Hostname Check
  if (IPV4_PATTERN.test(hostname)) {
    addFinding(
      "hostname_ip",
      "medium",
      "The website hostname is an IP address rather than a domain name.",
      "Legitimate commercial websites almost always use branded domain names. Direct IP addresses are frequently observed in phishing and malware drop sites."
    );
  }

  // 3. Embedded Credentials Check (RFC 3986 userinfo)
  if (parsed.username || parsed.password) {
    addFinding(
      "embedded_credentials",
      "high",
      "The URL contains embedded user credentials or userinfo before the hostname.",
      "Embedded credentials (e.g. user@domain.com) are historically used in URL obfuscation attacks to deceive users about the true destination."
    );
  }

  // 4. URL Length Check
  if (rawUrl.length > 200) {
    addFinding(
      "url_length",
      "low",
      "The URL is unusually long (> 200 characters).",
      "Excessively long URLs can be used to hide malicious domains, tokens, or redirects, though complex query strings also occur legitimately."
    );
  }

  // 5. Suspicious Keywords in Hostname
  const matchedKeywords = SUSPICIOUS_KEYWORDS.filter(kw => hostname.includes(kw));
  if (matchedKeywords.length > 0) {
    addFinding(
      "suspicious_keywords",
      "low",
      `The hostname contains authentication-related terms: ${matchedKeywords.join(", ")}.`,
      "Deceptive domains frequently incorporate trust-inducing keywords like 'login' or 'verify'. Always verify the apex registered domain."
    );
  }

  // 6. Punycode Detection (IDN homograph attacks)
  const labels = hostname.split(".");
  const hasPunycode = labels.some(label => label.startsWith("xn--"));
  if (hasPunycode) {
    addFinding(
      "punycode_label",
      "medium",
      "The hostname contains internationalized Punycode labels ('xn--').",
      "Punycode allows foreign language characters but can be exploited for homograph attacks that visually mimic legitimate domains."
    );
  }

  // 7. Excessive Subdomains
  const subdomainCount = Math.max(0, labels.length - 2);
  if (subdomainCount >= 4) {
    addFinding(
      "excessive_subdomains",
      "low",
      `The hostname has ${subdomainCount} subdomains, which is unusually high.`,
      "Deeply nested subdomain hierarchies can disguise the actual root domain or bypass simple filtering mechanisms."
    );
  }

  // 8. Known URL Shortener
  if (KNOWN_SHORTENERS.has(hostname)) {
    addFinding(
      "url_shortener",
      "low",
      "The URL uses a public link-shortening service.",
      "Shortened links conceal their eventual destination. Verify the target website before browsing or supplying credentials."
    );
  }

  // 9. Digit-Heavy Hostname Check
  const digitCount = (hostname.match(/\d/g) || []).length;
  const digitRatio = hostname.length > 0 ? digitCount / hostname.length : 0;
  if (hostname.length >= 10 && digitRatio > 0.3) {
    addFinding(
      "digit_heavy_hostname",
      "low",
      `The hostname contains an unusually high ratio of numeric digits (${Math.round(digitRatio * 100)}%).`,
      "Algorithmic domain generation (DGA) and throwaway phishing domains frequently feature high digit density."
    );
  }

  // Calculate Heuristic Score
  const weights = {
    low: 10,
    medium: 20,
    high: 40
  };

  const score = Math.min(
    findings.reduce((total, f) => total + (weights[f.severity] || 10), 0),
    100
  );

  const risk = score >= 60 ? "High" : score >= 20 ? "Medium" : "Low";

  // Sanitize URL to protect privacy: exclude sensitive search params and hash
  const sanitizedUrl = `${parsed.protocol}//${parsed.host}${parsed.pathname}`;

  return {
    url: parsed.href,
    sanitizedUrl,
    protocol: parsed.protocol,
    hostname,
    score,
    risk,
    features: {
      urlLength: rawUrl.length,
      hostnameLength: hostname.length,
      subdomainCount,
      digitRatio: Number(digitRatio.toFixed(3)),
      usesHttps: parsed.protocol === "https:",
      isIpAddress: IPV4_PATTERN.test(hostname),
      hasEmbeddedCredentials: Boolean(parsed.username || parsed.password),
      containsPunycode: hasPunycode,
      isShortener: KNOWN_SHORTENERS.has(hostname)
    },
    findings
  };
}

module.exports = {
  analyseUrl,
  SUSPICIOUS_KEYWORDS,
  KNOWN_SHORTENERS
};
