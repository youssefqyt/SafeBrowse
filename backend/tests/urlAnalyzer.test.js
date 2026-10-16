const test = require("node:test");
const assert = require("node:assert/strict");
const { analyseUrl } = require("../services/urlAnalyzer");

test("analyseUrl: clean HTTPS URL produces 0 score and Low risk", () => {
  const result = analyseUrl("https://example.com");
  assert.equal(result.score, 0);
  assert.equal(result.risk, "Low");
  assert.equal(result.findings.length, 0);
  assert.equal(result.hostname, "example.com");
  assert.equal(result.sanitizedUrl, "https://example.com/");
});

test("analyseUrl: insecure HTTP triggers transport indicator", () => {
  const result = analyseUrl("http://example.com");
  assert.equal(result.score, 10);
  assert.equal(result.risk, "Low");
  const transportFinding = result.findings.find(f => f.type === "transport");
  assert.ok(transportFinding);
  assert.equal(transportFinding.severity, "low");
});

test("analyseUrl: rejects invalid URL string", () => {
  assert.throws(() => analyseUrl("not a valid url"), {
    message: /Invalid URL format/
  });
  assert.throws(() => analyseUrl(""), {
    message: /valid URL string is required/
  });
});

test("analyseUrl: rejects unsupported protocols", () => {
  assert.throws(() => analyseUrl("ftp://files.example.com"), {
    message: /Unsupported protocol 'ftp:'/
  });
});

test("analyseUrl: detects IPv4 hostname", () => {
  const result = analyseUrl("http://192.168.1.100/admin");
  assert.equal(result.features.isIpAddress, true);
  const ipFinding = result.findings.find(f => f.type === "hostname_ip");
  assert.ok(ipFinding);
  assert.equal(ipFinding.severity, "medium");
});

test("analyseUrl: detects embedded credentials as high severity", () => {
  const result = analyseUrl("https://admin:secret123@secure-portal.com/login");
  assert.equal(result.features.hasEmbeddedCredentials, true);
  const credFinding = result.findings.find(f => f.type === "embedded_credentials");
  assert.ok(credFinding);
  assert.equal(credFinding.severity, "high");
  // Embedded creds (40) + suspicious keyword login (10) = 50 -> Medium risk
  assert.ok(result.score >= 40);
});

test("analyseUrl: detects unusually long URL (> 200 characters)", () => {
  const longUrl = "https://example.com/search?q=" + "a".repeat(220);
  const result = analyseUrl(longUrl);
  const lenFinding = result.findings.find(f => f.type === "url_length");
  assert.ok(lenFinding);
  assert.equal(lenFinding.severity, "low");
});

test("analyseUrl: detects suspicious authentication keywords in hostname", () => {
  const result = analyseUrl("https://verify-login-update-account.com");
  const kwFinding = result.findings.find(f => f.type === "suspicious_keywords");
  assert.ok(kwFinding);
  assert.match(kwFinding.message, /login/);
  assert.match(kwFinding.message, /verify/);
});

test("analyseUrl: detects Punycode label in hostname", () => {
  const result = analyseUrl("https://xn--pple-43d.com");
  assert.equal(result.features.containsPunycode, true);
  const punyFinding = result.findings.find(f => f.type === "punycode_label");
  assert.ok(punyFinding);
  assert.equal(punyFinding.severity, "medium");
});

test("analyseUrl: detects excessive subdomains (>= 4)", () => {
  const result = analyseUrl("https://one.two.three.four.example.com");
  assert.ok(result.features.subdomainCount >= 4);
  const subFinding = result.findings.find(f => f.type === "excessive_subdomains");
  assert.ok(subFinding);
});

test("analyseUrl: detects known URL shortener", () => {
  const result = analyseUrl("https://bit.ly/special-link");
  assert.equal(result.features.isShortener, true);
  const shortFinding = result.findings.find(f => f.type === "url_shortener");
  assert.ok(shortFinding);
});

test("analyseUrl: detects digit-heavy hostname", () => {
  const result = analyseUrl("https://domain9876543210.com");
  assert.ok(result.features.digitRatio > 0.3);
  const digitFinding = result.findings.find(f => f.type === "digit_heavy_hostname");
  assert.ok(digitFinding);
});

test("analyseUrl: sanitizes URL by omitting sensitive query parameters and hash", () => {
  const result = analyseUrl("https://example.com/checkout?token=super_secret_auth&email=user@test.com#card");
  assert.equal(result.sanitizedUrl, "https://example.com/checkout");
  assert.ok(!result.sanitizedUrl.includes("super_secret_auth"));
  assert.ok(!result.sanitizedUrl.includes("card"));
});
