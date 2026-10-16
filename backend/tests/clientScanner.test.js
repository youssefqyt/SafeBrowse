const test = require("node:test");
const assert = require("node:assert/strict");
const { scanUrlLocally } = require("../../extension/scanner");

test("scanUrlLocally: handles clean HTTPS URL", () => {
  const result = scanUrlLocally("https://example.com");
  assert.equal(result.score, 0);
  assert.equal(result.risk, "Low");
  assert.equal(result.findings.length, 0);
});

test("scanUrlLocally: detects HTTP insecure transport", () => {
  const result = scanUrlLocally("http://example.com");
  assert.equal(result.score, 10);
  assert.equal(result.risk, "Low");
  assert.ok(result.findings.some(f => f.type === "transport"));
});

test("scanUrlLocally: detects embedded credentials", () => {
  const result = scanUrlLocally("https://user:pass@example.com");
  assert.ok(result.score >= 40);
  assert.ok(result.findings.some(f => f.type === "embedded_credentials"));
});

test("scanUrlLocally: detects IP address hostname", () => {
  const result = scanUrlLocally("http://192.168.1.1");
  assert.ok(result.findings.some(f => f.type === "hostname_ip"));
});

test("scanUrlLocally: detects suspicious keywords in hostname", () => {
  const result = scanUrlLocally("https://verify-login.com");
  assert.ok(result.findings.some(f => f.type === "suspicious_keywords"));
});

test("scanUrlLocally: detects Punycode in hostname", () => {
  const result = scanUrlLocally("https://xn--test-43d.com");
  assert.ok(result.findings.some(f => f.type === "punycode_label"));
});

test("scanUrlLocally: detects URL shortener", () => {
  const result = scanUrlLocally("https://bit.ly/my-link");
  assert.ok(result.findings.some(f => f.type === "url_shortener"));
});
