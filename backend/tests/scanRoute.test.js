const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const app = require("../server");

// Helper to start ephemeral server for testing endpoints
function startTestServer() {
  return new Promise((resolve) => {
    const server = http.createServer(app);
    server.listen(0, () => {
      const port = server.address().port;
      const baseUrl = `http://127.0.0.1:${port}`;
      resolve({ server, baseUrl });
    });
  });
}

test("API: GET / returns service information", async () => {
  const { server, baseUrl } = await startTestServer();
  try {
    const res = await fetch(`${baseUrl}/`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.service, "SafeBrowse Security API");
    assert.equal(data.status, "online");
  } finally {
    server.close();
  }
});

test("API: GET /api/health returns health status and configuration info", async () => {
  const { server, baseUrl } = await startTestServer();
  try {
    const res = await fetch(`${baseUrl}/api/health`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.status, "ok");
    assert.equal(data.service, "SafeBrowse API");
    assert.ok(data.integrations);
    assert.ok(data.integrations.ai);
  } finally {
    server.close();
  }
});

test("API: POST /api/scan scans a legitimate HTTPS URL successfully", async () => {
  const { server, baseUrl } = await startTestServer();
  try {
    const res = await fetch(`${baseUrl}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: "https://example.com" })
    });

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.hostname, "example.com");
    assert.equal(data.score, 0);
    assert.equal(data.risk, "Low");
    assert.ok(Array.isArray(data.findings));
    assert.ok(data.threatIntel);
    assert.ok(data.explanation);
    assert.ok(data.explanationSource);
    assert.ok(data.note);
  } finally {
    server.close();
  }
});

test("API: POST /api/scan rejects missing or empty url with 400", async () => {
  const { server, baseUrl } = await startTestServer();
  try {
    const res1 = await fetch(`${baseUrl}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({})
    });
    assert.equal(res1.status, 400);

    const res2 = await fetch(`${baseUrl}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: "   " })
    });
    assert.equal(res2.status, 400);
  } finally {
    server.close();
  }
});

test("API: POST /api/scan rejects URL exceeding 2048 characters with 400", async () => {
  const { server, baseUrl } = await startTestServer();
  try {
    const excessiveUrl = "https://example.com/path?" + "param=".repeat(500);
    const res = await fetch(`${baseUrl}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: excessiveUrl })
    });
    assert.equal(res.status, 400);
    const data = await res.json();
    assert.match(data.error, /exceeds maximum limit/);
  } finally {
    server.close();
  }
});

test("API: POST /api/scan properly handles embedded credentials with high-severity finding", async () => {
  const { server, baseUrl } = await startTestServer();
  try {
    const res = await fetch(`${baseUrl}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: "https://user:password@target-bank.com/account" })
    });

    assert.equal(res.status, 200);
    const data = await res.json();
    const credFinding = data.findings.find(f => f.type === "embedded_credentials");
    assert.ok(credFinding);
    assert.equal(credFinding.severity, "high");
    assert.ok(data.score >= 40);
  } finally {
    server.close();
  }
});
