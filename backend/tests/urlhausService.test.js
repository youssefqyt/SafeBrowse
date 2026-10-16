const test = require("node:test");
const assert = require("node:assert/strict");
const { checkUrlhaus } = require("../services/urlhausService");

test("checkUrlhaus: returns 'not_configured' when API key is missing", async () => {
  const result = await checkUrlhaus("https://example.com", { apiKey: "" });
  assert.equal(result.checked, false);
  assert.equal(result.status, "not_configured");
  assert.match(result.message, /not configured/);
});

test("checkUrlhaus: parses 'ok' (listed) threat intelligence response", async () => {
  const originalFetch = global.fetch;
  global.fetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({
      query_status: "ok",
      threat: "malware_download",
      url_status: "online",
      tags: ["elf", "mozi", "botnet"],
      date_added: "2026-01-01 12:00:00"
    })
  });

  try {
    const result = await checkUrlhaus("https://example-malware-test.com", { apiKey: "test_key" });
    assert.equal(result.checked, true);
    assert.equal(result.status, "listed");
    assert.equal(result.threat, "malware_download");
    assert.deepEqual(result.tags, ["elf", "mozi", "botnet"]);
  } finally {
    global.fetch = originalFetch;
  }
});

test("checkUrlhaus: parses 'no_results' (clean) response", async () => {
  const originalFetch = global.fetch;
  global.fetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({
      query_status: "no_results"
    })
  });

  try {
    const result = await checkUrlhaus("https://example.com", { apiKey: "test_key" });
    assert.equal(result.checked, true);
    assert.equal(result.status, "not_listed");
    assert.equal(result.threat, null);
  } finally {
    global.fetch = originalFetch;
  }
});

test("checkUrlhaus: handles network timeouts or errors gracefully", async () => {
  const originalFetch = global.fetch;
  global.fetch = async () => {
    const err = new Error("Connection timed out");
    err.name = "TimeoutError";
    throw err;
  };

  try {
    const result = await checkUrlhaus("https://example.com", { apiKey: "test_key" });
    assert.equal(result.checked, false);
    assert.equal(result.status, "unavailable");
    assert.match(result.message, /timed out/);
  } finally {
    global.fetch = originalFetch;
  }
});
