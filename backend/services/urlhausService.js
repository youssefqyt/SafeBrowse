/**
 * SafeBrowse URLhaus Threat Intelligence Service
 * Queries the abuse.ch URLhaus database for confirmed malware and malicious URL listings.
 */

const URLHAUS_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/";
const DEFAULT_TIMEOUT_MS = 8000;

/**
 * Check whether a URL is listed in URLhaus.
 * @param {string} url - Target URL to check.
 * @param {object} options - Optional configuration overrides (e.g. timeout, apiKey).
 * @returns {Promise<object>} Threat intelligence result.
 */
async function checkUrlhaus(url, options = {}) {
  const authKey = options.apiKey || process.env.URLHAUS_AUTH_KEY;
  const timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;

  if (!authKey || authKey.trim() === "" || authKey === "your_urlhaus_api_key_here") {
    return {
      checked: false,
      status: "not_configured",
      threat: null,
      tags: [],
      message: "URLhaus API key is not configured on this server."
    };
  }

  try {
    const response = await fetch(URLHAUS_ENDPOINT, {
      method: "POST",
      headers: {
        "Auth-Key": authKey.trim(),
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({ url }),
      signal: AbortSignal.timeout(timeoutMs)
    });

    if (!response.ok) {
      return {
        checked: false,
        status: "provider_error",
        threat: null,
        tags: [],
        message: `URLhaus service returned HTTP ${response.status}.`
      };
    }

    const data = await response.json();

    if (data.query_status === "ok") {
      return {
        checked: true,
        status: "listed",
        threat: data.threat || "Malware / Phishing",
        urlStatus: data.url_status || "online",
        dateAdded: data.date_added || null,
        tags: Array.isArray(data.tags) ? data.tags : [],
        message: "Warning: URL is listed in URLhaus threat intelligence database."
      };
    }

    if (data.query_status === "no_results") {
      return {
        checked: true,
        status: "not_listed",
        threat: null,
        tags: [],
        message: "URL was not found in the URLhaus threat database."
      };
    }

    return {
      checked: false,
      status: "provider_error",
      threat: null,
      tags: [],
      message: `URLhaus returned query status: '${data.query_status || "unknown"}'.`
    };
  } catch (err) {
    const isTimeout = err.name === "TimeoutError" || err.message?.includes("timed out");
    return {
      checked: false,
      status: "unavailable",
      threat: null,
      tags: [],
      message: isTimeout
        ? "URLhaus request timed out."
        : "URLhaus could not be reached or network error occurred."
    };
  }
}

module.exports = {
  checkUrlhaus,
  URLHAUS_ENDPOINT
};
