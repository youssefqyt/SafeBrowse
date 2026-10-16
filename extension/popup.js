/**
 * SafeBrowse Extension Popup Controller
 * Manages tab detection, backend API integration, offline heuristic fallback,
 * connection settings, and secure DOM rendering.
 */

const DEFAULT_API_URL = "http://localhost:5000";

document.addEventListener("DOMContentLoaded", async () => {
  // DOM Elements
  const targetHostnameEl = document.getElementById("target-hostname");
  const targetFullUrlEl = document.getElementById("target-full-url");
  const targetProtocolBadge = document.getElementById("target-protocol-badge");
  const scanButton = document.getElementById("scan-button");
  const scanButtonText = document.getElementById("scan-button-text");
  const resultContainer = document.getElementById("result-container");
  const backendIndicator = document.getElementById("backend-indicator");
  const backendIndicatorText = document.getElementById("backend-indicator-text");

  // Settings DOM
  const toggleSettingsBtn = document.getElementById("toggle-settings-btn");
  const closeSettingsBtn = document.getElementById("close-settings-btn");
  const settingsPanel = document.getElementById("settings-panel");
  const apiUrlInput = document.getElementById("api-url-input");
  const testConnBtn = document.getElementById("test-connection-btn");
  const saveSettingsBtn = document.getElementById("save-settings-btn");
  const connStatusMsg = document.getElementById("connection-status-msg");

  let currentUrl = "";
  let currentHostname = "";
  let configuredApiUrl = DEFAULT_API_URL;

  // 1. Load Stored Configuration
  try {
    if (typeof chrome !== "undefined" && chrome.storage?.local) {
      const stored = await chrome.storage.local.get(["safebrowse_api_url"]);
      if (stored.safebrowse_api_url) {
        configuredApiUrl = stored.safebrowse_api_url.replace(/\/+$/, "");
      }
    } else {
      const localStored = localStorage.getItem("safebrowse_api_url");
      if (localStored) configuredApiUrl = localStored.replace(/\/+$/, "");
    }
  } catch (err) {
    console.warn("Could not load stored API URL, using default:", err);
  }

  apiUrlInput.value = configuredApiUrl;

  // 2. Settings Toggle & Save Handlers
  toggleSettingsBtn.addEventListener("click", () => {
    const isHidden = settingsPanel.classList.toggle("hidden");
    settingsPanel.setAttribute("aria-expanded", String(!isHidden));
  });

  closeSettingsBtn.addEventListener("click", () => {
    settingsPanel.classList.add("hidden");
    settingsPanel.setAttribute("aria-expanded", "false");
  });

  saveSettingsBtn.addEventListener("click", async () => {
    const newUrl = apiUrlInput.value.trim().replace(/\/+$/, "");
    if (!newUrl) return;

    configuredApiUrl = newUrl;
    try {
      if (typeof chrome !== "undefined" && chrome.storage?.local) {
        await chrome.storage.local.set({ safebrowse_api_url: newUrl });
      } else {
        localStorage.setItem("safebrowse_api_url", newUrl);
      }
      showSettingsNotice("Settings saved successfully.", "success");
      setTimeout(() => settingsPanel.classList.add("hidden"), 1200);
    } catch (err) {
      showSettingsNotice("Failed to save settings.", "error");
    }
  });

  testConnBtn.addEventListener("click", async () => {
    const testUrl = apiUrlInput.value.trim().replace(/\/+$/, "");
    showSettingsNotice("Testing connection...", "info");

    try {
      const resp = await fetch(`${testUrl}/api/health`, {
        signal: AbortSignal.timeout(6000)
      });
      if (resp.ok) {
        const data = await resp.json();
        showSettingsNotice(`Connected: ${data.service || "SafeBrowse API"} (v${data.version || "1.0"})`, "success");
        setBackendStatus("online", "Connected to API");
      } else {
        showSettingsNotice(`Server returned HTTP ${resp.status}.`, "error");
        setBackendStatus("offline", "Server Error");
      }
    } catch (err) {
      showSettingsNotice("Cannot reach server. Check URL or verify backend is running.", "error");
      setBackendStatus("offline", "Backend Unreachable");
    }
  });

  function showSettingsNotice(msg, type) {
    connStatusMsg.style.display = "block";
    connStatusMsg.textContent = msg;
    if (type === "success") {
      connStatusMsg.style.background = "#ecfdf5";
      connStatusMsg.style.color = "#047857";
      connStatusMsg.style.border = "1px solid #a7f3d0";
    } else if (type === "error") {
      connStatusMsg.style.background = "#fef2f2";
      connStatusMsg.style.color = "#b91c1c";
      connStatusMsg.style.border = "1px solid #fecaca";
    } else {
      connStatusMsg.style.background = "#f1f5f9";
      connStatusMsg.style.color = "#475569";
      connStatusMsg.style.border = "1px solid #e2e8f0";
    }
  }

  function setBackendStatus(state, label) {
    const dot = backendIndicator.querySelector(".status-dot");
    dot.className = "status-dot";
    if (state === "offline") dot.classList.add("offline");
    if (state === "error") dot.classList.add("error");
    backendIndicatorText.textContent = label;
  }

  // 3. Inspect Current Active Tab
  try {
    let tabs = [];
    if (typeof chrome !== "undefined" && chrome.tabs?.query) {
      tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    }

    const activeTab = tabs[0];

    if (activeTab?.url) {
      let parsed;
      try {
        parsed = new URL(activeTab.url);
      } catch {
        parsed = null;
      }

      if (parsed && ["http:", "https:"].includes(parsed.protocol)) {
        currentUrl = activeTab.url;
        currentHostname = parsed.hostname;

        targetHostnameEl.textContent = currentHostname;
        targetFullUrlEl.textContent = currentUrl;

        if (parsed.protocol === "https:") {
          targetProtocolBadge.textContent = "HTTPS Encrypted";
          targetProtocolBadge.className = "protocol-badge https";
        } else {
          targetProtocolBadge.textContent = "HTTP Insecure";
          targetProtocolBadge.className = "protocol-badge http";
        }
      } else {
        handleNonScannablePage(activeTab.url);
      }
    } else {
      handleNonScannablePage("browser internal");
    }
  } catch (err) {
    console.error("Failed to query active tab:", err);
    handleNonScannablePage("unknown");
  }

  function handleNonScannablePage(urlText) {
    targetHostnameEl.textContent = "Protected Browser Page";
    targetFullUrlEl.textContent = `Internal browser tabs cannot be scanned (${urlText || "system tab"}).`;
    targetProtocolBadge.textContent = "System";
    targetProtocolBadge.className = "protocol-badge";
    scanButton.disabled = true;
    scanButtonText.textContent = "Scanner Unavailable for System Page";
  }

  // 4. Scan Button Execution
  scanButton.addEventListener("click", async () => {
    if (!currentUrl) return;

    scanButton.disabled = true;
    scanButtonText.textContent = "Analyzing Target & Intelligence...";

    // Show Scanning State in Result Container
    resultContainer.replaceChildren();
    const loadingCard = document.createElement("div");
    loadingCard.className = "idle-state";

    const spinner = document.createElement("div");
    spinner.className = "scanning-spinner";
    spinner.style.borderColor = "var(--primary) transparent var(--primary) transparent";
    spinner.style.margin = "0 auto 10px";

    const loadingText = document.createElement("p");
    loadingText.className = "muted";
    loadingText.textContent = "Evaluating heuristic indicators, querying URLhaus threat intelligence, and generating AI explanation...";

    loadingCard.append(spinner, loadingText);
    resultContainer.appendChild(loadingCard);

    let scanData;

    try {
      // 4a. Attempt Cloud Backend Scan
      const response = await fetch(`${configuredApiUrl}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: currentUrl }),
        signal: AbortSignal.timeout(12000)
      });

      if (!response.ok) {
        throw new Error(`API responded with HTTP ${response.status}`);
      }

      scanData = await response.json();
      setBackendStatus("online", "Cloud API Active");
    } catch (networkOrApiError) {
      // 4b. Graceful Offline Heuristic Fallback
      console.warn("Backend API unreachable, activating local heuristic fallback:", networkOrApiError.message);
      setBackendStatus("offline", "Offline Fallback Active");

      const localAnalysis = typeof scanUrlLocally === "function"
        ? scanUrlLocally(currentUrl)
        : { score: 0, risk: "Unknown", findings: [] };

      scanData = {
        url: currentUrl,
        hostname: currentHostname || "Target Site",
        score: localAnalysis.score,
        risk: localAnalysis.risk,
        findings: localAnalysis.findings,
        threatIntel: {
          checked: false,
          status: "unavailable",
          message: "Cloud backend unreachable; URLhaus threat database could not be queried."
        },
        explanation: "The SafeBrowse cloud backend could not be reached. Local heuristic analysis was performed instead. Cloud threat intelligence and AI evaluation require an active backend connection.",
        explanationSource: "fallback",
        providerModel: "local-client-rules",
        note: "Local heuristic results cannot verify whether a URL is free of malicious intent."
      };
    } finally {
      scanButton.disabled = false;
      scanButtonText.textContent = "Re-Scan Website";
    }

    renderResult(scanData);
  });

  // 5. Secure DOM Result Renderer (No innerHTML for AI/user strings)
  function renderResult(data) {
    resultContainer.replaceChildren();

    const card = document.createElement("div");
    card.className = "result-card";

    // A. Risk Banner
    const riskLevel = String(data.risk || "Unknown").toLowerCase();
    const riskBanner = document.createElement("div");
    riskBanner.className = `risk-banner ${riskLevel}`;

    const riskTitle = document.createElement("p");
    riskTitle.className = "risk-title";
    riskTitle.textContent = `Security Risk: ${data.risk || "Unknown"}`;

    const riskBadge = document.createElement("span");
    riskBadge.className = "risk-badge-text";
    riskBadge.textContent = `${data.risk || "Unknown"} Risk`;

    riskBanner.append(riskTitle, riskBadge);
    card.appendChild(riskBanner);

    // B. Heuristic Score Visualizer
    const scoreSection = document.createElement("div");
    scoreSection.className = "score-section";

    const scoreRow = document.createElement("div");
    scoreRow.className = "score-row";

    const scoreTitle = document.createElement("span");
    scoreTitle.className = "score-title";
    scoreTitle.textContent = "Heuristic Warning Score";

    const scoreNum = document.createElement("span");
    scoreNum.className = "score-number";
    scoreNum.textContent = `${data.score ?? 0} / 100`;

    scoreRow.append(scoreTitle, scoreNum);

    const scoreTrack = document.createElement("div");
    scoreTrack.className = "score-track";

    const scoreFill = document.createElement("div");
    scoreFill.className = `score-fill ${riskLevel}`;
    scoreFill.style.width = `${Math.min(Math.max(data.score ?? 0, 0), 100)}%`;
    scoreTrack.appendChild(scoreFill);

    const scoreClarification = document.createElement("p");
    scoreClarification.className = "score-clarification";
    scoreClarification.textContent = "Heuristic score reflects observed structural warning indicators; it is not a statistical probability of safety.";

    scoreSection.append(scoreRow, scoreTrack, scoreClarification);
    card.appendChild(scoreSection);

    // C. AI Explanation Card
    const aiCard = document.createElement("div");
    aiCard.className = "ai-card";

    const aiHeader = document.createElement("div");
    aiHeader.className = "ai-header";

    const aiTitleRow = document.createElement("div");
    aiTitleRow.className = "ai-title-row";
    aiTitleRow.textContent = "AI Security Assessment";

    const aiBadge = document.createElement("span");
    const source = (data.explanationSource || "fallback").toLowerCase();
    aiBadge.className = `ai-provider-badge ${source}`;

    if (source === "groq") {
      const modelName = data.providerModel ? data.providerModel.split("/").pop() : "AI";
      aiBadge.textContent = `Groq (${modelName})`;
    } else if (source === "gemini") {
      aiBadge.textContent = "Google Gemini";
    } else {
      aiBadge.textContent = "Rule Fallback";
    }

    aiHeader.append(aiTitleRow, aiBadge);

    const aiText = document.createElement("p");
    aiText.className = "ai-explanation";
    aiText.textContent = data.explanation || "No assessment generated.";

    const aiDisclaimer = document.createElement("p");
    aiDisclaimer.className = "ai-disclaimer";
    aiDisclaimer.textContent = "AI explains technical scan indicators; it does not certify websites as safe.";

    aiCard.append(aiHeader, aiText, aiDisclaimer);
    card.appendChild(aiCard);

    // D. Threat Intelligence Card
    const threatCard = document.createElement("div");
    threatCard.className = "threat-card";

    const threatHeader = document.createElement("div");
    threatHeader.className = "threat-header";

    const threatTitle = document.createElement("span");
    threatTitle.className = "threat-title";
    threatTitle.textContent = "Threat Intelligence (URLhaus)";

    const intel = data.threatIntel || {};
    const threatTag = document.createElement("span");
    threatTag.className = "threat-status-tag";

    if (intel.status === "listed") {
      threatTag.classList.add("listed");
      threatTag.textContent = "Threat Listed";
    } else if (intel.status === "not_listed") {
      threatTag.classList.add("clean");
      threatTag.textContent = "No Record";
    } else {
      threatTag.classList.add("offline");
      threatTag.textContent = intel.status === "not_configured" ? "Not Configured" : "Unavailable";
    }

    threatHeader.append(threatTitle, threatTag);

    const threatDetail = document.createElement("p");
    threatDetail.className = "threat-detail";

    if (intel.status === "listed") {
      let desc = `Active threat flagged: ${intel.threat || "Malware"}.`;
      if (intel.tags?.length) desc += ` Tags: ${intel.tags.join(", ")}.`;
      threatDetail.textContent = desc;
      threatDetail.style.color = "var(--risk-high)";
      threatDetail.style.fontWeight = "600";
    } else {
      threatDetail.textContent = intel.message || "Threat database lookup status pending.";
    }

    threatCard.append(threatHeader, threatDetail);
    card.appendChild(threatCard);

    // E. Findings Section
    const findings = Array.isArray(data.findings) ? data.findings : [];
    const findingsSection = document.createElement("div");
    findingsSection.className = "findings-section";

    const findingsToggle = document.createElement("button");
    findingsToggle.className = "findings-toggle";
    findingsToggle.type = "button";
    findingsToggle.textContent = `Detailed Indicators (${findings.length}) ▾`;

    const findingsList = document.createElement("div");
    findingsList.className = "findings-list";

    findingsToggle.addEventListener("click", () => {
      const isCollapsed = findingsList.classList.toggle("collapsed");
      findingsToggle.textContent = `Detailed Indicators (${findings.length}) ${isCollapsed ? "▸" : "▾"}`;
    });

    if (findings.length === 0) {
      const emptyNotice = document.createElement("p");
      emptyNotice.className = "muted";
      emptyNotice.style.margin = "4px 0";
      emptyNotice.textContent = "No heuristic warning indicators detected for this target.";
      findingsList.appendChild(emptyNotice);
    } else {
      for (const finding of findings) {
        const item = document.createElement("div");
        item.className = "finding-item";

        const head = document.createElement("div");
        head.className = "finding-head";

        const chip = document.createElement("span");
        chip.className = `severity-chip ${finding.severity || "low"}`;
        chip.textContent = finding.severity || "info";

        const itemTitle = document.createElement("span");
        itemTitle.className = "finding-title";
        itemTitle.textContent = finding.message || "Indicator";

        head.append(chip, itemTitle);

        const desc = document.createElement("p");
        desc.className = "finding-desc";
        desc.textContent = finding.explanation || "Review this indicator.";

        item.append(head, desc);
        findingsList.appendChild(item);
      }
    }

    findingsSection.append(findingsToggle, findingsList);
    card.appendChild(findingsSection);

    resultContainer.appendChild(card);
  }
});
