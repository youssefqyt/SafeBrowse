# SafeBrowse — AI-Powered Browser Security Extension & Threat Intelligence API

SafeBrowse is a modern Manifest V3 browser security extension and Node.js microservice designed to protect users against phishing, deceptive hostnames, credential-harvesting schemes, and malicious infrastructure. It combines real-time URL heuristic analysis, abuse.ch URLhaus threat intelligence, and Generative AI security explanations (powered by Groq or Google Gemini) with resilient offline fallback.

---

## Architecture Overview

```text
Browser Extension (Edge / Chromium)
       │
       ▼
Express API Backend (Node.js)
       │
       ├─► 1. Multi-Vector Heuristic Analyzer (9 Indicators)
       │
       ├─► 2. URLhaus Threat Intelligence Lookup (abuse.ch)
       │
       └─► 3. AI Security Explanation Engine
                 │
                 ├── Groq Cloud (LLaMA 3.3 70B / LLaMA 3.1 8B)
                 ├── Google Gemini (Gemini 1.5 Flash / 2.0 Flash)
                 └── Deterministic Heuristic Fallback
       │
       ▼
Structured Security Verdict & Actionable Insights
       │
       ▼
Modern Cybersecurity Extension UI
```

---

## Key Features

1. **Multi-Vector Heuristic Engine**:
   - **Insecure Transport**: Flags unencrypted HTTP connections.
   - **IP-Based Hostnames**: Detects direct IPv4 access often used in phishing.
   - **Embedded User Credentials**: Identifies RFC 3986 userinfo patterns used in obfuscation.
   - **Excessive URL Length**: Flags URLs over 200 characters hiding deceptive parameters.
   - **Suspicious Hostname Keywords**: Detects sensitive terms (`login`, `verify`, `account`, `banking`, `wallet`).
   - **Punycode / IDN Homographs**: Detects `xn--` internationalized labels designed to impersonate familiar brands.
   - **Deep Subdomain Nesting**: Flags domains with 4 or more subdomains.
   - **Link Shortener Detection**: Identifies public URL shorteners hiding destination domains.
   - **Digit-Heavy Hostnames**: Detects algorithmic or disposable domain patterns.

2. **Real-Time Threat Intelligence**:
   - Integrates with the abuse.ch URLhaus database to check for active malware distribution sites.

3. **Generative AI Risk Explanations**:
   - **Preferred**: Groq API using `llama-3.3-70b-versatile` or `llama-3.1-8b-instant`.
   - **Alternative**: Google Gemini API using `gemini-1.5-flash`.
   - Privacy-first URL sanitization: Query strings and authentication parameters are stripped before AI evaluation.
   - Defensive prompt boundaries neutralizing adversarial prompt injection attempts in domain names.

4. **Resilient Offline Fallback**:
   - If the backend is unreachable or the AI provider experiences outages or rate limits, the client and server gracefully fall back to local heuristic rules without crashing or blocking the user.

5. **Modern Cybersecurity UI/UX**:
   - Deep emerald green branding (`#006c49`), slate card architecture, and accessible contrast.
   - Real-time score visualizer clearly distinguishing heuristic scores from statistical safety probabilities.
   - In-popup backend connection manager allowing seamless toggling between Render cloud production and local development.
   - Expandable finding cards with severity chips and actionable remediation advice.

---

## Directory Structure

```text
SafeBrowse/
├── .gitignore                      # Root git ignore rules (protects .env and node_modules)
├── LICENSE                         # MIT License
├── README.md                       # Comprehensive guide and documentation
├── extension/                      # Manifest V3 browser extension
│   ├── manifest.json               # Extension manifest, permissions, and icons
│   ├── popup.html                  # Extension UI structure and settings drawer
│   ├── popup.css                   # Modern cybersecurity styling and animations
│   ├── popup.js                    # Tab inspection, API client, and safe DOM renderer
│   ├── scanner.js                  # Client-side heuristic fallback scanner
│   └── icons/                      # Extension icons (16px, 32px, 48px, 128px)
│       ├── icon16.png
│       ├── icon32.png
│       ├── icon48.png
│       └── icon128.png
└── backend/                        # Express API server and microservices
    ├── server.js                   # Application entry point and security middleware
    ├── routes/
    │   ├── scan.js                 # URL scan route coordinating heuristics, intel, and AI
    │   └── health.js               # Service health and integration readiness endpoint
    ├── services/
    │   ├── urlAnalyzer.js          # Modular 9-vector heuristic analyzer
    │   ├── urlhausService.js       # URLhaus API client with timeouts and status checks
    │   └── aiExplanationService.js # Dual-provider (Groq/Gemini) AI explanation engine
    ├── middleware/
    │   ├── corsConfig.js           # Extension-aware CORS policy
    │   ├── errorHandler.js         # Safe error handler preventing info leakage
    │   └── rateLimiter.js          # IP-based rate limiting (60 req/min)
    ├── tests/                      # Automated test suite (Node.js test runner)
    │   ├── urlAnalyzer.test.js
    │   ├── urlhausService.test.js
    │   ├── aiExplanationService.test.js
    │   ├── scanRoute.test.js
    │   └── clientScanner.test.js
    ├── package.json                # Dependencies and test scripts
    ├── .env                        # Local environment variables (DO NOT COMMIT)
    ├── .env.example                # Template for configuration
    └── .gitignore                  # Backend-specific ignore rules
```

---

## Technology Stack

- **Browser Extension**: Manifest V3, HTML5, Vanilla CSS3, Modern JavaScript (ES2022+), Chrome Extension APIs (`chrome.tabs`, `chrome.storage`).
- **Backend API**: Node.js (v18+ / v22+), Express 5, Helmet, CORS, Express-Rate-Limit.
- **AI Providers**: Groq SDK (`groq-sdk`), Google Gen AI SDK (`@google/genai`), Fetch API with `AbortSignal.timeout`.
- **Testing**: Node.js Native Test Runner (`node:test`, `node:assert/strict`).

---

## Prerequisites

- **Node.js**: v18.0.0 or higher (v20+ or v22+ recommended). Verify with `node -v`.
- **npm**: v9.0.0 or higher. Verify with `npm -v`.
- **Browser**: Microsoft Edge, Google Chrome, Brave, or any Chromium-based browser supporting Manifest V3.

---

## Local Installation & Setup

### 1. Clone or Open the Repository

```bash
cd SafeBrowse
```

### 2. Install Backend Dependencies

> **Note:** Run this command inside the `backend/` directory.

```bash
cd backend
npm install
```

### 3. Configure Environment Variables

Inside `backend/`, copy `.env.example` to `.env`:

```bash
# Windows PowerShell (inside backend/)
Copy-Item .env.example .env

# Linux / macOS (inside backend/)
cp .env.example .env
```

Open `backend/.env` in your editor and configure your settings:

```env
PORT=5000
NODE_ENV=development

# AI Provider: 'groq' | 'gemini' | 'none'
AI_PROVIDER=groq

# Groq API Configuration (Preferred)
GROQ_API_KEY=gsk_your_actual_key_here
GROQ_MODEL=llama-3.3-70b-versatile

# Google Gemini API Configuration (Alternative)
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-1.5-flash

# Timeout in milliseconds
AI_REQUEST_TIMEOUT_MS=6000

# URLhaus API Key (optional for public endpoint, recommended for production)
URLHAUS_AUTH_KEY=your_urlhaus_api_key_here

# Security
RATE_LIMIT_WINDOW_MS=60000
RATE_LIMIT_MAX_REQUESTS=60
ALLOWED_ORIGINS=*
```

---

## Obtaining API Keys

### Groq API Key (Preferred Provider)

1. Go to the [Groq Console](https://console.groq.com/).
2. Sign up or log in using your Google or GitHub account.
3. In the left navigation bar, click **API Keys**.
4. Click **Create API Key**, enter a descriptive name (e.g. `SafeBrowse-Dev`), and copy the generated key (`gsk_...`).
5. Paste the key into `backend/.env` under `GROQ_API_KEY=`.
6. Supported models: `llama-3.3-70b-versatile` (high reasoning), `llama-3.1-8b-instant` (ultra-fast).

### Google Gemini API Key (Alternative Provider)

1. Go to [Google AI Studio](https://aistudio.google.com/app/apikey).
2. Sign in with your Google account.
3. Click **Create API Key** and select or create a Google Cloud project.
4. Copy your API key and paste it into `backend/.env` under `GEMINI_API_KEY=`.
5. In `backend/.env`, set `AI_PROVIDER=gemini`.
6. Supported models: `gemini-1.5-flash`, `gemini-2.0-flash`.

### URLhaus API Key

1. Visit [abuse.ch URLhaus API](https://urlhaus.abuse.ch/api/).
2. Free registration provides an Auth-Key for higher rate limits.
3. Paste the key into `backend/.env` under `URLHAUS_AUTH_KEY=`.

---

## Running the Application Locally

### 1. Start the Backend API Server

> **Directory:** Run inside `backend/`

```bash
# Standard start
npm start

# Development mode with live reload
npm run dev
```

The server will start at:
```text
[SafeBrowse API] Server actively listening on port 5000
[SafeBrowse API] Health endpoint: http://localhost:5000/api/health
[SafeBrowse API] AI Provider configured: groq
```

Verify the health check in your browser or terminal:
```bash
curl http://localhost:5000/api/health
```

Expected response:
```json
{
  "status": "ok",
  "service": "SafeBrowse API",
  "version": "1.2.0",
  "environment": "development",
  "integrations": {
    "ai": { "provider": "groq", "configured": true, "model": "llama-3.3-70b-versatile" },
    "threatIntel": { "provider": "URLhaus", "configured": true }
  }
}
```

---

## Loading the Extension Locally (Microsoft Edge / Chrome)

1. Open Microsoft Edge and navigate to `edge://extensions` (or Chrome at `chrome://extensions`).
2. In the left sidebar (or top right in Chrome), toggle on **Developer mode**.
3. Click the **Load unpacked** button.
4. Browse to your project folder and select the **`SafeBrowse/extension`** folder.
5. SafeBrowse will now appear in your browser toolbar with its green shield icon.
6. Click the extension icon on any webpage to inspect the active tab and scan it!

### In-Extension Connection Settings

The extension defaults to `http://localhost:5000`. You can configure this directly in the extension:
1. Click the **Gear icon** in the top right of the popup.
2. Enter your backend URL (e.g. `http://localhost:5000` or your live Render URL `https://safebrowse-api.onrender.com`).
3. Click **Test Connection** to verify that the backend is reachable.
4. Click **Save**. The configuration is saved in local browser storage.

---

## Running Automated Tests

The test suite runs using Node.js's built-in test runner with zero extra testing dependencies:

> **Directory:** Run inside `backend/`

```bash
npm test
```

### What is Tested:
- **`urlAnalyzer.test.js`**: All 9 heuristic indicators, URL parsing, protocol restrictions, sanitization, and scoring weights.
- **`urlhausService.test.js`**: Threat intelligence lookups, clean results, malware matches, unconfigured states, and timeout resilience.
- **`aiExplanationService.test.js`**: Groq generation, Gemini generation, prompt formatting, prompt injection defense, and graceful fallback.
- **`scanRoute.test.js`**: Endpoint validation, health check, oversized payloads, embedded credentials handling, and HTTP status codes.
- **`clientScanner.test.js`**: Client-side scanner heuristic parity with backend rules.

---

## Switching AI Providers

To switch between Groq, Gemini, or deterministic fallback, update `backend/.env`:

### To Use Groq (Default / Recommended):
```env
AI_PROVIDER=groq
GROQ_API_KEY=gsk_your_key_here
GROQ_MODEL=llama-3.3-70b-versatile
```

### To Use Google Gemini:
```env
AI_PROVIDER=gemini
GEMINI_API_KEY=your_gemini_key_here
GEMINI_MODEL=gemini-1.5-flash
```

### To Run in Deterministic Fallback Mode (No External AI API Calls):
```env
AI_PROVIDER=none
```

Restart the backend server after changing `.env`.

---

## Deployment to Render

The SafeBrowse backend is ready for one-click deployment to [Render](https://render.com/).

### 1. Push Code to GitHub

Make sure you do **NOT** commit `.env` or `node_modules` (the provided `.gitignore` handles this automatically):

```bash
git init
git add .
git commit -m "feat: complete SafeBrowse extension and backend"
git branch -M main
git remote add origin https://github.com/your-username/SafeBrowse.git
git push -u origin main
```

### 2. Create Web Service on Render

1. Log in to [Render Dashboard](https://dashboard.render.com/).
2. Click **New +** → **Web Service**.
3. Connect your GitHub repository.
4. Configure the service settings:
   - **Name**: `safebrowse-api` (or custom name)
   - **Region**: Choose closest to your audience (e.g., Oregon, Frankfurt)
   - **Root Directory**: `backend` *(CRITICAL: must specify `backend`)*
   - **Runtime**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Instance Type**: `Free`
5. Under **Environment Variables**, add:
   - `NODE_ENV`: `production`
   - `AI_PROVIDER`: `groq` (or `gemini`)
   - `GROQ_API_KEY`: *(paste your Groq key)*
   - `GROQ_MODEL`: `llama-3.3-70b-versatile`
   - `URLHAUS_AUTH_KEY`: *(paste your URLhaus key)*
   - `ALLOWED_ORIGINS`: `*`
6. Click **Deploy Web Service**.

### 3. Verify Deployment

Once Render displays **Live**, copy your service URL (e.g. `https://safebrowse-api.onrender.com`):
```bash
curl https://safebrowse-api.onrender.com/api/health
```

### 4. Point the Browser Extension to Render

Open the SafeBrowse extension popup:
1. Click the **Gear icon** in the popup header.
2. Set the API Base URL to your Render URL: `https://safebrowse-api.onrender.com`.
3. Click **Test Connection** (verify it reports `Connected: SafeBrowse API`).
4. Click **Save**.

The extension will now scan websites through your live Render cloud backend from any computer in the world!

---

## Microsoft Edge Add-ons Publication Guide

### 1. Developer Account Registration

1. Visit [Microsoft Partner Center](https://partner.microsoft.com/dashboard/microsoftedge).
2. Register for a developer account (requires a one-time registration or company verification).

### 2. Prepare the Extension ZIP Package

Only package the contents of the `extension/` folder:

```bash
# Windows PowerShell (from project root)
Compress-Archive -Path "extension\*" -DestinationPath "safebrowse-extension-v1.2.0.zip" -Force
```

Verify that the ZIP contains:
- `manifest.json` at the root of the ZIP
- `popup.html`, `popup.css`, `popup.js`, `scanner.js`
- `icons/` folder with `icon16.png`, `icon32.png`, `icon48.png`, `icon128.png`
- *Does NOT contain `node_modules`, backend files, `.env`, or `.git`.*

### 3. Partner Center Submission Checklist

- **Extension Name**: SafeBrowse - AI URL Security Scanner
- **Short Description**: Real-time browser security scanner using heuristic analysis, threat intelligence, and AI explanations to identify risky links.
- **Detailed Description**: Outline features, how indicators work, and state that scans are advisory.
- **Category**: Productivity / Security.
- **Privacy Policy**: Provide a link to your public privacy policy explaining:
  - URLs are inspected on user request only.
  - Query parameters and passwords are stripped before AI evaluation.
  - No personal identifiable information (PII) is sold or permanently stored.
- **Permissions Justification**:
  - `activeTab`: Required to read the URL of the tab the user explicitly chooses to scan.
  - `storage`: Required to save user preferences such as backend API endpoint configuration.
  - `host_permissions`: Required to communicate with the SafeBrowse analysis API.
- **Visual Assets**:
  - Store logo: 128x128 PNG (provided in `extension/icons/icon128.png`).
  - Screenshots: At least 1 screenshot (1280x800 or 640x480) showing the scan results in action.

---

## Security & Privacy Considerations

1. **Advisory Nature**: No automated scanner guarantees 100% safety. SafeBrowse provides heuristic and intelligence signals to assist user decisions.
2. **URL Sanitization**: Before passing data to AI models, URLs are sanitized to remove sensitive query parameters (`?token=...`, `?auth=...`) and user credentials.
3. **Prompt Injection Defense**: Untrusted hostname and URL components are explicitly marked as data in system prompts to prevent prompt injection.
4. **No Server-Side Fetching of Arbitrary Sites**: The backend does NOT download or render third-party pages, eliminating Server-Side Request Forgery (SSRF) risks.
5. **Rate Limiting & DoS Protection**: The backend enforces rate limiting (60 requests per minute per IP) to prevent abuse and protect AI quotas.

---

## Free-Tier & Provider Quota Information

- **Groq Free Tier**: Offers generous free tier quotas for models like `llama-3.3-70b-versatile` and `llama-3.1-8b-instant` with high request-per-minute limits. Check the Groq console for current rate limits.
- **Google Gemini Free Tier**: Free tier available through Google AI Studio (subject to standard RPM/RPD limits).
- **Render Free Tier**: Render's free Web Services spin down after 15 minutes of inactivity. When a request arrives, a cold start takes approximately 30-50 seconds. SafeBrowse extension handles timeouts gracefully.

---

## License

This project is licensed under the [MIT License](LICENSE).
