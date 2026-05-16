# TLS Posture Analyzer

> **Android Network Security Audit Tool** — Static analysis, APK decompilation, TLS inspection and AI-powered reporting in one interface.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![React](https://img.shields.io/badge/react-18-61dafb)
![FastAPI](https://img.shields.io/badge/fastapi-0.115-009688)

---

## Overview

TLS Posture Analyzer is an open-source security audit tool designed for Android application penetration testers and mobile security engineers. It automates the most tedious parts of a TLS posture review:

- **Endpoint extraction** from decompiled Java/Smali code, raw APK strings, proxy logs, and HAR files
- **Network Security Config (NSC) analysis** with full AXML decoding (no apktool required for NSC)
- **Java security pattern detection** — TrustManager bypass, HostnameVerifier, WebView SSL errors, OkHttp certificate pinning, cleartext traffic, and more
- **AI-generated reports** via Groq (Llama 3.3 70B) with risk scoring and hardening recommendations
- **Batch APK analysis** for large-scale assessments

---

## Features

### 🔍 Input Sources
| Source | Description |
|--------|-------------|
| APK file | Full decompilation via jadx (Java source) + apktool (Smali) |
| HAR file | HTTP Archive from Burp Suite, mitmproxy, Chrome DevTools |
| Proxy logs | Raw CONNECT/GET logs (Burp, mitmproxy text format) |
| NSC XML | Manual paste of `network_security_config.xml` |
| Raw strings | Output of `strings classes.dex` or any text dump |

### 🛡️ Security Checks
- **TrustManager custom** — detects empty `checkServerTrusted()` (TLS bypass)
- **HostnameVerifier** — `AllowAllHostnameVerifier`, `verify() → true`
- **WebView SSL errors** — `handler.proceed()` in `onReceivedSslError`
- **OkHttp CertificatePinner** — presence and SHA-256 pin validation
- **TLS version** — SSLv3 / TLS 1.0 detection, TLS 1.2/1.3 enforcement
- **Cleartext traffic** — `cleartextTrafficPermitted=true`, `usesCleartextTraffic=true`
- **Debug overrides** — user certificates active outside debug scope
- **Cipher suites** — `ConnectionSpec.MODERN_TLS` detection
- **SSLContext / HttpURLConnection** — custom SSL factory detection
- **Certificate Transparency** — lifecycle and pin expiry warnings
- **NSC domain rules** — `base-config`, `domain-config`, `pin-set` deep parsing

### 📊 Endpoint Analysis
- URL / domain / bare IP extraction with noise filtering (no XML namespaces, no Android SDK artifacts)
- Environment classification: **prod**, **test**, **unknown**
- NSC coverage correlation per endpoint
- TLS risk level per endpoint (based on NSC + code patterns)
- Anomaly detection: cleartext HTTP, private IPs, ngrok/tunneling domains, mixed protocols

### 🤖 AI Report (Groq)
- Risk summary with score /10
- Top 3 critical findings
- Prioritized hardening recommendations (P0→P3)
- Full hardened NSC XML example
- Streaming output via Server-Sent Events

---

## Architecture

```
tls-analyzer/
├── backend/               # FastAPI — Python 3.10+
│   ├── main.py            # API routes (/analyze/*, /decompile/*, /ai/stream)
│   ├── analyzer.py        # Endpoint extraction, NSC parsing, anomaly detection
│   ├── decompiler.py      # jadx + apktool wrapper (3-pass decompilation strategy)
│   └── requirements.txt
└── frontend/              # React 18 + Vite
    └── src/
        ├── App.jsx         # Main app (6 tabs: Inputs, Endpoints, TLS, Anomalies, Decompilation, AI)
        ├── api.js          # Backend API client
        └── components/
            ├── DecompilerViewer.jsx   # Java file browser with evidence highlighting
            ├── CodeSnippet.jsx        # Syntax-aware code display with line numbers
            └── EvidenceBadge.jsx      # Clickable anomaly badges
```

---

## Prerequisites

| Tool | Required | Purpose |
|------|----------|---------|
| Python 3.10+ | ✅ | Backend runtime |
| Node.js 18+ | ✅ | Frontend build |
| jadx | Recommended | Java source decompilation |
| apktool | Optional | Smali decompilation + NSC fallback |
| Groq API key | Optional | AI report generation |

### Installing jadx and apktool

```bash
# Linux (Debian/Ubuntu)
sudo apt install jadx apktool

# macOS
brew install jadx apktool

# Windows (Chocolatey)
choco install jadx apktool
```

> **Note:** If jadx is not installed, the tool falls back to string extraction from raw APK assets. Full Java code analysis requires jadx.

---

## Quick Start

### Linux / macOS

```bash
git clone https://github.com/M4l1k40/tls-analyzer
cd tls-analyzer
chmod +x start.sh
./start.sh
```

### Windows

```bat
start.bat
```

Both scripts:
1. Create a Python virtual environment and install dependencies
2. Install Node.js packages
3. Start the FastAPI backend on **port 8000**
4. Start the Vite frontend on **port 5173**

Open **http://localhost:5173** in your browser.

---

## Manual Setup

```bash
# Backend
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# Frontend (separate terminal)
cd frontend
npm install
npm run dev
```

---

## Configuration

### Groq API Key (AI reports)

```bash
# Option A: .env file (recommended)
cp backend/.env.example backend/.env
# Edit and set: GROQ_API_KEY=gsk_...

# Option B: at runtime via the API
curl -X POST http://localhost:8000/config/api-key \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "api_key=gsk_your_key_here"
```

Check key status:
```bash
curl http://localhost:8000/config/api-key-status
# {"configured": true, "api_key_preview": "gsk_7...xLL"}
```

---

## API Reference

### Health & Configuration
```
GET  /health                  → Backend status + API key presence
POST /config/api-key          → Set Groq API key at runtime
GET  /config/api-key-status   → Masked key status
```

### Analysis
```
POST /analyze/text            → Text-based analysis (strings + proxy logs + NSC)
POST /analyze/apk             → Single APK analysis (jadx primary)
POST /analyze/har             → HAR file analysis (endpoints + security headers)
POST /analyze/folder          → Batch APK analysis (multiple files)
```

### Decompilation
```
POST /decompile/java          → Java source via jadx (3-pass strategy)
POST /decompile/smali         → Smali bytecode via apktool
POST /decompile/full          → Complete analysis: static + smali + java + secrets
GET  /decompile/tools-status  → Check jadx / apktool availability
```

### AI
```
POST /ai/stream               → Groq Llama streaming (SSE)
```

Interactive API docs: **http://localhost:8000/docs**

---

## Usage Examples

### Analyze a single APK (curl)
```bash
curl -X POST http://localhost:8000/analyze/apk \
  -F "file=@app.apk"
```

### Batch analysis
```bash
curl -X POST http://localhost:8000/analyze/folder \
  -F "files=@app1.apk" \
  -F "files=@app2.apk" \
  -F "files=@app3.apk" \
  > results.json
```

### Full decompilation with secret detection
```bash
curl -X POST http://localhost:8000/decompile/full \
  -F "file=@app.apk" | python3 -m json.tool
```

---

## Response Structure

```json
{
  "endpoints": [
    { "type": "url", "value": "https://api.example.com/v2", "env": "prod", "source": "java_code" }
  ],
  "anomalies": [
    { "endpoint": "http://dev.example.com", "issue": "Cleartext HTTP", "severity": "critical" }
  ],
  "secrets": [
    { "type": "api_key", "value": "sk_live_...", "file": "Config.java" }
  ],
  "tls_checks": [
    { "label": "Certificate Pinning (NSC)", "ok": false, "severity": "high", "detail": "No pin declared" }
  ],
  "java_security_checks": [
    { "label": "TrustManager custom", "found": true, "vulnerable": true, "severity": "critical" }
  ],
  "stats": {
    "total": 12, "prod": 8, "test": 2, "cleartext": 1,
    "critical": 3, "high": 2, "secrets_found": 1
  },
  "decompilation_status": "success"
}
```

---

## Decompilation Strategy

jadx decompilation uses a **3-pass approach** for maximum coverage:

| Pass | Mode | Target |
|------|------|--------|
| 1 | Standard | Clean APKs, unobfuscated code |
| 2 | Permissive | Obfuscated APKs (`--show-bad-code --deobf --no-res`) |
| 3 | Partial recovery | Heavily protected APKs — collects whatever jadx produced before failing |

NSC (Network Security Config) is decoded from binary AXML format without requiring apktool, using a built-in pure-Python AXML decoder.

---

## OWASP / CWE Coverage

| ID | Title |
|----|-------|
| CWE-295 | Improper Certificate Validation |
| CWE-297 | Improper Validation of Certificate with Host Mismatch |
| CWE-326 | Inadequate Encryption Strength |
| CWE-327 | Use of Broken or Risky Cryptographic Algorithm |
| OWASP M2 | Insecure Data Storage / Transport |
| OWASP M3 | Insecure Communication |

---

## Troubleshooting

**Backend not reachable**
```bash
curl http://localhost:8000/health
# If timeout: check that uvicorn is running on port 8000
```

**jadx not found**
```bash
curl http://localhost:8000/decompile/tools-status
# "available": false → install jadx and ensure it is in PATH
```

**Port conflict**
```bash
uvicorn main:app --port 8001
# Update BASE in frontend/src/api.js accordingly
```

**Groq API key error**
```bash
curl http://localhost:8000/config/api-key-status
# {"configured": false} → set key via /config/api-key or .env
```

---

## License

MIT — see [LICENSE](LICENSE)

---

## Author

**M4l1k40** — 2026
