# ╔══════════════════════════════════════════════════════════════╗
# ║                 🎣  PHISHING ANALYZER                       ║
# ║         ML-Driven Phishing Detection Engine                 ║
# ╚══════════════════════════════════════════════════════════════╝

An intelligent phishing detection engine that uses **machine learning** to analyze URLs and email content, scoring them for phishing risk with a trained classification model.

```
          ┌──────────┐      ┌──────────────┐      ┌──────────┐
 Input ───▶  Feature  ──▶   ML Pipeline   ──▶   Risk Score │
 (URL/    │  Extract  │      │  (sklearn)   │      │  0-100   │
  Email)  └──────────┘      └──────┬───────┘      └──────────┘
                                   │
                           ┌───────▼───────┐
                           │  🔴 PHISHING  │  ← high confidence
                           │  🟡 SUSPICIOUS│  ← medium confidence
                           │  🟢 SAFE      │  ← low confidence
                           └───────────────┘
```

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **ML Classification** | Calibrated ensemble (LR + RF + GBM) via scikit-learn + joblib |
| **URL Feature Extraction** | Typosquatting detection, risky TLDs, URL shorteners, IP-based URLs |
| **Email Header Analysis** | SPF/DKIM/DMARC validation, Reply-To mismatch, sender spoofing |
| **Heuristics Engine** | Urgency phrases, social engineering patterns, structural anomalies |
| **Risk Scoring** | 0–100 scale with Safe / Suspicious / Phishing thresholds |
| **Web Dashboard** | Real-time analysis via FastAPI + interactive HTML/JS UI |
| **Database Logging** | Async SQLite-backed scan history with full audit trail |
| **IMAP Scanner** | Background polling of a live mailbox with auto-quarantine |
| **VirusTotal Integration** | Optional URL reputation checks via VirusTotal v3 API |

---

## 📁 Project Structure

```
phishing-analyzer/
├── main.py                  ← FastAPI application entry point
├── src/
│   ├── analysis.py          ← Multi-signal fusion engine
│   ├── heuristics.py        ← Rule-based heuristics checks
│   ├── model.py             ← Ensemble ML model training & inference
│   ├── preprocessing.py     ← Email parsing & feature extraction
│   ├── database.py          ← Async SQLite persistence (aiosqlite)
│   ├── mail_scanner.py      ← Background IMAP scanner
│   └── config.py            ← Weights, thresholds, whitelists, API keys
├── static/
│   ├── index.html           ← Dashboard UI
│   ├── app.js               ← Frontend JavaScript
│   └── style.css            ← Dashboard styling
├── trained_model.joblib     ← Pre-trained classification model
├── test_scores.py           ← Scoring accuracy tests (6 scenarios)
├── requirements.txt
└── README.md
```

---

## 🚀 Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/hackergovind/phishing-analyzer.git
cd phishing-analyzer

python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS/Linux

pip install -r requirements.txt
```

### 2. Run

```bash
python main.py
```

Open **http://localhost:8000** for the web dashboard.  
Interactive API docs: **http://localhost:8000/docs**

### 3. Test

```bash
python test_scores.py
```

Expected output — all 6 tests should PASS:

```
Test                                        Score       Status     Expected   OK?
----------------------------------------------------------------------
1. Obvious PayPal Phishing                   75.8     Phishing     Phishing  PASS
2. Microsoft Phishing                        75.2     Phishing     Phishing  PASS
3. Credential Harvesting                     77.4     Phishing     Phishing  PASS
4. Safe Meeting Email                         9.1         Safe         Safe  PASS
5. Subtle Dropbox Phishing                   42.9   Suspicious   Suspicious  PASS
6. Nigerian Prince Scam                      35.6   Suspicious   Suspicious  PASS
```

---

## 📡 API Usage

### Analyze raw email text

```bash
curl -X POST http://localhost:8000/analyze/text \
  -F "text=URGENT: Your PayPal account has been compromised. Click here: http://paypa1.com.malicious.top/login"
```

**Response:**
```json
{
  "status": "Phishing",
  "action": "QUARANTINED — Blocked from user inbox.",
  "threat_score": 75.8,
  "confidence": 0.9,
  "breakdown": {
    "ml_score": 35.0,
    "heuristic_score": 30.0,
    "header_auth": 6.75,
    "url_risk": 4.0,
    "whitelist_offset": 0.0
  },
  "evidence": [
    { "source": "ML Ensemble", "detail": "Phishing probability: 100.00%", "contribution": 35.0 },
    { "source": "Heuristic: urgency:phrase", "detail": "Found: \"unauthorized access\"", "contribution": 5.4 }
  ]
}
```

### Analyze an EML file

```bash
curl -X POST http://localhost:8000/analyze \
  -F "file=@suspicious_email.eml"
```

### Get scan history

```bash
curl http://localhost:8000/api/results?limit=10
```

### Get statistics

```bash
curl http://localhost:8000/api/stats
```

### Start IMAP background scanner

```bash
curl -X POST http://localhost:8000/api/mail/connect \
  -H "Content-Type: application/json" \
  -d '{
    "imap_host": "imap.gmail.com",
    "email": "your@gmail.com",
    "password": "your-app-password",
    "poll_interval": 30
  }'
```

> **Note for Gmail:** You must use an [App Password](https://myaccount.google.com/apppasswords), not your regular password.

---

## ⚙️ Configuration

All tunable settings live in [`src/config.py`](src/config.py):

| Setting | Default | Description |
|---------|---------|-------------|
| `WEIGHT_ML_SCORE` | 35.0 | Max contribution from ensemble ML |
| `WEIGHT_HEURISTIC_SCORE` | 30.0 | Max contribution from heuristics |
| `WEIGHT_HEADER_AUTH` | 15.0 | Max contribution from header checks |
| `WEIGHT_URL_RISK` | 20.0 | Max contribution from URL analysis |
| `THRESHOLD_SUSPICIOUS` | 35.0 | Score above which email is Suspicious |
| `THRESHOLD_PHISHING` | 60.0 | Score above which email is Phishing |
| `WHITELIST_TRUST_OFFSET` | -25.0 | Trust discount for authenticated trusted domains |

### Optional: VirusTotal integration

```bash
export VIRUSTOTAL_API_KEY="your_vt_api_key_here"
python main.py
```

---

## 🧪 Detection Capabilities

| Indicator | Signal | Weight |
|-----------|--------|--------|
| 🔴 ML ensemble flags email | ML probabilities | Up to 35 pts |
| 🔴 Typosquatting domain (e.g. `paypa1.com`) | Levenshtein distance | 0.30–0.35 |
| 🔴 IP-based URL (e.g. `http://192.168.1.1/login`) | Regex match | 0.25 |
| 🔴 Mismatched display/href link | HTML link analysis | 0.35 |
| 🟡 Risky TLD (`.tk`, `.xyz`, `.ml`, …) | TLD list | 0.12 |
| 🟡 Urgency language cluster | Phrase matching | 0.10–0.22 per phrase |
| 🟡 Social engineering patterns | Phrase matching | 0.04–0.18 per phrase |
| 🟡 URL shortener | Domain list | 0.10 |
| 🟡 SPF/DKIM/DMARC failure | Header parsing | Up to 15 pts |
| 🟢 Authenticated trusted domain | Whitelist + auth | -25 pts boost |

---

## ⚙️ Tech Stack

| Component | Technology |
|-----------|-----------|
| **Backend** | Python 3.11+, FastAPI, uvicorn |
| **ML Pipeline** | scikit-learn (LR + RF + GBM ensemble), joblib |
| **Database** | SQLite via aiosqlite (async) |
| **Frontend** | HTML/CSS/JavaScript |
| **Email Parsing** | Python `email`, BeautifulSoup4 |
| **URL Reputation** | VirusTotal v3 API (optional) |

---

## ⚠️ Disclaimer

> **This tool is provided for educational and authorized security testing purposes only.**
>
> The author does not condone, encourage, or support the use of this software for any illegal or
> unethical activity. Any actions taken using this tool are the sole responsibility of the user.
> Always obtain explicit, written authorization before testing any system you do not own.
>
> **By using this software, you agree that:**
> 1. You will only use it on systems you own or have explicit written permission to test.
> 2. You understand and comply with all applicable local, state, national, and international laws.
> 3. The author is not responsible for any misuse, damage, or legal consequences arising from the use of this software.
> 4. This software is provided "AS IS" without warranty of any kind.
>
> If you discover a vulnerability in a third-party system, follow responsible disclosure practices.

---

## 📜 License

MIT

---

<div align="center">
<sub>Built for defenders. Used responsibly.</sub>
</div>
