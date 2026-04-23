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
                           │  🟢 SAFE      │  ← low confidence
                           └───────────────┘
```

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **ML Classification** | Trained scikit-learn model with joblib serialization |
| **URL Feature Extraction** | Domain age, path depth, suspicious keywords, entropy analysis |
| **Email Header Analysis** | SPF/DKIM validation, sender reputation checks |
| **Risk Scoring** | 0-100 scale with configurable thresholds |
| **Web Dashboard** | Real-time analysis via Flask web interface |
| **Database Logging** | SQLite-backed scan history with full audit trail |
| **Batch Processing** | Analyze multiple URLs/emails in a single request |

---

## 📁 Project Structure

```
phishing-analyzer/
├── main.py                  ← Flask application entry point
├── src/
│   ├── feature_extractor.py ← URL & email feature engineering
│   ├── model.py             ← ML model training & prediction
│   └── utils.py             ← Helper functions
├── static/
│   ├── app.js               ← Frontend JavaScript
│   └── style.css            ← Dashboard styling
├── trained_model.joblib     ← Pre-trained classification model
├── test_scores.py           ← Model accuracy & scoring tests
├── requirements.txt
└── README.md
```

---

## 🚀 Quick Start

### 1. Clone & Install

```bash
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

Open **http://localhost:5000** for the web dashboard.

### 3. Test

```bash
python test_scores.py
```

---

## 📡 API Usage

### Analyze a URL

```bash
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "http://suspicious-login-page.tk/account/verify"}'
```

**Response:**
```json
{
  "url": "http://suspicious-login-page.tk/account/verify",
  "risk_score": 87,
  "verdict": "PHISHING",
  "confidence": 0.93,
  "features": {
    "domain_age_days": 3,
    "has_ip_address": false,
    "path_depth": 2,
    "suspicious_keywords": ["login", "verify", "account"],
    "entropy": 4.21
  }
}
```

---

## 🧪 Detection Capabilities

| Indicator | Feature | Weight |
|-----------|---------|--------|
| 🔴 New domain (< 30 days) | `domain_age_days` | High |
| 🔴 Suspicious TLD (.tk, .ml, .ga) | `tld_risk` | High |
| 🟡 Long URL path | `path_depth` | Medium |
| 🟡 Keyword triggers (login, verify, account) | `suspicious_keywords` | Medium |
| 🔴 IP address in URL | `has_ip_address` | High |
| 🟡 High entropy strings | `entropy` | Medium |
| 🔴 Punycode/IDN homograph | `is_punycode` | Critical |

---

## ⚙️ Tech Stack

| Component | Technology |
|-----------|-----------|
| **Backend** | Python, Flask |
| **ML Pipeline** | scikit-learn, joblib |
| **Database** | SQLite |
| **Frontend** | HTML/CSS/JavaScript |
| **Testing** | pytest, unittest |

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
