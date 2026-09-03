"""
Centralized configuration for the Phishing Analyzer.
All tunable weights, thresholds, whitelists, and API keys live here.
"""
import os


# ---------------------------------------------------------------------------
# API Keys (read from environment; fall back to empty for graceful degradation)
# ---------------------------------------------------------------------------
VIRUSTOTAL_API_KEY: str = os.environ.get(
    "VIRUSTOTAL_API_KEY",
    "a4c9f495065088aeacdc116dff240c72025794410428b5dae164c1de37240d33"
)
GOOGLE_SAFE_BROWSING_API_KEY: str = os.environ.get(
    "GOOGLE_SAFE_BROWSING_API_KEY",
    "AIzaSyB-_mDnaR7FnvrTNssluCe6dwv-fnDmA7g"
)
ABUSEIPDB_API_KEY: str = os.environ.get(
    "ABUSEIPDB_API_KEY",
    "c974088d0bcb6f83451537e0b71580de39d38dd16f4fb6bcc9f1ac522c0894162d74bd31aa93986d"
)


# ---------------------------------------------------------------------------
# Trusted Domain Whitelist
# Emails authenticated (SPF pass + DKIM present) from these domains receive
# a significant trust boost, preventing false positives on legitimate mail.
# ---------------------------------------------------------------------------
TRUSTED_DOMAINS: set[str] = {
    "google.com", "gmail.com",
    "microsoft.com", "outlook.com", "hotmail.com", "live.com",
    "apple.com", "icloud.com",
    "amazon.com",
    "github.com",
    "linkedin.com",
    "facebook.com", "meta.com",
    "twitter.com", "x.com",
    "paypal.com",
    "dropbox.com",
    "slack.com",
    "zoom.us",
    "salesforce.com",
    "adobe.com",
    "netflix.com",
    "spotify.com",
}


# ---------------------------------------------------------------------------
# Scoring Weights  (sum of max contributions should allow reaching 100)
# ---------------------------------------------------------------------------
WEIGHT_ML_SCORE        = 35.0   # Max contribution from ensemble ML model
WEIGHT_HEURISTIC_SCORE = 30.0   # Max contribution from heuristics engine
WEIGHT_HEADER_AUTH     = 15.0   # Max contribution from header authentication
WEIGHT_URL_RISK        = 20.0   # Max contribution from URL analysis

# Trust boost applied to email from whitelisted authenticated domains
WHITELIST_TRUST_OFFSET = -25.0  # Negative = lowers threat score


# ---------------------------------------------------------------------------
# Verdict Thresholds
# ---------------------------------------------------------------------------
THRESHOLD_SUSPICIOUS = 35.0
THRESHOLD_PHISHING   = 60.0

# Confidence floor: if overall confidence is below this, downgrade Phishing→Suspicious
CONFIDENCE_FLOOR_FOR_PHISHING = 0.60


# ---------------------------------------------------------------------------
# Heuristic Sub-Weights
# ---------------------------------------------------------------------------
# Urgency language — individual phrases score low; clusters compound
URGENCY_PHRASES: dict[str, float] = {
    "act now":               0.15,
    "urgent":                0.12,
    "immediate action":      0.18,
    "account suspended":     0.20,
    "verify your account":   0.20,
    "confirm your identity": 0.18,
    "unauthorized access":   0.18,
    "security alert":        0.15,
    "unusual activity":      0.15,
    "click here immediately":0.22,
    "expires today":         0.14,
    "last warning":          0.18,
    "failure to respond":    0.16,
    "within 24 hours":       0.14,
    "within 48 hours":       0.12,
    "limited time":          0.12,
    "risk of closure":       0.18,
    "suspended":             0.10,
    "deactivated":           0.10,
    "update your payment":   0.20,
    "update your information": 0.16,
}

# Social engineering patterns
SOCIAL_ENGINEERING_PHRASES: dict[str, float] = {
    "dear customer":         0.08,
    "dear user":             0.10,
    "dear account holder":   0.12,
    "dear valued":           0.08,
    "it department":         0.06,
    "technical support":     0.06,
    "do not share this":     0.10,
    "you have been selected":0.14,
    "congratulations":       0.08,
    "won a prize":           0.16,
    "lottery":               0.16,
    "inheritance":           0.18,
    "kindly":                0.04,
    "please find attached":  0.03,
    "wire transfer":         0.14,
    "bitcoin":               0.10,
    "cryptocurrency":        0.08,
    "gift card":             0.14,
    "ssn":                   0.12,
    "social security":       0.12,
    "password":              0.06,
    "credit card number":    0.14,
    "bank account":          0.08,
}

# Suspicious file extensions in attachments
SUSPICIOUS_EXTENSIONS: set[str] = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".wsf", ".msi", ".com", ".pif", ".hta", ".cpl",
    ".jar", ".iso", ".img",
}

# Risky TLDs often used in phishing
RISKY_TLDS: set[str] = {
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".xyz", ".top", ".buzz", ".club", ".work",
    ".icu", ".cam", ".rest", ".surf",
}

# Known URL shortener domains
URL_SHORTENERS: set[str] = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
}


# ---------------------------------------------------------------------------
# IMAP Mail Scanner Configuration
# ---------------------------------------------------------------------------
MAIL_IMAP_HOST: str = os.environ.get("MAIL_IMAP_HOST", "imap.gmail.com")
MAIL_IMAP_PORT: int = int(os.environ.get("MAIL_IMAP_PORT", "993"))
MAIL_EMAIL: str = os.environ.get("MAIL_EMAIL", "")
MAIL_PASSWORD: str = os.environ.get("MAIL_PASSWORD", "")
MAIL_FOLDER: str = os.environ.get("MAIL_FOLDER", "INBOX")
MAIL_POLL_INTERVAL: int = int(os.environ.get("MAIL_POLL_INTERVAL", "30"))  # seconds
MAIL_QUARANTINE_FOLDER: str = os.environ.get("MAIL_QUARANTINE_FOLDER", "Phishing")

# Database
DB_PATH: str = os.path.join(os.path.dirname(__file__), "..", "phishing_analyzer.db")
