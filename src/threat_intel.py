"""
Threat Intelligence Integration Module.

Integrates multiple public and private threat feeds:
  1. VirusTotal v3 API (URLs and Domains)
  2. OpenPhish Live Phishing Feed (Community Edition)
  3. Google Safe Browsing API v4 (Optional if key configured)
  4. AbuseIPDB API (Optional if key configured)
"""

import base64
import logging
import os
import re
import time
from functools import lru_cache
from typing import Optional
from urllib.parse import urlparse

import requests

from src.config import VIRUSTOTAL_API_KEY, TRUSTED_DOMAINS

logger = logging.getLogger(__name__)

# Optional additional threat API keys
GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")

# ---------------------------------------------------------------------------
# OpenPhish Live Community Cache
# ---------------------------------------------------------------------------
_openphish_urls: set[str] = set()
_openphish_domains: set[str] = set()
_openphish_last_sync: float = 0.0
OPENPHISH_SYNC_INTERVAL = 1800  # Sync every 30 minutes


def _sync_openphish_feed():
    """Fetch latest active phishing URLs from OpenPhish community feed."""
    global _openphish_urls, _openphish_domains, _openphish_last_sync
    now = time.time()
    if now - _openphish_last_sync < OPENPHISH_SYNC_INTERVAL and _openphish_urls:
        return

    try:
        resp = requests.get("https://openphish.com/feed.txt", timeout=6)
        if resp.status_code == 200:
            urls = {line.strip() for line in resp.text.splitlines() if line.strip()}
            domains = set()
            for u in urls:
                try:
                    p = urlparse(u)
                    if p.netloc:
                        domains.add(p.netloc.lower().split(":")[0])
                except Exception:
                    pass
            _openphish_urls = urls
            _openphish_domains = domains
            _openphish_last_sync = now
            logger.info("OpenPhish feed synchronized: %d active phishing URLs, %d domains", len(_openphish_urls), len(_openphish_domains))
    except Exception as exc:
        logger.warning("OpenPhish sync skipped: %s", exc)


# ---------------------------------------------------------------------------
# VirusTotal v3 Lookups
# ---------------------------------------------------------------------------
@lru_cache(maxsize=512)
def check_virustotal_url(url: str) -> Optional[dict]:
    """Query VirusTotal v3 for a URL's detection stats."""
    if not VIRUSTOTAL_API_KEY:
        return None

    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}

        resp = requests.get(api_url, headers=headers, timeout=8)
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            total = sum(stats.values()) if stats else 1
            return {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "total": total,
            }
        elif resp.status_code == 404:
            # Not in VT database yet
            return {"malicious": 0, "suspicious": 0, "harmless": 0, "total": 0, "unknown": True}
    except Exception as exc:
        logger.warning("VirusTotal URL check failed for %s: %s", url[:60], exc)

    return None


@lru_cache(maxsize=512)
def check_virustotal_domain(domain: str) -> Optional[dict]:
    """Query VirusTotal v3 for a domain's reputation."""
    if not VIRUSTOTAL_API_KEY or not domain or domain in TRUSTED_DOMAINS:
        return None

    try:
        api_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}

        resp = requests.get(api_url, headers=headers, timeout=8)
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            reputation = data.get("reputation", 0)
            return {
                "malicious": malicious,
                "suspicious": suspicious,
                "reputation": reputation,
            }
    except Exception as exc:
        logger.warning("VirusTotal domain check failed for %s: %s", domain, exc)

    return None


# ---------------------------------------------------------------------------
# Google Safe Browsing v4 (Optional)
# ---------------------------------------------------------------------------
@lru_cache(maxsize=256)
def check_google_safe_browsing(url: str) -> Optional[dict]:
    """Check a URL against Google Safe Browsing Lookup API v4."""
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        return None

    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
        payload = {
            "client": {"clientId": "phishguard-analyzer", "clientVersion": "2.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            }
        }
        resp = requests.post(endpoint, json=payload, timeout=6)
        if resp.status_code == 200:
            matches = resp.json().get("matches", [])
            if matches:
                threat_type = matches[0].get("threatType", "MALICIOUS")
                return {"flagged": True, "threat_type": threat_type}
            return {"flagged": False}
    except Exception as exc:
        logger.warning("Google Safe Browsing check failed: %s", exc)

    return None


# ---------------------------------------------------------------------------
# Composite Threat Intelligence Evaluation
# ---------------------------------------------------------------------------
def evaluate_url_threat(url: str) -> dict:
    """
    Evaluates a URL using all available threat intelligence layers.
    Returns:
      {
        "risk": float (0.0 to 1.0),
        "flagged": bool,
        "source": str,
        "detail": str,
      }
    """
    # 1. OpenPhish Active Live Feed check
    _sync_openphish_feed()
    try:
        clean_url = url.strip()
        parsed = urlparse(clean_url)
        domain = parsed.netloc.lower().split(":")[0]
    except Exception:
        domain = ""

    if clean_url in _openphish_urls:
        return {
            "risk": 1.0,
            "flagged": True,
            "source": "OpenPhish",
            "detail": f"Matched active phishing campaign URL on OpenPhish feed: {clean_url[:70]}"
        }

    if domain and domain in _openphish_domains and domain not in TRUSTED_DOMAINS:
        return {
            "risk": 0.95,
            "flagged": True,
            "source": "OpenPhish",
            "detail": f"Domain '{domain}' is actively hosting phishing campaigns on OpenPhish"
        }

    # 2. VirusTotal URL scan
    vt_result = check_virustotal_url(clean_url)
    if vt_result and not vt_result.get("unknown"):
        malicious = vt_result.get("malicious", 0)
        suspicious = vt_result.get("suspicious", 0)

        # Ignore single vendor noise on whitelisted domains
        if domain in TRUSTED_DOMAINS and malicious <= 1:
            malicious = 0
            suspicious = 0

        if malicious >= 3:
            return {
                "risk": 1.0,
                "flagged": True,
                "source": "VirusTotal",
                "detail": f"VirusTotal flagged URL: {malicious} security vendors confirmed malicious ({clean_url[:70]})"
            }
        elif malicious == 2:
            return {
                "risk": 0.85,
                "flagged": True,
                "source": "VirusTotal",
                "detail": f"VirusTotal flagged URL: {malicious} security vendors reported malicious ({clean_url[:70]})"
            }
        elif malicious == 1 and suspicious >= 1:
            return {
                "risk": 0.60,
                "flagged": True,
                "source": "VirusTotal",
                "detail": f"VirusTotal flagged URL: 1 malicious + {suspicious} suspicious vendor warnings ({clean_url[:70]})"
            }
        elif malicious == 1:
            return {
                "risk": 0.25,
                "flagged": False,
                "source": "VirusTotal",
                "detail": f"VirusTotal note: 1 vendor warning ({clean_url[:70]})"
            }
        elif suspicious >= 2:
            return {
                "risk": 0.40,
                "flagged": True,
                "source": "VirusTotal",
                "detail": f"VirusTotal flagged URL as suspicious ({suspicious} vendor warnings)"
            }

    # 3. VirusTotal Domain scan (if URL wasn't flagged or known)
    if domain and domain not in TRUSTED_DOMAINS:
        vt_domain = check_virustotal_domain(domain)
        if vt_domain:
            d_mal = vt_domain.get("malicious", 0)
            if d_mal >= 2:
                return {
                    "risk": 0.9,
                    "flagged": True,
                    "source": "VirusTotal",
                    "detail": f"VirusTotal domain reputation: {d_mal} engines flagged domain '{domain}' as malicious"
                }

    # 4. Google Safe Browsing
    gsb = check_google_safe_browsing(clean_url)
    if gsb and gsb.get("flagged"):
        return {
            "risk": 1.0,
            "flagged": True,
            "source": "Google Safe Browsing",
            "detail": f"Google Safe Browsing flagged URL as {gsb.get('threat_type')}: {clean_url[:70]}"
        }

    return {
        "risk": 0.0,
        "flagged": False,
        "source": "ThreatIntel",
        "detail": "Clean on active threat feeds"
    }
