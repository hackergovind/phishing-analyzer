"""
Multi-signal analysis engine.

Fuses outputs from:
  1. Ensemble ML model (calibrated probabilities)
  2. Heuristics engine (urgency, social engineering, URL risk, etc.)
  3. Header authentication checks (SPF / DKIM / DMARC)
  4. URL scanning (VirusTotal or heuristic-only fallback)

Outputs a threat score, a confidence level, and a detailed evidence trail.

Anti-false-positive design:
  - Trusted-domain whitelist with auth verification gives a trust *boost*.
  - Confidence-aware verdicts: low-confidence high-threat = "Suspicious" not "Phishing".
  - No single weak signal can push past the phishing threshold alone.
"""
import hashlib
import base64
import logging
import os
from functools import lru_cache
from urllib.parse import urlparse

import requests

from src.config import (
    VIRUSTOTAL_API_KEY,
    TRUSTED_DOMAINS,
    WEIGHT_ML_SCORE,
    WEIGHT_HEURISTIC_SCORE,
    WEIGHT_HEADER_AUTH,
    WEIGHT_URL_RISK,
    WHITELIST_TRUST_OFFSET,
    THRESHOLD_SUSPICIOUS,
    THRESHOLD_PHISHING,
    CONFIDENCE_FLOOR_FOR_PHISHING,
)
from src.heuristics import run_heuristics, HeuristicResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class AnalysisVerdict:
    """Full analysis output."""
    def __init__(self):
        self.threat_score: float = 0.0
        self.confidence: float = 0.0
        self.status: str = "Safe"
        self.action: str = "DELIVERED"
        self.evidence: list[dict] = []
        self.breakdown: dict = {}

    def to_dict(self) -> dict:
        return {
            "threat_score": round(self.threat_score, 1),
            "confidence": round(self.confidence, 2),
            "status": self.status,
            "action": self.action,
            "evidence": self.evidence,
            "breakdown": {k: round(v, 2) for k, v in self.breakdown.items()},
        }


def analyze(parsed_data: dict, ml_model=None) -> AnalysisVerdict:
    """Run the full multi-signal analysis pipeline."""
    verdict = AnalysisVerdict()

    # --- 1. ML Score ---
    ml_contrib, ml_confidence = _score_ml(parsed_data, ml_model, verdict)

    # --- 2. Heuristics ---
    heur_contrib, heur_confidence = _score_heuristics(parsed_data, verdict)

    # --- 3. Header Authentication ---
    header_contrib = _score_headers(parsed_data, verdict)

    # --- 4. URL Risk ---
    url_contrib = _score_urls(parsed_data, verdict)

    # --- 5. Whitelist trust boost ---
    whitelist_offset = _apply_whitelist(parsed_data, verdict)

    # --- Combine ---
    raw_score = ml_contrib + heur_contrib + header_contrib + url_contrib + whitelist_offset
    verdict.threat_score = max(0.0, min(raw_score, 100.0))

    # Overall confidence = weighted average of ML and heuristic confidences
    if ml_confidence >= 0 and heur_confidence >= 0:
        verdict.confidence = 0.5 * ml_confidence + 0.5 * heur_confidence
    elif ml_confidence >= 0:
        verdict.confidence = ml_confidence
    else:
        verdict.confidence = heur_confidence

    verdict.breakdown = {
        "ml_score": ml_contrib,
        "heuristic_score": heur_contrib,
        "header_auth": header_contrib,
        "url_risk": url_contrib,
        "whitelist_offset": whitelist_offset,
    }

    # --- Verdict & action ---
    _determine_verdict(verdict)

    return verdict


# ---------------------------------------------------------------------------
# Signal scorers
# ---------------------------------------------------------------------------

def _score_ml(parsed_data: dict, ml_model, verdict: AnalysisVerdict) -> tuple[float, float]:
    """Score from the ML ensemble model."""
    body = parsed_data.get("body", "")
    if not body or ml_model is None:
        return 0.0, -1.0  # -1 = not available

    url_count = len(parsed_data.get("urls", []))
    has_attachment = 1 if parsed_data.get("attachments") else 0

    # Quick urgency estimate for the ML metadata feature
    urgency = 0.0
    urgency_words = ["urgent", "immediately", "suspended", "verify", "act now"]
    body_lower = body.lower()
    for w in urgency_words:
        if w in body_lower:
            urgency += 0.2
    urgency = min(urgency, 1.0)

    probs = ml_model.predict_proba(body, url_count, has_attachment, urgency)
    phishing_prob = probs[1]

    contrib = phishing_prob * WEIGHT_ML_SCORE

    verdict.evidence.append({
        "source": "ML Ensemble",
        "detail": f"Phishing probability: {phishing_prob:.2%}",
        "contribution": round(contrib, 1),
    })

    return contrib, phishing_prob  # probability doubles as confidence


def _score_heuristics(parsed_data: dict, verdict: AnalysisVerdict) -> tuple[float, float]:
    """Score from the rule-based heuristics engine."""
    result: HeuristicResult = run_heuristics(parsed_data)

    contrib = result.score * WEIGHT_HEURISTIC_SCORE

    if result.signals:
        # Report top 5 most impactful signals
        top = sorted(result.signals, key=lambda s: s["weight"], reverse=True)[:5]
        for sig in top:
            verdict.evidence.append({
                "source": f"Heuristic: {sig['name']}",
                "detail": sig["detail"],
                "contribution": round(sig["weight"] * WEIGHT_HEURISTIC_SCORE, 1),
            })

    return contrib, result.confidence


def _score_headers(parsed_data: dict, verdict: AnalysisVerdict) -> float:
    """Score based on email authentication header status."""
    headers = parsed_data.get("headers", {})
    penalty = 0.0

    spf = headers.get("spf", "None").lower()
    dkim = headers.get("dkim", "None").lower()
    dmarc = headers.get("dmarc", "None").lower()

    # SPF
    if "fail" in spf and "softfail" not in spf:
        penalty += 0.4
        verdict.evidence.append({"source": "Header: SPF", "detail": "SPF hard fail", "contribution": round(0.4 * WEIGHT_HEADER_AUTH, 1)})
    elif "softfail" in spf:
        penalty += 0.2
        verdict.evidence.append({"source": "Header: SPF", "detail": "SPF soft fail", "contribution": round(0.2 * WEIGHT_HEADER_AUTH, 1)})
    elif spf in ("none", "") or "pass" not in spf:
        penalty += 0.15
        verdict.evidence.append({"source": "Header: SPF", "detail": "SPF missing or inconclusive", "contribution": round(0.15 * WEIGHT_HEADER_AUTH, 1)})

    # DKIM
    if dkim in ("none", ""):
        penalty += 0.2
        verdict.evidence.append({"source": "Header: DKIM", "detail": "No DKIM signature", "contribution": round(0.2 * WEIGHT_HEADER_AUTH, 1)})

    # DMARC
    if dmarc == "fail":
        penalty += 0.3
        verdict.evidence.append({"source": "Header: DMARC", "detail": "DMARC failed", "contribution": round(0.3 * WEIGHT_HEADER_AUTH, 1)})
    elif dmarc in ("none", ""):
        penalty += 0.1

    # Sender anomalies from preprocessing
    sender = parsed_data.get("sender", {})
    if sender.get("reply_to_mismatch"):
        penalty += 0.15
    if sender.get("display_name_has_email"):
        penalty += 0.15

    return min(penalty, 1.0) * WEIGHT_HEADER_AUTH


def _score_urls(parsed_data: dict, verdict: AnalysisVerdict) -> float:
    """Score URLs via VirusTotal (if API key set) or heuristic-only fallback."""
    urls = parsed_data.get("urls", [])
    if not urls:
        return 0.0

    max_risk = 0.0
    for url in urls[:5]:  # Cap at 5 URLs to avoid API abuse
        risk = _check_single_url(url)
        if risk > max_risk:
            max_risk = risk
        if risk > 0.3:
            verdict.evidence.append({
                "source": "URL Scan",
                "detail": f"Risk {risk:.0%} for {url[:80]}",
                "contribution": round(risk * WEIGHT_URL_RISK, 1),
            })

    return max_risk * WEIGHT_URL_RISK


# ---------------------------------------------------------------------------
# URL scanning
# ---------------------------------------------------------------------------

@lru_cache(maxsize=256)
def _check_single_url(url: str) -> float:
    """
    Check a URL against VirusTotal if API key is configured.
    Falls back to heuristic-only scoring otherwise.
    Returns 0.0 – 1.0 risk score.
    """
    if VIRUSTOTAL_API_KEY:
        try:
            return _virustotal_scan(url)
        except Exception as exc:
            logger.warning("VirusTotal lookup failed for %s: %s", url[:60], exc)
    # Fallback: basic heuristic risk
    return _heuristic_url_risk(url)


def _virustotal_scan(url: str) -> float:
    """Query the VirusTotal v3 URL report API."""
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    resp = requests.get(api_url, headers=headers, timeout=10)
    if resp.status_code == 404:
        # URL not in VT database — submit it
        submit_resp = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=10,
        )
        if submit_resp.status_code == 200:
            logger.info("Submitted URL to VirusTotal: %s", url[:60])
        return 0.1  # Unknown — slightly elevated but not alarming

    if resp.status_code != 200:
        return 0.0

    data = resp.json().get("data", {}).get("attributes", {})
    stats = data.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) if stats else 1

    return (malicious + 0.5 * suspicious) / max(total, 1)


def _heuristic_url_risk(url: str) -> float:
    """Simple heuristic risk when VirusTotal is unavailable."""
    import re
    risk = 0.0
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()
    except Exception:
        return 0.0

    # IP-based
    if re.match(r"\d{1,3}(\.\d{1,3}){3}", netloc):
        risk += 0.3

    # Risky TLDs
    from src.config import RISKY_TLDS, URL_SHORTENERS
    for tld in RISKY_TLDS:
        if netloc.endswith(tld):
            risk += 0.2
            break

    bare = netloc.lstrip("www.")
    if bare in URL_SHORTENERS:
        risk += 0.15

    if netloc.count(".") > 3:
        risk += 0.15

    return min(risk, 1.0)


# ---------------------------------------------------------------------------
# Whitelist trust boost
# ---------------------------------------------------------------------------

def _apply_whitelist(parsed_data: dict, verdict: AnalysisVerdict) -> float:
    """
    If the sender domain is whitelisted AND email passes SPF/DKIM,
    apply a negative offset to reduce the threat score (less false positives
    for legitimate corporate / newsletter mail).
    """
    sender = parsed_data.get("sender", {})
    domain = sender.get("domain", "")
    headers = parsed_data.get("headers", {})
    spf_ok = "pass" in headers.get("spf", "").lower()
    dkim_present = headers.get("dkim", "None").lower() not in ("none", "")

    if domain in TRUSTED_DOMAINS and (spf_ok or dkim_present):
        verdict.evidence.append({
            "source": "Whitelist",
            "detail": f"Authenticated sender from trusted domain: {domain}",
            "contribution": WHITELIST_TRUST_OFFSET,
        })
        return WHITELIST_TRUST_OFFSET

    return 0.0


# ---------------------------------------------------------------------------
# Final verdict
# ---------------------------------------------------------------------------

def _determine_verdict(verdict: AnalysisVerdict):
    """Map threat score + confidence to a status and action."""
    score = verdict.threat_score
    conf = verdict.confidence

    if score >= THRESHOLD_PHISHING:
        # Confidence gate: downgrade if we're not sure enough
        if conf < CONFIDENCE_FLOOR_FOR_PHISHING:
            verdict.status = "Suspicious"
            verdict.action = "FLAGGED — Delivered with warning banner (low confidence for quarantine)."
            verdict.evidence.append({
                "source": "Confidence Gate",
                "detail": f"Score {score:.0f} exceeds phishing threshold but confidence ({conf:.0%}) is below {CONFIDENCE_FLOOR_FOR_PHISHING:.0%}",
                "contribution": 0,
            })
        else:
            verdict.status = "Phishing"
            verdict.action = "QUARANTINED — Blocked from user inbox."
    elif score >= THRESHOLD_SUSPICIOUS:
        verdict.status = "Suspicious"
        verdict.action = "FLAGGED — Delivered with warning banner."
    else:
        verdict.status = "Safe"
        verdict.action = "DELIVERED"
