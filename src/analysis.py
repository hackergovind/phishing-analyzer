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

    # Check origin IP if present in headers
    client_ip = headers.get("client_ip")
    if client_ip:
        from src.threat_intel import check_abuseipdb_ip
        ip_res = check_abuseipdb_ip(client_ip)
        if ip_res and ip_res.get("score", 0) >= 50:
            penalty += 0.3
            verdict.evidence.append({
                "source": "AbuseIPDB",
                "detail": f"Sender IP {client_ip} flagged with {ip_res['score']}% abuse confidence score",
                "contribution": round(0.3 * WEIGHT_HEADER_AUTH, 1)
            })

    return min(penalty, 1.0) * WEIGHT_HEADER_AUTH


def _score_urls(parsed_data: dict, verdict: AnalysisVerdict) -> float:
    """Score URLs and sender domains via VirusTotal, OpenPhish, and heuristic analysis."""
    from src.threat_intel import evaluate_url_threat

    urls = parsed_data.get("urls", [])
    max_risk = 0.0

    # 1. Inspect sender domain via threat intel
    sender = parsed_data.get("sender", {})
    sender_domain = sender.get("domain", "")
    if sender_domain and sender_domain not in TRUSTED_DOMAINS:
        sender_intel = evaluate_url_threat(f"http://{sender_domain}")
        if sender_intel.get("flagged"):
            verdict.evidence.append({
                "source": sender_intel["source"],
                "detail": f"Sender domain: {sender_intel['detail']}",
                "contribution": round(sender_intel["risk"] * WEIGHT_URL_RISK, 1),
            })
            max_risk = max(max_risk, sender_intel["risk"])

    # 2. Inspect embedded URLs
    for url in urls[:5]:  # Cap at 5 URLs
        intel = evaluate_url_threat(url)
        heur_risk = _heuristic_url_risk(url)
        combined_risk = max(intel.get("risk", 0.0), heur_risk)

        if combined_risk > max_risk:
            max_risk = combined_risk

        if intel.get("flagged"):
            verdict.evidence.append({
                "source": intel["source"],
                "detail": intel["detail"],
                "contribution": round(intel["risk"] * WEIGHT_URL_RISK, 1),
            })
        elif combined_risk > 0.3:
            verdict.evidence.append({
                "source": "URL Risk",
                "detail": f"Structural risk {combined_risk:.0%} for {url[:80]}",
                "contribution": round(combined_risk * WEIGHT_URL_RISK, 1),
            })

    return min(max_risk, 1.0) * WEIGHT_URL_RISK


# ---------------------------------------------------------------------------
# URL scanning
# ---------------------------------------------------------------------------

@lru_cache(maxsize=256)
def _check_single_url(url: str) -> float:
    """Check a URL against threat intelligence feeds with heuristic fallback."""
    from src.threat_intel import evaluate_url_threat
    intel = evaluate_url_threat(url)
    return max(intel.get("risk", 0.0), _heuristic_url_risk(url))



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
