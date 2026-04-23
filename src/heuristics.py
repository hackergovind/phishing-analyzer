"""
Heuristic analysis engine for phishing detection.

Returns granular, confidence-weighted signals rather than binary flags.
Individual weak signals contribute minimal risk; only a *cluster* of
corroborating signals significantly elevates the threat score.
"""
import re
from urllib.parse import urlparse

from src.config import (
    URGENCY_PHRASES,
    SOCIAL_ENGINEERING_PHRASES,
    RISKY_TLDS,
    URL_SHORTENERS,
    SUSPICIOUS_EXTENSIONS,
)

try:
    from Levenshtein import distance as levenshtein_distance
except ImportError:
    # Fallback if python-Levenshtein is not installed
    def levenshtein_distance(s1: str, s2: str) -> int:  # type: ignore[misc]
        if len(s1) < len(s2):
            return levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        return prev_row[-1]


# Well-known domains against which we check for lookalikes
_IMPERSONATION_TARGETS: list[str] = [
    "paypal.com", "apple.com", "microsoft.com", "google.com",
    "amazon.com", "netflix.com", "facebook.com", "instagram.com",
    "bankofamerica.com", "chase.com", "wellsfargo.com", "citibank.com",
    "dropbox.com", "linkedin.com", "github.com", "twitter.com",
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class HeuristicResult:
    """Bundled result from the heuristics engine."""
    __slots__ = ("score", "confidence", "signals")

    def __init__(self):
        self.score: float = 0.0       # 0.0 – 1.0 (normalized)
        self.confidence: float = 0.0  # 0.0 – 1.0
        self.signals: list[dict] = []

    def add(self, name: str, weight: float, detail: str = ""):
        self.signals.append({
            "name": name,
            "weight": weight,
            "detail": detail,
        })

    def finalize(self):
        """Compute final score and confidence from accumulated signals."""
        if not self.signals:
            self.score = 0.0
            self.confidence = 0.0
            return
        raw = sum(s["weight"] for s in self.signals)
        # Bounded sum allows combined confident signals to reflect true risk
        self.score = min(raw, 1.0)
        # Confidence rises with the number of independent signal categories
        categories = len({s["name"].split(":")[0] for s in self.signals})
        self.confidence = min(categories / 5.0, 1.0)  # 5 categories = full confidence


def run_heuristics(parsed_data: dict) -> HeuristicResult:
    """Run all heuristic checks and return a combined result."""
    result = HeuristicResult()

    body = parsed_data.get("body", "").lower()
    urls = parsed_data.get("urls", [])
    mismatched = parsed_data.get("mismatched_links", [])
    attachments = parsed_data.get("attachments", [])
    sender = parsed_data.get("sender", {})
    headers = parsed_data.get("headers", {})

    _check_urgency(body, result)
    _check_social_engineering(body, result)
    _check_url_risk(urls, result)
    _check_mismatched_links(mismatched, result)
    _check_attachments(attachments, result)
    _check_sender_anomalies(sender, headers, result)
    _check_structural_anomalies(headers, body, result)

    result.finalize()
    return result


# ---------------------------------------------------------------------------
# Individual heuristic checkers
# ---------------------------------------------------------------------------

def _check_urgency(body: str, result: HeuristicResult):
    """Score urgency / pressure language. Individual phrases add small amounts."""
    matched_count = 0
    for phrase, weight in URGENCY_PHRASES.items():
        if phrase in body:
            matched_count += 1
            result.add("urgency:phrase", weight, f'Found: "{phrase}"')
    
    # If 3+ urgency phrases co-occur, add a compounding bonus
    if matched_count >= 3:
        result.add("urgency:cluster", 0.15, f"{matched_count} urgency phrases detected (cluster bonus)")


def _check_social_engineering(body: str, result: HeuristicResult):
    """Score social engineering / manipulation patterns."""
    for phrase, weight in SOCIAL_ENGINEERING_PHRASES.items():
        if phrase in body:
            result.add("social_engineering:phrase", weight, f'Found: "{phrase}"')


def _check_url_risk(urls: list[str], result: HeuristicResult):
    """Analyze extracted URLs for structural risk indicators."""
    for url in urls:
        try:
            parsed = urlparse(url)
            netloc = parsed.netloc.lower()
            path = parsed.path + (parsed.query or "")
        except Exception:
            continue

        # IP-based URL (e.g., http://192.168.1.1/login)
        if re.match(r'\d{1,3}(\.\d{1,3}){3}', netloc):
            result.add("url:ip_address", 0.25, f"IP-based URL: {url[:80]}")

        # URL shortener
        bare_domain = netloc.lstrip("www.")
        if bare_domain in URL_SHORTENERS:
            result.add("url:shortener", 0.10, f"URL shortener: {bare_domain}")

        # Risky TLD
        for tld in RISKY_TLDS:
            if netloc.endswith(tld):
                result.add("url:risky_tld", 0.12, f"Risky TLD ({tld}): {netloc}")
                break

        # Excessive subdomains (more than 3 dots in netloc)
        if netloc.count(".") > 3:
            result.add("url:excessive_subdomains", 0.15, f"Excessive subdomains: {netloc}")

        # Lookalike domain check against known brands
        _check_lookalike_domain(netloc, result)

        # Suspicious path keywords
        suspicious_path_words = ["login", "verify", "secure", "update", "confirm", "account", "signin", "banking"]
        for word in suspicious_path_words:
            if word in path.lower():
                result.add("url:suspicious_path", 0.06, f'Path contains "{word}": {url[:80]}')
                break  # One hit per URL is enough


def _check_lookalike_domain(netloc: str, result: HeuristicResult):
    """Detect domains that are very close to well-known brands (typosquatting)."""
    # Extract the registrable part (e.g., "paypa1" from "paypa1.com")
    parts = netloc.split(".")
    if len(parts) < 2:
        return
    candidate = parts[-2]  # The main domain name without TLD

    sub_candidates = candidate.split("-")

    for target in _IMPERSONATION_TARGETS:
        target_name = target.split(".")[0]
        if candidate == target_name:
            continue  # exact match = legitimate
            
        # Only flag if edit distance is 1 or 2 (close typosquat)
        dist = levenshtein_distance(candidate, target_name)
        if 0 < dist <= 2 and len(candidate) >= 4:
            result.add(
                "url:lookalike_domain",
                0.30,
                f'"{netloc}" looks like "{target}" (edit distance {dist})'
            )
            return  # One match is enough
            
        # Check sub-candidates (e.g. 'dr0pbox-secure' -> 'dr0pbox', 'secure')
        for sub in sub_candidates:
            if sub == target_name:
                result.add(
                    "url:lookalike_domain",
                    0.35,
                    f'"{netloc}" contains target brand "{target}"'
                )
                return
            dist_sub = levenshtein_distance(sub, target_name)
            if 0 < dist_sub <= 2 and len(sub) >= 4:
                result.add(
                    "url:lookalike_domain",
                    0.30,
                    f'"{netloc}" looks like "{target}" (edit distance {dist_sub})'
                )
                return


def _check_mismatched_links(mismatched: list[dict], result: HeuristicResult):
    """Score hidden/mismatched links (display text ≠ actual href domain)."""
    for m in mismatched:
        result.add(
            "link:mismatch",
            0.35,
            f'Display: "{m["displayed_domain"]}" → Actual: "{m["actual_domain"]}"'
        )


def _check_attachments(attachments: list[dict], result: HeuristicResult):
    """Flag suspicious attachment types."""
    for att in attachments:
        if att.get("is_suspicious"):
            result.add(
                "attachment:suspicious",
                0.25,
                f'Suspicious attachment: {att["filename"]} ({att["extension"]})'
            )


def _check_sender_anomalies(sender: dict, headers: dict, result: HeuristicResult):
    """Check for sender spoofing tricks."""
    if sender.get("display_name_has_email"):
        result.add(
            "sender:display_name_email",
            0.20,
            "Display name contains an email address (common spoofing trick)"
        )

    if sender.get("reply_to_mismatch"):
        result.add(
            "sender:reply_to_mismatch",
            0.18,
            f'Reply-To domain differs from From domain'
        )


def _check_structural_anomalies(headers: dict, body: str, result: HeuristicResult):
    """Check for structural email anomalies."""
    subject = headers.get("subject", "")

    # Empty or missing subject
    if not subject.strip():
        result.add("structure:no_subject", 0.08, "Email has no subject line")

    # Subject line contains "Re:" or "Fwd:" but email is not a reply/forward
    # (simplistic check — real systems inspect In-Reply-To header)

    # Extremely short body with URLs (classic phishing pattern)
    word_count = len(body.split())
    url_count = len(re.findall(r'https?://', body))
    if word_count < 30 and url_count >= 1:
        result.add(
            "structure:short_body_with_urls",
            0.12,
            f"Very short body ({word_count} words) with {url_count} URL(s)"
        )

    # Check for excessive capitalization (shouting)
    if body and len(body) > 50:
        upper_ratio = sum(1 for c in body if c.isupper()) / max(len(body), 1)
        if upper_ratio > 0.40:
            result.add(
                "structure:excessive_caps",
                0.10,
                f"Excessive capitalization ({upper_ratio:.0%} uppercase)"
            )
