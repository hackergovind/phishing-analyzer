"""
Advanced email preprocessing — extracts rich features from raw email bytes.

Features extracted:
- Headers: SPF, DKIM, DMARC, Reply-To mismatch, Received hop count
- Body: plain text + HTML-stripped text, hidden/mismatched links
- URLs: all extracted links
- Attachments: filenames and suspicious extension flags
- Sender: display name, actual email address, domain, spoofing indicators
"""
import email
import re
from email import policy
from email.utils import parseaddr
from urllib.parse import urlparse
from html import unescape

from bs4 import BeautifulSoup

from src.config import SUSPICIOUS_EXTENSIONS


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_email(raw_email_bytes: bytes) -> dict:
    """Parses raw email bytes and extracts a comprehensive feature dictionary."""
    msg = email.message_from_bytes(raw_email_bytes, policy=policy.default)
    
    headers = _extract_headers(msg)
    body_plain, body_html = _extract_body(msg)
    body_text = body_plain or _html_to_text(body_html)
    urls = _extract_urls(body_plain, body_html)
    mismatched_links = _detect_mismatched_links(body_html)
    attachments = _extract_attachments(msg)
    sender_info = _analyze_sender(headers)
    
    return {
        "headers": headers,
        "body": body_text,
        "body_html": body_html,
        "urls": urls,
        "mismatched_links": mismatched_links,
        "attachments": attachments,
        "sender": sender_info,
    }


def parse_raw_text(text: str) -> dict:
    """Lightweight parser for raw text input (detects headers if pasted)."""
    urls = re.findall(r'(https?://[^\s<>"\']+)', text)
    headers = _empty_headers()
    sender_info = {
        "display_name": "",
        "email": "",
        "domain": "",
        "display_name_has_email": False,
        "reply_to_mismatch": False,
    }

    # Detect if user pasted email headers (From:, Subject:)
    subject_match = re.search(r'^(?:subject|re|fw|fwd):\s*(.+)$', text, re.I | re.M)
    if subject_match:
        headers["subject"] = subject_match.group(1).strip()

    from_match = re.search(r'^from:\s*(.+)$', text, re.I | re.M)
    if from_match:
        from_str = from_match.group(1).strip()
        headers["from"] = from_str
        d_name, e_addr = parseaddr(from_str)
        dom = e_addr.split("@")[-1].lower() if "@" in e_addr else ""
        sender_info["display_name"] = d_name
        sender_info["email"] = e_addr
        sender_info["domain"] = dom
        sender_info["display_name_has_email"] = bool(re.search(r'[\w.-]+@[\w.-]+', d_name))

    return {
        "headers": headers,
        "body": text,
        "body_html": "",
        "urls": urls,
        "mismatched_links": [],
        "attachments": [],
        "sender": sender_info,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _empty_headers() -> dict:
    return {
        "subject": "",
        "from": "",
        "to": "",
        "reply_to": "",
        "spf": "None",
        "dkim": "None",
        "dmarc": "None",
        "received_hops": 0,
    }


def _extract_headers(msg) -> dict:
    """Extract authentication and routing headers."""
    received_headers = msg.get_all("Received") or []
    
    auth_results = str(msg.get("Authentication-Results", ""))
    dmarc_status = "None"
    if "dmarc=pass" in auth_results.lower():
        dmarc_status = "pass"
    elif "dmarc=fail" in auth_results.lower():
        dmarc_status = "fail"
    
    return {
        "subject": str(msg.get("Subject", "")),
        "from": str(msg.get("From", "")),
        "to": str(msg.get("To", "")),
        "reply_to": str(msg.get("Reply-To", "")),
        "spf": str(msg.get("Received-SPF", "None")),
        "dkim": str(msg.get("DKIM-Signature", "None")),
        "dmarc": dmarc_status,
        "received_hops": len(received_headers),
    }


def _extract_body(msg) -> tuple[str, str]:
    """Return (plain_text, html_text) from the email."""
    plain = ""
    html = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            decoded = payload.decode(errors="ignore")
            if ct == "text/plain":
                plain += decoded
            elif ct == "text/html":
                html += decoded
    else:
        payload = msg.get_payload(decode=True)
        if isinstance(payload, bytes):
            text = payload.decode(errors="ignore")
        else:
            text = str(payload) if payload else ""
        ct = msg.get_content_type()
        if ct == "text/html":
            html = text
        else:
            plain = text
    return plain, html


def _html_to_text(html: str) -> str:
    """Strip HTML to plain text using BeautifulSoup."""
    if not html:
        return ""
    soup = BeautifulSoup(html, "html.parser")
    return unescape(soup.get_text(separator=" ", strip=True))


def _extract_urls(plain: str, html: str) -> list[str]:
    """Extract all URLs from both plain text and HTML href attributes."""
    urls: set[str] = set()
    
    # From plain text
    urls.update(re.findall(r'(https?://[^\s<>"\']+)', plain))
    
    # From HTML href attributes
    if html:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            if href.startswith("http"):
                urls.add(href)
    
    return list(urls)


def _detect_mismatched_links(html: str) -> list[dict]:
    """
    Detect links where the displayed text looks like a URL/domain 
    but points to a completely different domain. This is a strong
    phishing indicator (e.g. text says 'paypal.com' but links to 'evil.com').
    """
    mismatched: list[dict] = []
    if not html:
        return mismatched
    
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.find_all("a", href=True):
        href = tag["href"]
        display = tag.get_text(strip=True)
        
        # Only check if the display text looks like a URL or domain
        if not re.match(r'https?://|www\.|[a-z0-9-]+\.[a-z]{2,}', display, re.I):
            continue
        
        try:
            href_domain = urlparse(href).netloc.lower().lstrip("www.")
            # Extract domain from display text
            if display.startswith(("http://", "https://")):
                display_domain = urlparse(display).netloc.lower().lstrip("www.")
            else:
                display_domain = display.lower().split("/")[0].lstrip("www.")
            
            if href_domain and display_domain and href_domain != display_domain:
                mismatched.append({
                    "displayed": display,
                    "actual_href": href,
                    "displayed_domain": display_domain,
                    "actual_domain": href_domain,
                })
        except Exception:
            continue
    
    return mismatched


def _extract_attachments(msg) -> list[dict]:
    """Extract attachment metadata and flag suspicious extensions."""
    attachments: list[dict] = []
    if not msg.is_multipart():
        return attachments
    
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            attachments.append({
                "filename": filename,
                "extension": ext,
                "is_suspicious": ext in SUSPICIOUS_EXTENSIONS,
                "content_type": part.get_content_type(),
            })
    return attachments


def _analyze_sender(headers: dict) -> dict:
    """Analyze the sender for spoofing indicators."""
    display_name, email_addr = parseaddr(headers["from"])
    domain = email_addr.split("@")[-1].lower() if "@" in email_addr else ""
    
    # Check if display name contains a different email (spoofing trick)
    display_name_has_email = bool(re.search(r'[\w.-]+@[\w.-]+', display_name))
    
    # Reply-To mismatch
    reply_to = headers.get("reply_to", "")
    reply_to_mismatch = False
    if reply_to:
        _, reply_email = parseaddr(reply_to)
        reply_domain = reply_email.split("@")[-1].lower() if "@" in reply_email else ""
        if reply_domain and reply_domain != domain:
            reply_to_mismatch = True
    
    return {
        "display_name": display_name,
        "email": email_addr,
        "domain": domain,
        "display_name_has_email": display_name_has_email,
        "reply_to_mismatch": reply_to_mismatch,
    }
