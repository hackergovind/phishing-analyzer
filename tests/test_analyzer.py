"""
Automated Test Suite for PhishGuard AI
======================================
Tests:
  - Preprocessing (MIME, HTML, headers, URLs, attachments)
  - Heuristics engine (urgency, social engineering, URLs, lookalikes, caps)
  - Machine learning model (inference, calibration, persistence)
  - Multi-signal fusion & verdict gating
  - SQLite database persistence & aggregation
  - FastAPI endpoints (/health, /analyze, /analyze/text, /api/stats, /api/results)
"""
import os
import pytest
from fastapi.testclient import TestClient

from main import app, ml_model
from src.analysis import analyze, AnalysisVerdict
from src.database import init_db, save_result, get_results, get_stats
from src.heuristics import run_heuristics
from src.model import PhishingModel
from src.preprocessing import parse_email, parse_raw_text


@pytest.fixture(scope="session", autouse=True)
def setup_model_and_db():
    """Ensure model is loaded or trained and DB initialized before tests run."""
    if not ml_model.is_trained:
        if not ml_model.load():
            ml_model.train()


# ---------------------------------------------------------------------------
# 1. Preprocessing Tests
# ---------------------------------------------------------------------------
def test_parse_raw_text_basic():
    text = "Hello team, please see http://example.com/docs for our agenda."
    parsed = parse_raw_text(text)
    assert parsed["body"] == text
    assert len(parsed["urls"]) == 1
    assert parsed["urls"][0] == "http://example.com/docs"
    assert parsed["headers"]["subject"] == ""


def test_parse_raw_text_with_headers():
    text = """Subject: Urgent Security Notice
From: Alert System <security@service-updates.com>

Please verify your login at https://service-updates.com/verify
"""
    parsed = parse_raw_text(text)
    assert parsed["headers"]["subject"] == "Urgent Security Notice"
    assert parsed["sender"]["email"] == "security@service-updates.com"
    assert parsed["sender"]["domain"] == "service-updates.com"
    assert "https://service-updates.com/verify" in parsed["urls"]


def test_parse_email_eml_bytes():
    eml_content = (
        b"From: \"Support\" <support@bank-security.net>\r\n"
        b"To: victim@company.com\r\n"
        b"Subject: Action Required: Account Notice\r\n"
        b"Content-Type: text/html; charset=\"utf-8\"\r\n"
        b"\r\n"
        b"<html><body><p>Click <a href=\"http://evil.top/login\">paypal.com</a> to secure.</p></body></html>"
    )
    parsed = parse_email(eml_content)
    assert parsed["headers"]["subject"] == "Action Required: Account Notice"
    assert parsed["sender"]["email"] == "support@bank-security.net"
    assert "http://evil.top/login" in parsed["urls"]
    assert len(parsed["mismatched_links"]) == 1
    assert parsed["mismatched_links"][0]["displayed_domain"] == "paypal.com"
    assert parsed["mismatched_links"][0]["actual_domain"] == "evil.top"


# ---------------------------------------------------------------------------
# 2. Heuristics Engine Tests
# ---------------------------------------------------------------------------
def test_heuristics_urgency_and_social_engineering():
    data = {
        "body": "Your account will be suspended within 24 hours. Act now and update your payment information.",
        "headers": {"subject": "URGENT SECURITY ALERT"},
        "urls": [],
        "mismatched_links": [],
        "attachments": [],
        "sender": {},
    }
    result = run_heuristics(data)
    assert result.score > 0.3
    signals = [s["name"] for s in result.signals]
    assert any("urgency:phrase" in s for s in signals)
    assert any("urgency:cluster" in s for s in signals)


def test_heuristics_brand_impersonation_in_subdomain():
    data = {
        "body": "Please login to your account.",
        "headers": {"subject": "Account update"},
        "urls": ["http://paypal.com.attacker-domain.xyz/verify"],
        "mismatched_links": [],
        "attachments": [],
        "sender": {},
    }
    result = run_heuristics(data)
    signals = [s["name"] for s in result.signals]
    assert "url:brand_impersonation" in signals or "url:risky_tld" in signals


def test_heuristics_excessive_caps():
    # Capitalized body
    data = {
        "body": "ATTENTION USER YOUR ACCOUNT HAS BEEN TEMPORARILY DISABLED BY SYSTEM ADMINISTRATOR PLEASE RESPOND",
        "headers": {"subject": "CRITICAL EMERGENCY ALERT"},
        "urls": [],
        "mismatched_links": [],
        "attachments": [],
        "sender": {},
    }
    result = run_heuristics(data)
    signals = [s["name"] for s in result.signals]
    assert "structure:excessive_caps" in signals or "structure:excessive_subject_caps" in signals


# ---------------------------------------------------------------------------
# 3. ML Model Tests
# ---------------------------------------------------------------------------
def test_ml_model_predict_proba():
    model = PhishingModel()
    assert model.load() or ml_model.is_trained
    active_model = ml_model if ml_model.is_trained else model

    safe_probs = active_model.predict_proba("The team sync is moved to Friday 2pm.", url_count=0)
    phish_probs = active_model.predict_proba(
        "URGENT: Your account has been suspended! Verify your credit card immediately at http://evil.xyz",
        url_count=2,
        urgency_score=0.8,
    )

    assert len(safe_probs) == 2
    assert len(phish_probs) == 2
    assert phish_probs[1] > safe_probs[1]  # Phishing probability should be higher


# ---------------------------------------------------------------------------
# 4. Multi-Signal Fusion & Analysis Verdict Tests
# ---------------------------------------------------------------------------
def test_analyze_obvious_phishing():
    text = """Subject: URGENT: PayPal Account Suspended
From: service@paypa1.com.malicious.top

Dear Customer, We detected unauthorized access to your account.
Your account will be suspended within 24 hours unless you verify your information immediately.
Click here to secure your account: http://paypa1.com.malicious.top/secure/login
"""
    parsed = parse_raw_text(text)
    verdict = analyze(parsed, ml_model)
    data = verdict.to_dict()

    assert data["status"] in ("Phishing", "Suspicious")
    assert data["threat_score"] >= 60.0
    assert len(data["evidence"]) > 0


def test_analyze_safe_email():
    text = """Subject: Thursday Lunch and Learn Notes
From: coworker@company.com

Hi everyone,
Attached are the notes from our discussion on Monday. Let me know if you have any questions.
Thanks!
"""
    parsed = parse_raw_text(text)
    verdict = analyze(parsed, ml_model)
    data = verdict.to_dict()

    assert data["status"] == "Safe"
    assert data["threat_score"] < 35.0


# ---------------------------------------------------------------------------
# 5. Database CRUD Tests
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_database_operations():
    await init_db()
    row_id = await save_result(
        sender="test@example.com",
        subject="Test Run",
        status="Suspicious",
        threat_score=48.5,
        confidence=0.75,
        action="FLAGGED",
        evidence=[{"source": "test", "detail": "test alert", "contribution": 10.0}],
        breakdown={"ml_score": 20.0, "heuristic_score": 28.5},
        body_preview="Test body preview",
        source="unit_test",
    )
    assert row_id > 0

    results = await get_results(limit=5)
    assert len(results) > 0
    assert any(r["id"] == row_id for r in results)

    stats = await get_stats()
    assert stats["total"] > 0
    assert "suspicious" in stats


# ---------------------------------------------------------------------------
# 6. FastAPI Endpoints Tests
# ---------------------------------------------------------------------------
def test_api_health():
    with TestClient(app) as client:
        res = client.get("/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert data["model_trained"] is True


def test_api_analyze_text():
    with TestClient(app) as client:
        res = client.post("/analyze/text", data={"text": "URGENT: Verify your account now at http://bad.xyz"})
        assert res.status_code == 200
        data = res.json()
        assert "threat_score" in data
        assert "status" in data
        assert "evidence" in data


def test_api_analyze_eml():
    with TestClient(app) as client:
        eml_bytes = b"Subject: Test\r\nFrom: test@example.com\r\n\r\nMeeting at 10am."
        res = client.post(
            "/analyze",
            files={"file": ("test.eml", eml_bytes, "message/rfc822")},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "Safe"


def test_api_stats_and_results():
    with TestClient(app) as client:
        res_stats = client.get("/api/stats")
        assert res_stats.status_code == 200
        assert "total" in res_stats.json()

        res_results = client.get("/api/results?limit=10")
        assert res_results.status_code == 200
        assert isinstance(res_results.json(), list)
