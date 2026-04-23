"""
PhishGuard AI — FastAPI Application
====================================

Serves the dashboard UI and provides API endpoints for:
  - Manual email analysis (EML file or raw text)
  - Background IMAP mail scanning
  - Scan history and statistics
  - Model retraining
"""
import logging
from contextlib import asynccontextmanager
from typing import Optional

import uvicorn
from fastapi import FastAPI, File, Form, UploadFile, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from src.analysis import analyze, AnalysisVerdict
from src.database import init_db, save_result, get_results, get_stats
from src.mail_scanner import MailScanner
from src.model import PhishingModel
from src.preprocessing import parse_email, parse_raw_text

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Global instances
# ---------------------------------------------------------------------------
ml_model = PhishingModel()
scanner = MailScanner()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """On startup: init DB, load or train model, wire scanner."""
    await init_db()
    if not ml_model.load():
        logger.info("No saved model found — training on synthetic dataset …")
        ml_model.train()
    scanner.ml_model = ml_model
    yield
    # Shutdown: stop scanner if running
    if scanner.is_running:
        await scanner.stop()


# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = FastAPI(
    title="PhishGuard AI",
    description="AI-powered phishing email analysis and detection system with real-time mail scanning.",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")


# ---------------------------------------------------------------------------
# Response Models
# ---------------------------------------------------------------------------
class EvidenceItem(BaseModel):
    source: str
    detail: str
    contribution: float


class ScoreBreakdown(BaseModel):
    ml_score: float
    heuristic_score: float
    header_auth: float
    url_risk: float
    whitelist_offset: float


class AnalysisResponse(BaseModel):
    status: str
    action: str
    threat_score: float
    confidence: float
    breakdown: ScoreBreakdown
    evidence: list[EvidenceItem]


class HealthResponse(BaseModel):
    status: str
    model_trained: bool
    version: str


class TrainResponse(BaseModel):
    status: str
    report: str


class MailConnectRequest(BaseModel):
    imap_host: str = "imap.gmail.com"
    imap_port: int = 993
    email: str = ""
    password: str = ""
    folder: str = "INBOX"
    poll_interval: int = 30


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@app.get("/", include_in_schema=False)
async def serve_dashboard():
    """Serve the main dashboard HTML."""
    return FileResponse("static/index.html")


# ---------------------------------------------------------------------------
# Analysis Endpoints
# ---------------------------------------------------------------------------
@app.post("/analyze", response_model=AnalysisResponse, summary="Analyze an EML file")
async def analyze_eml(file: UploadFile = File(...)):
    """Upload a raw EML file for full multi-signal phishing analysis."""
    raw = await file.read()
    parsed = parse_email(raw)
    verdict = analyze(parsed, ml_model)

    # Save to database
    await save_result(
        sender=parsed["sender"].get("email", ""),
        subject=parsed["headers"].get("subject", ""),
        status=verdict.to_dict()["status"],
        threat_score=verdict.to_dict()["threat_score"],
        confidence=verdict.to_dict()["confidence"],
        action=verdict.to_dict()["action"],
        evidence=verdict.to_dict()["evidence"],
        breakdown=verdict.to_dict()["breakdown"],
        body_preview=parsed.get("body", "")[:300],
        source="upload",
    )

    return _verdict_to_response(verdict)


@app.post("/analyze/text", response_model=AnalysisResponse, summary="Analyze raw text")
async def analyze_text(text: str = Form(...)):
    """Paste raw email body text for quick analysis."""
    parsed = parse_raw_text(text)
    verdict = analyze(parsed, ml_model)

    # Save to database
    result = verdict.to_dict()
    await save_result(
        sender="",
        subject="(manual text input)",
        status=result["status"],
        threat_score=result["threat_score"],
        confidence=result["confidence"],
        action=result["action"],
        evidence=result["evidence"],
        breakdown=result["breakdown"],
        body_preview=text[:300],
        source="manual",
    )

    return _verdict_to_response(verdict)


# ---------------------------------------------------------------------------
# History & Stats Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/results", summary="Get recent scan results")
async def api_results(limit: int = 50, offset: int = 0):
    """Returns recent scan results from the database."""
    return await get_results(limit=limit, offset=offset)


@app.get("/api/stats", summary="Get aggregate statistics")
async def api_stats():
    """Returns aggregate stats for the dashboard."""
    return await get_stats()


# ---------------------------------------------------------------------------
# Mail Scanner Endpoints
# ---------------------------------------------------------------------------
@app.post("/api/mail/connect", summary="Start IMAP mail scanning")
async def mail_connect(config: MailConnectRequest):
    """Configure and start the background IMAP scanner."""
    try:
        scanner.configure(
            imap_host=config.imap_host,
            imap_port=config.imap_port,
            email_addr=config.email,
            password=config.password,
            folder=config.folder,
            poll_interval=config.poll_interval,
        )
        await scanner.start()
        return {"status": "ok", "message": "Scanner started"}
    except Exception as exc:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "detail": str(exc)},
        )


@app.post("/api/mail/disconnect", summary="Stop IMAP mail scanning")
async def mail_disconnect():
    """Stop the background mail scanner."""
    await scanner.stop()
    return {"status": "ok", "message": "Scanner stopped"}


@app.get("/api/mail/status", summary="Get scanner status")
async def mail_status():
    """Returns the current status of the IMAP scanner."""
    return scanner.status()


# ---------------------------------------------------------------------------
# Training Endpoint
# ---------------------------------------------------------------------------
@app.post("/train", response_model=TrainResponse, summary="Retrain the ML model")
async def train_model(file: Optional[UploadFile] = File(None)):
    """Upload a CSV to retrain the model, or retrain on synthetic data."""
    csv_path = None
    if file:
        csv_path = "uploaded_training_data.csv"
        content = await file.read()
        with open(csv_path, "wb") as f:
            f.write(content)
    report = ml_model.train(csv_path)
    return TrainResponse(status="ok", report=report or "Training complete.")


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
@app.get("/health", response_model=HealthResponse, summary="Health check")
async def health():
    return HealthResponse(
        status="ok",
        model_trained=ml_model.is_trained,
        version="2.0.0",
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _verdict_to_response(verdict: AnalysisVerdict) -> AnalysisResponse:
    data = verdict.to_dict()
    return AnalysisResponse(
        status=data["status"],
        action=data["action"],
        threat_score=data["threat_score"],
        confidence=data["confidence"],
        breakdown=ScoreBreakdown(**data["breakdown"]),
        evidence=[EvidenceItem(**e) for e in data["evidence"]],
    )


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
