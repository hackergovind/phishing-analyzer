"""
SQLite database for persisting phishing scan results.
Uses aiosqlite for async access from FastAPI.
"""
import json
import logging
import aiosqlite
from datetime import datetime, timezone

from src.config import DB_PATH

logger = logging.getLogger(__name__)

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    sender TEXT DEFAULT '',
    subject TEXT DEFAULT '',
    status TEXT NOT NULL,
    threat_score REAL NOT NULL,
    confidence REAL NOT NULL DEFAULT 0.0,
    action TEXT NOT NULL,
    evidence TEXT DEFAULT '[]',
    breakdown TEXT DEFAULT '{}',
    body_preview TEXT DEFAULT '',
    source TEXT DEFAULT 'manual'
)
"""


async def init_db():
    """Create the database and tables if they don't exist."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("PRAGMA journal_mode=WAL;")
        await db.execute("PRAGMA busy_timeout=5000;")
        await db.execute(CREATE_TABLE_SQL)
        await db.commit()
    logger.info("Database initialized at %s", DB_PATH)


async def save_result(
    sender: str,
    subject: str,
    status: str,
    threat_score: float,
    confidence: float,
    action: str,
    evidence: list[dict],
    breakdown: dict,
    body_preview: str = "",
    source: str = "manual",
) -> int:
    """Save a scan result and return its ID."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("PRAGMA busy_timeout=5000;")
        cursor = await db.execute(
            """INSERT INTO scan_results 
               (timestamp, sender, subject, status, threat_score, confidence,
                action, evidence, breakdown, body_preview, source)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.now(timezone.utc).isoformat(),
                sender,
                subject,
                status,
                threat_score,
                confidence,
                action,
                json.dumps(evidence),
                json.dumps(breakdown),
                body_preview[:500],  # Cap preview length
                source,
            ),
        )
        await db.commit()
        return cursor.lastrowid or 0


async def get_results(limit: int = 50, offset: int = 0) -> list[dict]:
    """Get recent scan results, newest first."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """SELECT * FROM scan_results 
               ORDER BY id DESC LIMIT ? OFFSET ?""",
            (limit, offset),
        )
        rows = await cursor.fetchall()
        results = []
        for row in rows:
            r = dict(row)
            r["evidence"] = json.loads(r["evidence"])
            r["breakdown"] = json.loads(r["breakdown"])
            results.append(r)
        return results


async def get_stats() -> dict:
    """Get aggregate statistics for the dashboard."""
    async with aiosqlite.connect(DB_PATH) as db:
        # Total counts by status
        cursor = await db.execute("SELECT COUNT(*) FROM scan_results")
        total = (await cursor.fetchone())[0]

        cursor = await db.execute("SELECT COUNT(*) FROM scan_results WHERE status = 'Safe'")
        safe = (await cursor.fetchone())[0]

        cursor = await db.execute("SELECT COUNT(*) FROM scan_results WHERE status = 'Suspicious'")
        suspicious = (await cursor.fetchone())[0]

        cursor = await db.execute("SELECT COUNT(*) FROM scan_results WHERE status = 'Phishing'")
        phishing = (await cursor.fetchone())[0]

        cursor = await db.execute("SELECT AVG(threat_score) FROM scan_results")
        avg_row = await cursor.fetchone()
        avg_score = avg_row[0] if avg_row[0] is not None else 0.0

        # Recent trend: last 24 hours
        cursor = await db.execute(
            """SELECT status, COUNT(*) as cnt FROM scan_results 
               WHERE timestamp > datetime('now', '-1 day')
               GROUP BY status"""
        )
        trend_rows = await cursor.fetchall()
        trend = {row[0]: row[1] for row in trend_rows}

        return {
            "total": total,
            "safe": safe,
            "suspicious": suspicious,
            "phishing": phishing,
            "avg_threat_score": round(avg_score, 1),
            "last_24h": trend,
        }
