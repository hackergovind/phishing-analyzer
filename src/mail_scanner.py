"""
Background IMAP mail scanner.

Connects to an IMAP server, periodically polls for unread emails,
runs each through the phishing analysis pipeline, stores results in
the database, and optionally quarantines detected phishing emails
by moving them to a dedicated folder.
"""
import asyncio
import email as email_lib
import imaplib
import logging
from datetime import datetime

from src.config import (
    MAIL_IMAP_HOST,
    MAIL_IMAP_PORT,
    MAIL_EMAIL,
    MAIL_PASSWORD,
    MAIL_FOLDER,
    MAIL_POLL_INTERVAL,
    MAIL_QUARANTINE_FOLDER,
)
from src.preprocessing import parse_email
from src.analysis import analyze
from src.database import save_result

logger = logging.getLogger(__name__)


class MailScanner:
    """Manages a background IMAP polling loop."""

    def __init__(self, ml_model=None):
        self.ml_model = ml_model
        self._task: asyncio.Task | None = None
        self._running = False
        self._imap_host = MAIL_IMAP_HOST
        self._imap_port = MAIL_IMAP_PORT
        self._email = MAIL_EMAIL
        self._password = MAIL_PASSWORD
        self._folder = MAIL_FOLDER
        self._poll_interval = MAIL_POLL_INTERVAL
        self._quarantine_folder = MAIL_QUARANTINE_FOLDER
        self.last_error: str | None = None
        self.emails_scanned: int = 0

    @property
    def is_running(self) -> bool:
        return self._running

    def configure(
        self,
        imap_host: str | None = None,
        imap_port: int | None = None,
        email_addr: str | None = None,
        password: str | None = None,
        folder: str | None = None,
        poll_interval: int | None = None,
    ):
        """Update configuration at runtime."""
        if imap_host:
            self._imap_host = imap_host
        if imap_port:
            self._imap_port = imap_port
        if email_addr:
            self._email = email_addr
        if password:
            self._password = password
        if folder:
            self._folder = folder
        if poll_interval:
            self._poll_interval = poll_interval

    async def start(self):
        """Start the background polling loop after verifying credentials."""
        if self._running:
            return
        if not self._email or not self._password:
            raise ValueError("Mail credentials not configured. Set MAIL_EMAIL and MAIL_PASSWORD.")

        # Test connection FIRST so we fail fast with a clear error
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._test_connection)

        self._running = True
        self.last_error = None
        self._task = asyncio.create_task(self._poll_loop())
        logger.info("Mail scanner started for %s", self._email)

    def _test_connection(self):
        """Blocking test: actually log in to IMAP to verify credentials."""
        try:
            conn = imaplib.IMAP4_SSL(self._imap_host, self._imap_port)
            conn.login(self._email, self._password)
            conn.select(self._folder)
            conn.logout()
            logger.info("IMAP connection test passed for %s", self._email)
        except imaplib.IMAP4.error as exc:
            error_msg = str(exc)
            # Provide friendly messages for common failures
            if "Application-specific password" in error_msg:
                raise ValueError(
                    "Gmail requires an App Password for IMAP access. "
                    "Go to https://myaccount.google.com/apppasswords to generate one, "
                    "then use it instead of your regular password."
                ) from exc
            elif "AUTHENTICATIONFAILED" in error_msg or "Invalid credentials" in error_msg:
                raise ValueError(
                    "Authentication failed. Check your email and password. "
                    "For Gmail, use an App Password (not your regular password)."
                ) from exc
            else:
                raise ValueError(f"IMAP login failed: {error_msg}") from exc
        except Exception as exc:
            raise ValueError(f"Could not connect to {self._imap_host}:{self._imap_port} — {exc}") from exc

    async def stop(self):
        """Stop the background polling loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            self._task = None
        logger.info("Mail scanner stopped")

    def status(self) -> dict:
        return {
            "running": self._running,
            "email": self._email,
            "host": self._imap_host,
            "folder": self._folder,
            "poll_interval": self._poll_interval,
            "emails_scanned": self.emails_scanned,
            "last_error": self.last_error,
        }

    # ------------------------------------------------------------------
    # Internal polling loop
    # ------------------------------------------------------------------

    async def _poll_loop(self):
        """Main polling loop — runs in a background asyncio task."""
        while self._running:
            try:
                await self._fetch_and_analyze()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self.last_error = str(exc)
                logger.error("Mail scanner error: %s", exc)
            await asyncio.sleep(self._poll_interval)

    async def _fetch_and_analyze(self):
        """Connect to IMAP, fetch unseen messages, analyze each."""
        # IMAP operations are blocking, so run in a thread
        loop = asyncio.get_running_loop()
        messages = await loop.run_in_executor(None, self._imap_fetch_unseen)

        for msg_uid, raw_bytes in messages:
            try:
                parsed = parse_email(raw_bytes)
                verdict = analyze(parsed, self.ml_model)

                sender = parsed["sender"].get("email", "")
                subject = parsed["headers"].get("subject", "")
                body_preview = parsed.get("body", "")[:300]

                result = verdict.to_dict()
                await save_result(
                    sender=sender,
                    subject=subject,
                    status=result["status"],
                    threat_score=result["threat_score"],
                    confidence=result["confidence"],
                    action=result["action"],
                    evidence=result["evidence"],
                    breakdown=result["breakdown"],
                    body_preview=body_preview,
                    source="imap",
                )

                self.emails_scanned += 1
                logger.info(
                    "Scanned email from %s — %s (score: %.1f)",
                    sender, result["status"], result["threat_score"],
                )

                # Quarantine phishing emails
                if result["status"] == "Phishing":
                    await loop.run_in_executor(
                        None, self._imap_move_to_quarantine, msg_uid
                    )

            except Exception as exc:
                logger.error("Error analyzing email UID %s: %s", msg_uid, exc)

    def _imap_fetch_unseen(self) -> list[tuple[str, bytes]]:
        """Fetch unseen emails via IMAP using persistent UIDs (blocking)."""
        messages = []
        try:
            conn = imaplib.IMAP4_SSL(self._imap_host, self._imap_port)
            conn.login(self._email, self._password)
            conn.select(self._folder)

            status, data = conn.uid("search", None, "UNSEEN")
            if status != "OK" or not data or not data[0]:
                conn.logout()
                return messages

            uids = data[0].split()
            for uid in uids[-20:]:  # Cap at 20 per poll to avoid overload
                status, msg_data = conn.uid("fetch", uid, "(RFC822)")
                if status == "OK" and msg_data and msg_data[0]:
                    raw = msg_data[0][1]
                    if isinstance(raw, bytes):
                        messages.append((uid.decode(), raw))

            conn.logout()
        except Exception as exc:
            self.last_error = str(exc)
            logger.error("IMAP fetch error: %s", exc)

        return messages

    def _imap_move_to_quarantine(self, msg_uid: str):
        """Move a message to the quarantine folder using UID (blocking)."""
        try:
            conn = imaplib.IMAP4_SSL(self._imap_host, self._imap_port)
            conn.login(self._email, self._password)
            conn.select(self._folder)

            # Create quarantine folder if it doesn't exist
            conn.create(self._quarantine_folder)

            # Copy to quarantine by UID, then flag as deleted in original
            conn.uid("copy", msg_uid.encode(), self._quarantine_folder)
            conn.uid("store", msg_uid.encode(), "+FLAGS", "(\\Deleted)")
            conn.expunge()

            conn.logout()
            logger.info("Moved UID %s to quarantine folder '%s'", msg_uid, self._quarantine_folder)
        except Exception as exc:
            logger.warning("Failed to quarantine UID %s: %s", msg_uid, exc)
