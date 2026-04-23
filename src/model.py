"""
Ensemble ML model for phishing detection.

Architecture:
- TF-IDF text vectorization + metadata features via ColumnTransformer
- Calibrated VotingClassifier (Logistic Regression + Random Forest + Gradient Boosting)
- Probability calibration ensures confident predictions are truly confident
- Built-in synthetic dataset generator for out-of-the-box demo training
"""
import logging
import os
import random

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import (
    GradientBoostingClassifier,
    RandomForestClassifier,
    VotingClassifier,
)
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "trained_model.joblib")


class PhishingModel:
    """Calibrated ensemble classifier for phishing email detection."""

    def __init__(self):
        self.pipeline: Pipeline | None = None
        self.is_trained: bool = False

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def train(self, csv_path: str | None = None):
        """
        Train the ensemble on a CSV dataset.
        If no path is provided, generate a synthetic demo dataset.
        Expected CSV columns: 'email_body', 'url_count', 'has_attachment',
                              'urgency_score', 'label'
        Minimum required: 'email_body', 'label'
        """
        if csv_path and os.path.exists(csv_path):
            logger.info("Loading dataset from %s", csv_path)
            df = pd.read_csv(csv_path)
        else:
            logger.info("No dataset provided — generating synthetic training data")
            df = _generate_synthetic_dataset()

        # Ensure minimum columns exist
        if "email_body" not in df.columns or "label" not in df.columns:
            raise ValueError("Dataset must contain 'email_body' and 'label' columns")

        # Fill optional metadata columns
        for col, default in [("url_count", 0), ("has_attachment", 0), ("urgency_score", 0.0)]:
            if col not in df.columns:
                df[col] = default

        df["email_body"] = df["email_body"].fillna("")

        X = df[["email_body", "url_count", "has_attachment", "urgency_score"]]
        y = df["label"]

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        # Build pipeline
        self.pipeline = self._build_pipeline()

        logger.info("Training ensemble model …")
        self.pipeline.fit(X_train, y_train)
        self.is_trained = True

        # Evaluate
        predictions = self.pipeline.predict(X_test)
        report = classification_report(y_test, predictions)
        logger.info("Evaluation Report:\n%s", report)

        # Persist
        self.save()
        return report

    def _build_pipeline(self) -> Pipeline:
        """Construct the full sklearn pipeline."""
        text_transformer = TfidfVectorizer(
            stop_words="english",
            max_features=5000,
            ngram_range=(1, 2),
            sublinear_tf=True,
        )

        preprocessor = ColumnTransformer(
            transformers=[
                ("text", text_transformer, "email_body"),
                ("meta", StandardScaler(), ["url_count", "has_attachment", "urgency_score"]),
            ]
        )

        # Ensemble of 3 diverse classifiers
        estimators = [
            ("lr", LogisticRegression(max_iter=1000, C=1.0, random_state=42)),
            ("rf", RandomForestClassifier(n_estimators=120, max_depth=20, random_state=42)),
            ("gb", GradientBoostingClassifier(n_estimators=100, max_depth=5, random_state=42)),
        ]

        voting = VotingClassifier(estimators=estimators, voting="soft")

        # Wrap in calibration for accurate probabilities
        calibrated = CalibratedClassifierCV(voting, cv=3, method="isotonic")

        return Pipeline([
            ("preprocessor", preprocessor),
            ("classifier", calibrated),
        ])

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def predict_proba(self, text: str, url_count: int = 0,
                      has_attachment: int = 0, urgency_score: float = 0.0) -> list[float]:
        """
        Return [P(Safe), P(Phishing)].
        Falls back to a conservative midpoint if the model is not trained.
        """
        if not self.is_trained or self.pipeline is None:
            return [0.5, 0.5]

        sample = pd.DataFrame([{
            "email_body": text,
            "url_count": url_count,
            "has_attachment": has_attachment,
            "urgency_score": urgency_score,
        }])
        probs = self.pipeline.predict_proba(sample)
        return probs[0].tolist()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: str | None = None):
        path = path or MODEL_PATH
        if self.pipeline is not None:
            joblib.dump(self.pipeline, path)
            logger.info("Model saved to %s", path)

    def load(self, path: str | None = None) -> bool:
        path = path or MODEL_PATH
        if os.path.exists(path):
            self.pipeline = joblib.load(path)
            self.is_trained = True
            logger.info("Model loaded from %s", path)
            return True
        return False


# ---------------------------------------------------------------------------
# Synthetic Dataset Generator
# ---------------------------------------------------------------------------

_SAFE_TEMPLATES = [
    "Hi {name}, The meeting has been rescheduled to {day}. Please update your calendar.",
    "Hello team, Attached is the quarterly report for Q{q}. Let me know if you have questions.",
    "Hey {name}, Just wanted to follow up on our conversation last week about the project timeline.",
    "Dear {name}, Thank you for your purchase. Your order #{order} has shipped and will arrive by {day}.",
    "Hi {name}, Welcome to the team! Please find the onboarding documents attached.",
    "Good morning, Here are the notes from yesterday's standup meeting. Action items are highlighted.",
    "Hi {name}, Your subscription renewal for {service} has been processed successfully.",
    "Dear {name}, We appreciate your feedback regarding our {service}. We'll look into it.",
    "Hello, The office will be closed on {day} for maintenance. Please plan accordingly.",
    "Hi {name}, Please review the attached design mockups and share your thoughts by Friday.",
    "Hello {name}, Your flight confirmation for {day} is attached. Have a great trip!",
    "Hi team, Reminder: the deadline for the {project} proposal is next {day}.",
    "Dear {name}, Your recent support ticket #{order} has been resolved. Please verify.",
    "Hello, Lunch-and-learn session this {day} at noon in Conference Room B. Topic: {service}.",
    "Hi {name}, I've shared the Google Doc with you. Please add your section by end of week.",
]

_PHISHING_TEMPLATES = [
    "URGENT: Your {service} account has been compromised. Verify your identity immediately at {url}",
    "Dear Customer, We detected unauthorized access to your account. Click here to secure it: {url}",
    "Your account will be suspended within 24 hours unless you verify your information at {url}",
    "SECURITY ALERT: Unusual activity detected on your {service} account. Confirm your identity: {url}",
    "Dear valued customer, Update your payment information immediately to avoid service interruption: {url}",
    "Congratulations! You have been selected to receive a $1000 gift card. Claim now: {url}",
    "Your {service} password expires today. Click here immediately to update: {url}",
    "Dear user, Your account has been deactivated. Verify your account to restore access: {url}",
    "IMPORTANT: Failure to respond within 48 hours will result in permanent account closure. Act now: {url}",
    "You have won a prize in our lottery! Click here to claim your winnings: {url}",
    "Dear account holder, We need to verify your social security number for tax purposes: {url}",
    "ALERT: Your credit card number on file is invalid. Update your payment method: {url}",
    "Urgent: Your {service} subscription payment failed. Update your bank account details: {url}",
    "Dear Customer, Kindly wire transfer the remaining balance to avoid legal action. Details: {url}",
    "Security Notice: Someone tried to sign in to your {service} account. Confirm it was you: {url}",
    "I am a barrister in Nigeria. My late client left behind an inheritance of $15,000,000. Kindly wire transfer processing fee to {url} and provide your bank account details.",
    "Your {service} password expires today. Please click the link below to update your password and continue using our service: {url}",
]

def _generate_synthetic_dataset(n_samples: int = 2000) -> pd.DataFrame:
    """Generate a balanced synthetic dataset for model training."""
    rng = random.Random(42)
    rows = []
    names = ["Alex", "Jordan", "Sam", "Taylor", "Morgan", "Casey"]
    days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
    services = ["Office365", "Gmail", "Dropbox", "OneDrive", "Slack", "Netflix"]
    projects = ["Alpha", "Phoenix", "Mercury", "Titan"]
    phish_urls = [
        "http://secure-login.evil-site.xyz/verify",
        "http://192.168.1.100/update",
        "https://acc0unt-verify.tk/login",
        "http://paypa1.com.malicious.top/secure",
        "https://bit.ly/3xFake",
    ]

    half = n_samples // 2

    for _ in range(half):
        tpl = rng.choice(_SAFE_TEMPLATES)
        body = tpl.format(
            name=rng.choice(names), day=rng.choice(days),
            q=rng.randint(1, 4), order=rng.randint(10000, 99999),
            service=rng.choice(services), project=rng.choice(projects),
        )
        rows.append({
            "email_body": body,
            "url_count": rng.randint(0, 2),
            "has_attachment": rng.choice([0, 0, 0, 1]),
            "urgency_score": round(rng.uniform(0.0, 0.15), 2),
            "label": 0,
        })

    for _ in range(half):
        tpl = rng.choice(_PHISHING_TEMPLATES)
        body = tpl.format(
            service=rng.choice(services),
            url=rng.choice(phish_urls),
        )
        rows.append({
            "email_body": body,
            "url_count": rng.randint(1, 5),
            "has_attachment": rng.choice([0, 0, 1]),
            "urgency_score": round(rng.uniform(0.4, 1.0), 2),
            "label": 1,
        })

    rng.shuffle(rows)
    return pd.DataFrame(rows)
