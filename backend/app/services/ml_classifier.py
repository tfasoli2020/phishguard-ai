"""
Baseline ML classifier: TF-IDF + LinearSVC trained on a synthetic dataset.
The model is trained once on first use and persisted to disk.
It supports the rule-based engine — it does not replace it.
"""
from __future__ import annotations


import json
import logging
import os
import pickle
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, List, Tuple

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split

logger = logging.getLogger(__name__)

LABELS = ["phishing", "business_email_compromise", "spam", "legitimate"]

# ── Synthetic training corpus ────────────────────────────────────────────────
# Each entry is (text, label). These are entirely synthetic and contain no
# real user data.  They exist only to give the baseline classifier a signal.
SYNTHETIC_DATA: List[Tuple[str, str]] = [
    # ── Phishing samples ──────────────────────────────────────────────────
    ("Your account has been suspended. Verify your identity immediately at http://secure-login.example.net/verify", "phishing"),
    ("Click here to confirm your PayPal account or it will be permanently closed http://paypa1-secure.example.com", "phishing"),
    ("URGENT: Your Apple ID was used to sign in from an unknown device. Confirm now: http://apple-id-check.example.org", "phishing"),
    ("Dear Customer, your Netflix account payment failed. Update your billing at http://netflix-billing.example.net", "phishing"),
    ("Security Alert: Unusual sign-in activity detected. Verify account: http://microsoft-verify.example.com/login", "phishing"),
    ("Your Amazon order cannot be shipped. Verify your shipping address: http://amaz0n-update.example.net", "phishing"),
    ("IRS Notice: You are eligible for a tax refund. Claim at http://irs-refund.example.com immediately.", "phishing"),
    ("Chase Bank: Your account access has been limited. Sign in to resolve: http://chase-secure.example.org", "phishing"),
    ("Your Dropbox storage is full. Upgrade your plan: http://dropbox-upgrade.example.net/account", "phishing"),
    ("DocuSign: You have a pending document. Click to review: http://docusign-review.example.com/doc", "phishing"),
    ("Dear valued member, please verify your credentials to avoid account suspension. Click here.", "phishing"),
    ("Your password will expire in 24 hours. Reset now at http://password-reset.example.net/update", "phishing"),
    ("We noticed suspicious activity on your account. Verify your identity to continue.", "phishing"),
    ("One-time verification code request. Click the link to confirm your phone number.", "phishing"),
    ("FINAL NOTICE: Your account will be closed unless you update your information within 48 hours.", "phishing"),
    ("Dear user, your account requires verification. Enter your username and password to confirm.", "phishing"),
    ("You have a new secure message. Sign in to view: http://secure-messages.example.com/inbox", "phishing"),
    ("Your FedEx package could not be delivered. Reschedule delivery: http://fedex-reschedule.example.net", "phishing"),
    ("USPS alert: Your package is held. Confirm address at http://usps-confirm.example.org", "phishing"),
    ("Wells Fargo: Unusual transaction detected. Review at http://wellsfargo-verify.example.com", "phishing"),

    # ── BEC samples ──────────────────────────────────────────────────────
    ("Hi, are you available? I need you to handle a confidential task urgently. Do not discuss with anyone.", "business_email_compromise"),
    ("This is the CEO. Please process a wire transfer of $45,000 to this account by end of day. Keep this between us.", "business_email_compromise"),
    ("CFO here. We have a time-sensitive acquisition. Purchase five $500 iTunes gift cards and send me the codes.", "business_email_compromise"),
    ("Our vendor has updated their banking details. Please update payment information for future invoices.", "business_email_compromise"),
    ("I am in a meeting and cannot be reached by phone. Please initiate a wire transfer to the attached account details.", "business_email_compromise"),
    ("This is strictly confidential. Our company is finalizing a merger. Do not contact legal or finance teams yet.", "business_email_compromise"),
    ("Please change the bank account for our supplier ABC Corp to the new account provided below immediately.", "business_email_compromise"),
    ("Invoice #4521 is overdue. Please wire payment to our new account immediately to avoid penalties.", "business_email_compromise"),
    ("Can you handle a discreet purchase for me? I need Amazon gift cards for a client. Don't tell anyone yet.", "business_email_compromise"),
    ("Hello, I need you to process an urgent payment. The client is waiting. Please don't call — I'm traveling.", "business_email_compromise"),
    ("Our finance department has a new banking partner. Please update our payment receiving account details.", "business_email_compromise"),
    ("Hi, it's your manager. I need a favor — purchase Google Play gift cards totaling $300 and share the codes.", "business_email_compromise"),
    ("Reminder: Invoice attached. Please process payment to our new bank account immediately.", "business_email_compromise"),
    ("I am the President and I need this wire transfer processed today. Time is critical. Don't involve anyone else.", "business_email_compromise"),
    ("URGENT: Change vendor payment details before next check run. New banking info attached.", "business_email_compromise"),

    # ── Spam samples ──────────────────────────────────────────────────────
    ("You have been selected as a winner! Claim your $1,000 prize now. Limited time offer!", "spam"),
    ("Exclusive deal: 80% off all products today only. Click to shop before it's gone!", "spam"),
    ("Lose 30 pounds in 30 days with this one simple trick. Doctors don't want you to know!", "spam"),
    ("Make $5,000 a week from home. No experience required. Start today!", "spam"),
    ("Hot singles in your area are waiting. Click to see their profiles.", "spam"),
    ("Your email was selected for a special offer. Unsubscribe at any time.", "spam"),
    ("Discount medications available without a prescription. Order online today.", "spam"),
    ("Nigerian prince needs your help transferring $15 million. You keep 30%.", "spam"),
    ("Congratulations! You have been pre-approved for a $10,000 credit line.", "spam"),
    ("Work from home opportunity — earn big with minimal effort. Join now.", "spam"),
    ("Limited time: Buy one get one free on all supplements. Click to order.", "spam"),
    ("Refinance your mortgage today. Get the lowest rates available. Apply now.", "spam"),
    ("You are a finalist in our sweepstakes! Respond to claim your prize.", "spam"),
    ("Enlarge and strengthen. Guaranteed results. Discreet shipping.", "spam"),
    ("Best price on Rolex watches. 90% discount. Free shipping worldwide.", "spam"),

    # ── Legitimate samples ─────────────────────────────────────────────────
    ("Hi John, attached is the Q3 budget report as discussed in yesterday's meeting. Let me know if you have questions.", "legitimate"),
    ("Your order #12345 has shipped and will arrive by Friday. Track your package on our website.", "legitimate"),
    ("Team, the all-hands meeting is scheduled for Tuesday at 2pm in Conference Room B. Please confirm attendance.", "legitimate"),
    ("Hi Sarah, thank you for applying. We'd like to schedule an interview for next week. Please reply with your availability.", "legitimate"),
    ("Your monthly statement is now available. Log in to your account to view your recent transactions.", "legitimate"),
    ("Reminder: Your dentist appointment is on Thursday, May 15 at 3:30 PM. Reply to confirm or reschedule.", "legitimate"),
    ("Please find the revised proposal attached. Let me know if the scope changes are acceptable.", "legitimate"),
    ("Your GitHub pull request was merged by maintainer. Thanks for contributing to the project!", "legitimate"),
    ("This is a courtesy reminder that your library books are due on Friday. Renew online or at the branch.", "legitimate"),
    ("Welcome aboard! Your first day is Monday. Please arrive at 9am and ask for HR at the front desk.", "legitimate"),
    ("Your subscription renewal is coming up on June 1. No action is needed — your card on file will be charged.", "legitimate"),
    ("Hi, just following up on the contract draft I sent last week. Are there any revisions needed?", "legitimate"),
    ("Quarterly security awareness training is due by end of month. Please complete the module in the learning portal.", "legitimate"),
    ("Your flight confirmation is attached. Please review the details and contact us if anything needs correction.", "legitimate"),
    ("Maintenance is scheduled this weekend from Saturday 10pm to Sunday 6am. Services may be intermittently unavailable.", "legitimate"),
]


@dataclass
class MLResult:
    prediction: str
    confidence: float
    model_loaded: bool


_pipeline = None  # type: Optional[Pipeline]


def _build_pipeline() -> Pipeline:
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=10_000,
        sublinear_tf=True,
        strip_accents="unicode",
    )
    svc = CalibratedClassifierCV(LinearSVC(max_iter=2000, C=1.0))
    return Pipeline([("tfidf", vectorizer), ("clf", svc)])


def _train_and_save(model_path: str) -> Pipeline:
    texts = [t for t, _ in SYNTHETIC_DATA]
    labels = [l for _, l in SYNTHETIC_DATA]

    pipeline = _build_pipeline()
    pipeline.fit(texts, labels)

    Path(model_path).parent.mkdir(parents=True, exist_ok=True)
    with open(model_path, "wb") as f:
        pickle.dump(pipeline, f)

    logger.info("ML model trained and saved to %s", model_path)
    return pipeline


def load_model(model_path: str) -> Pipeline:
    global _pipeline
    if _pipeline is not None:
        return _pipeline

    if os.path.exists(model_path):
        try:
            with open(model_path, "rb") as f:
                _pipeline = pickle.load(f)
            logger.info("ML model loaded from %s", model_path)
        except Exception as exc:
            logger.warning("Failed to load model from disk (%s), retraining.", exc)
            _pipeline = _train_and_save(model_path)
    else:
        _pipeline = _train_and_save(model_path)

    return _pipeline


def is_model_loaded() -> bool:
    return _pipeline is not None


def classify_email(text: str, model_path: str) -> MLResult:
    try:
        pipeline = load_model(model_path)
        proba = pipeline.predict_proba([text])[0]
        classes = pipeline.classes_
        pred_idx = int(np.argmax(proba))
        prediction = classes[pred_idx]
        confidence = float(proba[pred_idx])
        return MLResult(prediction=prediction, confidence=round(confidence, 4), model_loaded=True)
    except Exception as exc:
        logger.error("ML classification failed: %s", exc)
        return MLResult(prediction="unknown", confidence=0.0, model_loaded=False)
