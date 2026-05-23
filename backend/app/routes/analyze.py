from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models.email_analysis import EmailAnalysis
from app.models.schemas import AnalyzeRequest, AnalyzeResponse, EmailMetadata, Finding
from app.services.email_parser import parse_email
from app.services.header_analyzer import analyze_headers
from app.services.url_analyzer import analyze_urls
from app.services.content_analyzer import analyze_content
from app.services.risk_scoring import calculate_risk_score, ML_CONFIDENCE_THRESHOLD, CLASSIFICATION_DISPLAY
from app.services.report_generator import generate_report
from app.services.ml_classifier import classify_email
from app.utils.security_helpers import sanitize_text, truncate

logger = logging.getLogger(__name__)
router = APIRouter()


def _to_schema_finding(f) -> Finding:
    return Finding(
        category=sanitize_text(f.category),
        severity=sanitize_text(f.severity),
        finding=sanitize_text(f.finding),
        evidence=sanitize_text(truncate(f.evidence, 500)),
        recommendation=sanitize_text(f.recommendation),
    )


def _user_facing_ml(raw_prediction: str | None, confidence: float | None) -> str | None:
    """
    Return the prediction label shown to the user.
    Low-confidence results are surfaced as 'inconclusive' so they don't
    alarm analysts when the rule-based engine found nothing suspicious.
    """
    if raw_prediction is None or confidence is None:
        return None
    if confidence < ML_CONFIDENCE_THRESHOLD:
        return "inconclusive"
    return raw_prediction


@router.post("/analyze", response_model=AnalyzeResponse, tags=["Analysis"])
def analyze_email_route(request: AnalyzeRequest, db: Session = Depends(get_db)):
    if len(request.email_text.encode()) > settings.MAX_EMAIL_SIZE_BYTES:
        raise HTTPException(status_code=413, detail="Email content exceeds maximum allowed size.")

    # ── Parse ─────────────────────────────────────────────────────────────────
    parsed = parse_email(request.email_text)

    # ── Rule-based detection ──────────────────────────────────────────────────
    all_findings: list = []
    all_findings.extend(analyze_headers(parsed))
    all_findings.extend(analyze_urls(parsed.urls))
    all_findings.extend(analyze_content(parsed))

    # ── ML classification ─────────────────────────────────────────────────────
    ml_result = classify_email(request.email_text, settings.ML_MODEL_PATH)
    raw_ml_prediction = ml_result.prediction if ml_result.model_loaded else None
    ml_confidence = ml_result.confidence if ml_result.model_loaded else None

    # User-facing ML label (suppresses low-confidence scary predictions)
    ml_display_prediction = _user_facing_ml(raw_ml_prediction, ml_confidence)

    # ── Risk scoring (uses raw prediction internally) ─────────────────────────
    scoring = calculate_risk_score(all_findings, raw_ml_prediction, ml_confidence)

    # ── Build response objects ────────────────────────────────────────────────
    schema_findings = [_to_schema_finding(f) for f in all_findings]
    email_metadata = EmailMetadata(
        sender=sanitize_text(parsed.sender),
        reply_to=sanitize_text(parsed.reply_to),
        recipient=sanitize_text(parsed.recipient),
        subject=sanitize_text(parsed.subject),
        date=sanitize_text(parsed.date),
        domains=parsed.domains[:50],
        urls=[truncate(u, 300) for u in parsed.urls[:50]],
    )

    # ── Persist to database ───────────────────────────────────────────────────
    db_record = EmailAnalysis(
        sender=parsed.sender[:512] if parsed.sender else None,
        subject=parsed.subject[:1024] if parsed.subject else None,
        classification=scoring.classification,
        classification_label=scoring.classification_label,
        risk_score=scoring.risk_score,
        risk_level=scoring.risk_level,
        summary=scoring.summary,
        raw_email=truncate(request.email_text, 50_000),
        findings_json=json.dumps([f.model_dump() for f in schema_findings]),
        recommended_actions_json=json.dumps(scoring.recommended_actions),
        email_metadata_json=email_metadata.model_dump_json(),
        ml_prediction=ml_display_prediction,
        ml_confidence=ml_confidence,
        report="",
    )
    db.add(db_record)
    db.flush()

    report_text = generate_report(
        parsed=parsed,
        scoring=scoring,
        findings=all_findings,
        ml_display_prediction=ml_display_prediction,
        raw_ml_prediction=raw_ml_prediction,
        ml_confidence=ml_confidence,
        analysis_id=db_record.id,
    )
    db_record.report = report_text
    db.commit()
    db.refresh(db_record)

    return AnalyzeResponse(
        analysis_id=db_record.id,
        classification=scoring.classification,
        classification_label=scoring.classification_label,
        risk_score=scoring.risk_score,
        risk_level=scoring.risk_level,
        summary=scoring.summary,
        email_metadata=email_metadata,
        ml_prediction=ml_display_prediction,
        ml_confidence=ml_confidence,
        findings=schema_findings,
        recommended_actions=scoring.recommended_actions,
        report=report_text,
    )
