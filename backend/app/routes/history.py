import json
import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.email_analysis import EmailAnalysis
from app.models.schemas import AnalysisSummary, AnalysisDetail, EmailMetadata, Finding
from app.services.risk_scoring import CLASSIFICATION_DISPLAY

logger = logging.getLogger(__name__)
router = APIRouter()


def _label(record: EmailAnalysis) -> str:
    """Return the display label, falling back to computing it from the code."""
    if record.classification_label:
        return record.classification_label
    return CLASSIFICATION_DISPLAY.get(record.classification, record.classification.replace("_", " ").title())


def _to_detail(record: EmailAnalysis) -> AnalysisDetail:
    findings_raw = json.loads(record.findings_json or "[]")
    findings = [Finding(**f) for f in findings_raw]

    recommended_actions = json.loads(record.recommended_actions_json or "[]")

    metadata_raw = json.loads(record.email_metadata_json or "{}")
    email_metadata = EmailMetadata(**metadata_raw)

    return AnalysisDetail(
        analysis_id=record.id,
        timestamp=record.timestamp,
        sender=record.sender,
        subject=record.subject,
        classification=record.classification,
        classification_label=_label(record),
        risk_score=record.risk_score,
        risk_level=record.risk_level,
        summary=record.summary,
        email_metadata=email_metadata,
        ml_prediction=record.ml_prediction,
        ml_confidence=record.ml_confidence,
        findings=findings,
        recommended_actions=recommended_actions,
        report=record.report,
    )


@router.get("/history", response_model=list, tags=["History"])
def get_history(limit: int = 50, db: Session = Depends(get_db)):
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 500")
    records = (
        db.query(EmailAnalysis)
        .order_by(EmailAnalysis.timestamp.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "analysis_id": r.id,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            "sender": r.sender,
            "subject": r.subject,
            "classification": r.classification,
            "classification_label": _label(r),
            "risk_score": r.risk_score,
            "risk_level": r.risk_level,
            "summary": r.summary,
        }
        for r in records
    ]


@router.get("/history/{analysis_id}", response_model=AnalysisDetail, tags=["History"])
def get_analysis(analysis_id: int, db: Session = Depends(get_db)):
    record = db.query(EmailAnalysis).filter(EmailAnalysis.id == analysis_id).first()
    if not record:
        raise HTTPException(status_code=404, detail=f"Analysis {analysis_id} not found.")
    return _to_detail(record)


@router.delete("/history/{analysis_id}", status_code=204, tags=["History"])
def delete_analysis(analysis_id: int, db: Session = Depends(get_db)):
    record = db.query(EmailAnalysis).filter(EmailAnalysis.id == analysis_id).first()
    if not record:
        raise HTTPException(status_code=404, detail=f"Analysis {analysis_id} not found.")
    db.delete(record)
    db.commit()
