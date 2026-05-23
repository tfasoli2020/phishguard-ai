from pydantic import BaseModel, Field, field_validator
from typing import Optional
from datetime import datetime


class AnalyzeRequest(BaseModel):
    email_text: str = Field(..., min_length=1, max_length=500_000)

    @field_validator("email_text")
    @classmethod
    def strip_and_validate(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("email_text must not be blank")
        return stripped


class Finding(BaseModel):
    category: str
    severity: str  # critical | high | medium | low | info
    finding: str
    evidence: str
    recommendation: str


class EmailMetadata(BaseModel):
    sender: str = ""
    reply_to: str = ""
    recipient: str = ""
    subject: str = ""
    date: str = ""
    domains: list = []
    urls: list = []


class AnalyzeResponse(BaseModel):
    analysis_id: int
    classification: str        # internal code: "phishing", "business_email_compromise", etc.
    classification_label: str  # display label: "Phishing", "Business Email Compromise", etc.
    risk_score: int
    risk_level: str
    summary: str
    email_metadata: EmailMetadata
    ml_prediction: Optional[str] = None      # "inconclusive" when confidence < 65%
    ml_confidence: Optional[float] = None
    findings: list = []
    recommended_actions: list = []
    report: str


class AnalysisSummary(BaseModel):
    model_config = {"from_attributes": True}

    analysis_id: int
    timestamp: datetime
    sender: Optional[str]
    subject: Optional[str]
    classification: str
    classification_label: str
    risk_score: int
    risk_level: str
    summary: str


class AnalysisDetail(AnalysisSummary):
    email_metadata: EmailMetadata
    ml_prediction: Optional[str]
    ml_confidence: Optional[float]
    findings: list = []
    recommended_actions: list = []
    report: str


class HealthResponse(BaseModel):
    status: str
    version: str
    ml_model_loaded: bool
