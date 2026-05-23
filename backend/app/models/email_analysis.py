from sqlalchemy import Column, Integer, String, Float, Text, DateTime
from sqlalchemy.sql import func
from app.database import Base


class EmailAnalysis(Base):
    __tablename__ = "email_analyses"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Email metadata
    sender = Column(String(512), nullable=True)
    subject = Column(String(1024), nullable=True)

    # Results
    classification = Column(String(64), nullable=False)
    classification_label = Column(String(128), nullable=False, default="")
    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String(32), nullable=False)
    summary = Column(Text, nullable=False)

    # Stored as JSON strings
    raw_email = Column(Text, nullable=False)
    findings_json = Column(Text, nullable=False)
    recommended_actions_json = Column(Text, nullable=False)
    email_metadata_json = Column(Text, nullable=False)

    # ML outputs
    ml_prediction = Column(String(64), nullable=True)
    ml_confidence = Column(Float, nullable=True)

    # Generated report
    report = Column(Text, nullable=False)
