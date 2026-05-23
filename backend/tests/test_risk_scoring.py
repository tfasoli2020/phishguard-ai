"""Tests for risk_scoring service."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dataclasses import dataclass
from app.services.risk_scoring import calculate_risk_score, SEVERITY_WEIGHTS


@dataclass
class MockFinding:
    category: str
    severity: str
    finding: str
    evidence: str
    recommendation: str


def make_findings(*severities):
    return [
        MockFinding(
            category="Test",
            severity=sev,
            finding=f"{sev} finding",
            evidence="test evidence",
            recommendation="test recommendation",
        )
        for sev in severities
    ]


def test_no_findings_scores_zero():
    result = calculate_risk_score([])
    assert result.risk_score == 0
    assert result.risk_level == "Low"


def test_single_critical_finding():
    result = calculate_risk_score(make_findings("critical"))
    assert result.risk_score == 30
    assert result.risk_level == "Medium"  # 30 is in 21-50 = Medium


def test_score_capped_at_100():
    # Many critical findings should not exceed 100
    result = calculate_risk_score(make_findings(*["critical"] * 10))
    assert result.risk_score == 100


def test_risk_level_thresholds():
    assert calculate_risk_score(make_findings("low")).risk_level == "Low"          # 5 → Low
    assert calculate_risk_score(make_findings("medium", "medium", "medium")).risk_level == "Medium"  # 30 → Medium
    assert calculate_risk_score(make_findings("high", "high", "high")).risk_level == "High"          # 60 → High
    assert calculate_risk_score(make_findings("critical", "critical", "critical")).risk_level == "Critical"  # 90 → Critical


def test_phishing_classification():
    findings = [
        MockFinding("URL Analysis", "critical", "credential harvesting", "http://evil.com", "avoid"),
        MockFinding("Content Analysis", "high", "credential harvesting language", "verify account", "avoid"),
    ]
    result = calculate_risk_score(findings)
    assert result.classification == "phishing"


def test_legitimate_classification():
    result = calculate_risk_score([])
    assert result.classification == "likely_legitimate"


def test_bec_classification():
    findings = [
        MockFinding("BEC Analysis", "critical", "CEO impersonation wire transfer request", "wire", "verify"),
        MockFinding("Content Analysis", "high", "payment request language", "send $50,000", "verify"),
    ]
    result = calculate_risk_score(findings)
    assert result.classification == "business_email_compromise"


def test_summary_is_string():
    result = calculate_risk_score(make_findings("high"))
    assert isinstance(result.summary, str)
    assert len(result.summary) > 10


def test_recommended_actions_not_empty_for_high_risk():
    result = calculate_risk_score(make_findings("high", "high", "critical"))
    assert len(result.recommended_actions) >= 1


def test_score_explanation_present():
    result = calculate_risk_score(make_findings("medium"))
    assert isinstance(result.score_explanation, str)
    assert "10" in result.score_explanation  # medium = 10 pts


def test_ml_boost_on_borderline_score():
    # Score of 20 (2x low=5, 1x medium=10) → Low normally
    findings = make_findings("low", "low", "medium")
    base = calculate_risk_score(findings)
    assert base.risk_score == 20

    # ML highly confident phishing should add 10
    boosted = calculate_risk_score(findings, ml_prediction="phishing", ml_confidence=0.95)
    assert boosted.risk_score == 30


def test_classification_label_field_present():
    """ScoringResult must always carry a human-readable classification_label."""
    result = calculate_risk_score([])
    assert hasattr(result, "classification_label")
    assert isinstance(result.classification_label, str)
    assert len(result.classification_label) > 0


def test_classification_label_full_name_for_bec():
    """BEC classification must use the full label, not 'BEC' abbreviation."""
    findings = [
        MockFinding("BEC Analysis", "critical", "CEO impersonation wire transfer request", "wire $50k", "verify"),
        MockFinding("Content Analysis", "high", "payment request language", "send funds", "verify"),
    ]
    result = calculate_risk_score(findings)
    assert result.classification == "business_email_compromise"
    assert result.classification_label == "Business Email Compromise"


def test_low_confidence_ml_does_not_override_likely_legitimate():
    """When rule-based finds nothing and ML is below threshold, result stays likely_legitimate."""
    result = calculate_risk_score([], ml_prediction="phishing", ml_confidence=0.52)
    assert result.classification == "likely_legitimate"
    assert result.risk_score == 0


def test_high_confidence_ml_phishing_boosts_score():
    """High-confidence ML phishing prediction adds 10 to a zero-finding score."""
    result = calculate_risk_score([], ml_prediction="phishing", ml_confidence=0.90)
    assert result.risk_score == 10
    assert result.classification in ("phishing", "likely_legitimate")  # small boost, may not reclassify
