"""
Aggregates rule-based findings and ML signal into a 0-100 risk score,
classification, and analyst-ready summary.
"""
from __future__ import annotations
from dataclasses import dataclass

SEVERITY_WEIGHTS = {
    "critical": 30,
    "high": 20,
    "medium": 10,
    "low": 5,
    "info": 0,
}

RISK_LEVELS = [
    (76, "Critical"),
    (51, "High"),
    (21, "Medium"),
    (0, "Low"),
]

# ML predictions below this threshold are treated as inconclusive
ML_CONFIDENCE_THRESHOLD = 0.65

# Professional display labels for API responses and reports
CLASSIFICATION_DISPLAY = {
    "phishing":                  "Phishing",
    "business_email_compromise": "Business Email Compromise",
    "spam":                      "Spam",
    "likely_legitimate":         "Likely Legitimate",
    "inconclusive":              "Inconclusive",
}


@dataclass
class ScoringResult:
    risk_score: int
    risk_level: str
    classification: str       # internal code (e.g. "phishing")
    classification_label: str  # display label (e.g. "Phishing")
    summary: str
    recommended_actions: list
    score_explanation: str


def _risk_level(score: int) -> str:
    for threshold, label in RISK_LEVELS:
        if score > threshold:
            return label
    return "Low"


def _ml_is_confident(ml_prediction: str | None, ml_confidence: float | None) -> bool:
    return (
        ml_prediction is not None
        and ml_confidence is not None
        and ml_confidence >= ML_CONFIDENCE_THRESHOLD
    )


def _classify(
    score: int,
    risk_level: str,
    findings: list,
    ml_prediction: str | None,
    ml_confidence: float | None,
) -> str:
    """Return the internal classification code."""
    categories = {f.category for f in findings}
    finding_texts = " ".join(f.finding.lower() + " " + f.evidence.lower() for f in findings)

    has_bec = "BEC Analysis" in categories
    has_credential = any("credential" in f.finding.lower() for f in findings)
    has_url = "URL Analysis" in categories
    has_payment = any(
        "payment" in f.finding.lower() or "gift card" in f.finding.lower()
        for f in findings
    )
    ml_confident = _ml_is_confident(ml_prediction, ml_confidence)

    # Strong BEC signal overrides URL-phishing path
    if has_bec and (has_payment or "secrecy" in finding_texts):
        if risk_level in ("Critical", "High"):
            return "business_email_compromise"

    if risk_level in ("Critical", "High"):
        if has_credential or has_url:
            return "phishing"
        if has_bec:
            return "business_email_compromise"
        if has_payment:
            return "business_email_compromise"

    if risk_level == "Medium":
        # Only let ML break ties when it is confident
        if ml_confident and ml_prediction in (
            "phishing", "business_email_compromise", "spam"
        ):
            return ml_prediction
        if has_credential or has_url:
            return "phishing"
        if has_bec or has_payment:
            return "business_email_compromise"
        return "spam"

    # Low risk: rule-based engine found nothing significant
    # Never let a low-confidence ML result override a clean rule-based scan
    return "likely_legitimate"


def _build_summary(
    score: int,
    risk_level: str,
    classification: str,
    findings: list,
    ml_prediction: str | None,
    ml_confidence: float | None,
) -> str:
    label = CLASSIFICATION_DISPLAY.get(classification, classification)

    if score == 0:
        base = (
            "No suspicious indicators were detected by the rule-based detection engine. "
            "This email appears to be low-risk."
        )
        if ml_prediction and not _ml_is_confident(ml_prediction, ml_confidence):
            base += (
                f" The ML classifier returned '{CLASSIFICATION_DISPLAY.get(ml_prediction, ml_prediction)}' "
                f"with {(ml_confidence or 0)*100:.0f}% confidence, which is below the 65% threshold "
                f"and is treated as inconclusive. The rule-based assessment takes precedence."
            )
        return base

    count = len(findings)
    high_sev = [f for f in findings if f.severity in ("critical", "high")]
    top_categories = list({f.category for f in high_sev})[:3]

    severity_desc = {
        "Critical": "critically suspicious",
        "High":     "highly suspicious",
        "Medium":   "moderately suspicious",
        "Low":      "mildly suspicious",
    }.get(risk_level, "suspicious")

    category_str = ", ".join(top_categories) if top_categories else "general content"

    summary = (
        f"This email is {severity_desc} (risk score: {score}/100, "
        f"{count} finding(s) detected). "
        f"Primary concerns: {category_str}. "
        f"Classification: {label}."
    )
    return summary


def _recommended_actions(classification: str, risk_level: str, findings: list) -> list:
    actions = []

    if classification == "phishing":
        if risk_level in ("Critical", "High"):
            actions.append("Do not click any links or download any attachments in this email.")
            actions.append("Report this email to your security operations team or SOC immediately.")
            actions.append("Do not reply to the email or engage with the sender in any way.")
        actions.append(
            "If you clicked any links or entered credentials, change your passwords immediately "
            "and notify your IT/security team."
        )
        actions.append(
            "Verify the request by navigating directly to the organization's official website "
            "or calling them using a known-good phone number — never use contact details from the email."
        )
        if risk_level in ("Critical", "High"):
            actions.append(
                "Consider blocking the sender domain and submitting URLs to your threat intelligence platform."
            )

    elif classification == "business_email_compromise":
        if risk_level in ("Critical", "High"):
            actions.append("Do not reply to this email or engage with the purported sender.")
            actions.append(
                "Do not process any payment, wire transfer, or bank account change based on this email alone."
            )
        actions.append(
            "Verify the request by calling the alleged sender using a known, pre-established phone number — "
            "not any number provided in this email."
        )
        actions.append(
            "Escalate to your finance team, security operations team, and management before taking any action."
        )
        actions.append(
            "If a wire transfer was already processed, contact your bank immediately and file a report "
            "with the FBI IC3 (ic3.gov)."
        )

    elif classification == "spam":
        actions.append("Mark this email as spam and do not engage with any offers or links.")
        actions.append("No escalation is required unless additional suspicious indicators are present.")
        if risk_level in ("High", "Critical"):
            actions.append(
                "Despite spam classification, elevated indicators were detected — "
                "verify this is not a targeted attack before dismissing."
            )

    else:  # likely_legitimate / inconclusive
        actions.append("No immediate action required based on the current analysis.")
        actions.append("Continue normal caution: verify any unusual requests through a known channel.")
        if risk_level == "Medium":
            actions.append(
                "The email received a moderate risk score. "
                "Verify the sender's identity independently before acting on any requests."
            )

    # Universal additions for gift card requests
    has_gift_card = any("gift card" in f.finding.lower() for f in findings)
    if has_gift_card:
        actions.append(
            "IMPORTANT: No legitimate organization requests gift card payments via email. "
            "This is a universally recognized fraud indicator — do not purchase gift cards."
        )

    return actions


def calculate_risk_score(
    findings: list,
    ml_prediction: str | None = None,
    ml_confidence: float | None = None,
) -> ScoringResult:
    raw_score = sum(SEVERITY_WEIGHTS.get(f.severity.lower(), 0) for f in findings)
    score = min(raw_score, 100)

    # ML boost: only when model is very confident AND rule score is borderline
    if _ml_is_confident(ml_prediction, ml_confidence) and (ml_confidence or 0) >= 0.80:
        if ml_prediction in ("phishing", "business_email_compromise") and score < 50:
            score = min(score + 10, 100)

    risk_level = _risk_level(score)
    classification = _classify(score, risk_level, findings, ml_prediction, ml_confidence)
    classification_label = CLASSIFICATION_DISPLAY.get(classification, classification)
    summary = _build_summary(score, risk_level, classification, findings, ml_prediction, ml_confidence)
    actions = _recommended_actions(classification, risk_level, findings)

    # Plain-English score breakdown
    sev_counts: dict = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    parts = [
        f"{v} {k}"
        for k, v in sorted(sev_counts.items(), key=lambda x: -SEVERITY_WEIGHTS.get(x[0], 0))
    ]
    score_explanation = (
        f"Score of {score}/100 derived from {len(findings)} finding(s): "
        + (", ".join(parts) if parts else "no weighted findings")
        + f". Risk level: {risk_level}."
    )

    return ScoringResult(
        risk_score=score,
        risk_level=risk_level,
        classification=classification,
        classification_label=classification_label,
        summary=summary,
        recommended_actions=actions,
        score_explanation=score_explanation,
    )
