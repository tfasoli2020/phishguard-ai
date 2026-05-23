"""
Analyzes email body content for phishing, BEC, and social-engineering indicators.
"""
from dataclasses import dataclass

from app.services.email_parser import ParsedEmail
from app.utils.regex_patterns import (
    URGENCY_PATTERNS,
    THREAT_PATTERNS,
    CREDENTIAL_PATTERNS,
    PAYMENT_PATTERNS,
    BEC_PATTERNS,
    GENERIC_GREETING_PATTERNS,
    AUTH_RESET_PATTERNS,
)


@dataclass
class Finding:
    category: str
    severity: str
    finding: str
    evidence: str
    recommendation: str


def _first_match(patterns: list, text: str) -> str:
    for p in patterns:
        m = p.search(text)
        if m:
            start = max(0, m.start() - 30)
            end = min(len(text), m.end() + 30)
            return f"…{text[start:end]}…"
    return ""


def _count_matches(patterns: list, text: str) -> int:
    return sum(1 for p in patterns if p.search(text))


def analyze_content(parsed: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    body = parsed.body or ""
    body_lower = body.lower()

    # ── Urgency language ──────────────────────────────────────────────────────
    urgency_count = _count_matches(URGENCY_PATTERNS, body)
    if urgency_count >= 2:
        findings.append(Finding(
            category="Content Analysis",
            severity="high",
            finding="Email body contains multiple urgency-inducing phrases.",
            evidence=_first_match(URGENCY_PATTERNS, body),
            recommendation=(
                "High-urgency language is a key social-engineering tactic designed to bypass "
                "rational decision-making. Pause and verify any request through a separate channel."
            ),
        ))
    elif urgency_count == 1:
        findings.append(Finding(
            category="Content Analysis",
            severity="medium",
            finding="Email body contains urgency language.",
            evidence=_first_match(URGENCY_PATTERNS, body),
            recommendation=(
                "Urgency is a social-engineering tactic. Verify requests independently "
                "before taking action."
            ),
        ))

    # ── Threatening language ──────────────────────────────────────────────────
    threat_count = _count_matches(THREAT_PATTERNS, body)
    if threat_count >= 1:
        findings.append(Finding(
            category="Content Analysis",
            severity="high",
            finding="Email contains threatening language (account suspension, legal action, etc.).",
            evidence=_first_match(THREAT_PATTERNS, body),
            recommendation=(
                "Threats of account termination or legal action are common phishing pressure tactics. "
                "Contact the organization directly through their official website to verify."
            ),
        ))

    # ── Credential harvesting ─────────────────────────────────────────────────
    cred_count = _count_matches(CREDENTIAL_PATTERNS, body)
    if cred_count >= 1:
        findings.append(Finding(
            category="Content Analysis",
            severity="critical",
            finding="Email contains credential harvesting language (verify account, click to login, etc.).",
            evidence=_first_match(CREDENTIAL_PATTERNS, body),
            recommendation=(
                "Never click email links to log in. Navigate directly to the official site. "
                "This email is likely attempting to steal your credentials."
            ),
        ))

    # ── Payment / financial request ───────────────────────────────────────────
    payment_count = _count_matches(PAYMENT_PATTERNS, body)
    if payment_count >= 2:
        findings.append(Finding(
            category="Content Analysis",
            severity="critical",
            finding="Email contains multiple financial transaction request indicators.",
            evidence=_first_match(PAYMENT_PATTERNS, body),
            recommendation=(
                "Wire transfer and gift card requests via email are almost always fraud. "
                "Verify all payment requests through an established, out-of-band communication channel."
            ),
        ))
    elif payment_count == 1:
        findings.append(Finding(
            category="Content Analysis",
            severity="high",
            finding="Email contains a financial transaction or payment request indicator.",
            evidence=_first_match(PAYMENT_PATTERNS, body),
            recommendation=(
                "Verify all payment requests with the requester using a known-good phone number "
                "or in-person before taking any action."
            ),
        ))

    # ── BEC-specific patterns ─────────────────────────────────────────────────
    bec_count = _count_matches(BEC_PATTERNS, body)
    if bec_count >= 3:
        findings.append(Finding(
            category="BEC Analysis",
            severity="critical",
            finding="Email shows strong Business Email Compromise (BEC) indicators.",
            evidence=_first_match(BEC_PATTERNS, body),
            recommendation=(
                "High BEC confidence. Contact the alleged sender via a verified phone number. "
                "Escalate to your security team and do not process any financial requests."
            ),
        ))
    elif bec_count >= 1:
        findings.append(Finding(
            category="BEC Analysis",
            severity="high",
            finding="Email contains Business Email Compromise (BEC) indicators.",
            evidence=_first_match(BEC_PATTERNS, body),
            recommendation=(
                "BEC emails often impersonate executives or trusted vendors. "
                "Verify any unusual requests through a separate, trusted communication channel."
            ),
        ))

    # ── Request for secrecy ───────────────────────────────────────────────────
    import re
    secrecy_patterns = [
        re.compile(p, re.IGNORECASE) for p in [
            r"\bdo not (tell|inform|contact|discuss)\b",
            r"\bkeep (this )(confidential|secret|quiet|between us)\b",
            r"\bdon't mention\b",
            r"\bthis is (confidential|private|sensitive)\b",
        ]
    ]
    if any(p.search(body) for p in secrecy_patterns):
        findings.append(Finding(
            category="BEC Analysis",
            severity="high",
            finding="Email explicitly requests secrecy or asks not to involve others.",
            evidence=_first_match(secrecy_patterns, body),
            recommendation=(
                "Requests for secrecy are a classic social-engineering red flag used in BEC and fraud. "
                "Legitimate business requests do not require confidentiality from your own security team."
            ),
        ))

    # ── Generic / impersonal greeting ────────────────────────────────────────
    body_lines = body.strip().splitlines()
    first_lines = "\n".join(body_lines[:5])
    if any(p.search(first_lines) for p in GENERIC_GREETING_PATTERNS):
        findings.append(Finding(
            category="Content Analysis",
            severity="low",
            finding="Email uses a generic, impersonal greeting.",
            evidence=_first_match(GENERIC_GREETING_PATTERNS, first_lines),
            recommendation=(
                "Legitimate emails from organizations you have a relationship with typically "
                "address you by name. Generic greetings are common in mass phishing campaigns."
            ),
        ))

    # ── MFA / password reset language ────────────────────────────────────────
    if any(p.search(body) for p in AUTH_RESET_PATTERNS):
        findings.append(Finding(
            category="Content Analysis",
            severity="high",
            finding="Email contains MFA or password reset language.",
            evidence=_first_match(AUTH_RESET_PATTERNS, body),
            recommendation=(
                "MFA reset emails are used to bypass two-factor authentication. "
                "Only initiate resets from the official service website, never from an email link."
            ),
        ))

    # ── Gift card request ─────────────────────────────────────────────────────
    gift_card_re = re.compile(r"\bgift card\b", re.IGNORECASE)
    if gift_card_re.search(body):
        findings.append(Finding(
            category="Content Analysis",
            severity="critical",
            finding="Email requests gift cards as a form of payment.",
            evidence=_first_match([gift_card_re], body),
            recommendation=(
                "Gift card requests are a universally recognized fraud indicator. "
                "No legitimate organization requests gift cards as payment. Report this immediately."
            ),
        ))

    # ── Poor grammar / spelling indicators (simple heuristic) ────────────────
    double_space = body.count("  ")
    grammar_patterns = [
        re.compile(p, re.IGNORECASE) for p in [
            r"\bkindly (do|click|provide|revert)\b",
            r"\bdo the needful\b",
            r"\brevert back\b",
            r"\bbelow mentioned\b",
        ]
    ]
    grammar_hits = sum(1 for p in grammar_patterns if p.search(body))
    if grammar_hits >= 2 or double_space > 10:
        findings.append(Finding(
            category="Content Analysis",
            severity="low",
            finding="Email contains non-standard phrasing often associated with phishing campaigns.",
            evidence=_first_match(grammar_patterns, body) if grammar_hits else "Unusual spacing detected",
            recommendation=(
                "Poor grammar and unusual phrasing can indicate a message crafted by a non-native "
                "speaker or generated automatically. Combined with other indicators, treat with caution."
            ),
        ))

    return findings
