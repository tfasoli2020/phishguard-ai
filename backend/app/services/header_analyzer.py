"""
Analyzes email header fields for phishing and BEC indicators.
"""
from dataclasses import dataclass, field

from app.services.email_parser import ParsedEmail
from app.utils.regex_patterns import FREE_EMAIL_PROVIDERS, URGENCY_PATTERNS


@dataclass
class Finding:
    category: str
    severity: str
    finding: str
    evidence: str
    recommendation: str


def analyze_headers(parsed: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []

    # ── Sender / Reply-To domain mismatch ────────────────────────────────────
    if (
        parsed.sender_domain
        and parsed.reply_to_domain
        and parsed.sender_domain.lower() != parsed.reply_to_domain.lower()
    ):
        findings.append(Finding(
            category="Header Analysis",
            severity="high",
            finding="Sender domain and Reply-To domain do not match.",
            evidence=f"From domain: {parsed.sender_domain} | Reply-To domain: {parsed.reply_to_domain}",
            recommendation=(
                "This is a common phishing tactic to redirect replies to an attacker-controlled mailbox. "
                "Do not reply to this email. Verify the sender through a separate trusted channel."
            ),
        ))

    # ── Free email provider used for a seemingly business email ──────────────
    if parsed.sender_domain and parsed.sender_domain.lower() in FREE_EMAIL_PROVIDERS:
        findings.append(Finding(
            category="Header Analysis",
            severity="medium",
            finding="Sender is using a free consumer email provider.",
            evidence=f"Sender domain: {parsed.sender_domain}",
            recommendation=(
                "Legitimate organizations typically send email from their own domain. "
                "Treat any financial, account-related, or executive requests from free providers with suspicion."
            ),
        ))

    # ── Reply-To uses a free email provider ──────────────────────────────────
    if parsed.reply_to_domain and parsed.reply_to_domain.lower() in FREE_EMAIL_PROVIDERS:
        findings.append(Finding(
            category="Header Analysis",
            severity="high",
            finding="Reply-To address uses a free consumer email provider.",
            evidence=f"Reply-To domain: {parsed.reply_to_domain}",
            recommendation=(
                "Replies will be routed to a free account, not a corporate address. "
                "This is a strong BEC and spear-phishing indicator."
            ),
        ))

    # ── Missing or empty sender ───────────────────────────────────────────────
    if not parsed.sender:
        findings.append(Finding(
            category="Header Analysis",
            severity="medium",
            finding="Email has no visible sender (From header is absent or empty).",
            evidence="From: [not present]",
            recommendation=(
                "Legitimate emails always identify the sender. "
                "Treat any email without a From header as highly suspicious."
            ),
        ))

    # ── Subject contains urgency indicators ──────────────────────────────────
    if parsed.subject:
        matched_patterns = [
            p.pattern for p in URGENCY_PATTERNS if p.search(parsed.subject)
        ]
        if matched_patterns:
            findings.append(Finding(
                category="Header Analysis",
                severity="medium",
                finding="Subject line contains urgency language.",
                evidence=f"Subject: {parsed.subject[:200]}",
                recommendation=(
                    "Urgency in subject lines is a psychological pressure tactic. "
                    "Do not act on the email until the request is verified independently."
                ),
            ))

    # ── Subject is ALL CAPS ───────────────────────────────────────────────────
    if parsed.subject and parsed.subject == parsed.subject.upper() and len(parsed.subject) > 5:
        findings.append(Finding(
            category="Header Analysis",
            severity="low",
            finding="Subject line is written entirely in uppercase letters.",
            evidence=f"Subject: {parsed.subject[:200]}",
            recommendation=(
                "ALL-CAPS subjects are associated with spam and phishing campaigns. "
                "Verify the message through a trusted channel."
            ),
        ))

    return findings
