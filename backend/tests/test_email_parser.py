"""Tests for email_parser service."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services.email_parser import parse_email


FULL_EMAIL = """\
From: attacker@evil-domain.com
Reply-To: harvest@other-evil.net
To: victim@company.com
Subject: Urgent: Verify your account
Date: Mon, 20 May 2024 10:00:00 +0000

Dear Customer, click here to verify: http://evil.example.com/verify
"""

BODY_ONLY = "Hello, please send $500 in gift cards to this address."

HTML_EMAIL = """\
From: noreply@bank.com
To: user@company.com
Subject: Security Alert

<html><body>
<p>Your account has been <strong>suspended</strong>.</p>
<a href="http://bank-secure.evil.net/login">Click here</a>
</body></html>
"""


def test_parse_full_email_extracts_headers():
    parsed = parse_email(FULL_EMAIL)
    assert parsed.has_headers is True
    assert "attacker@evil-domain.com" in parsed.sender
    assert "harvest@other-evil.net" in parsed.reply_to
    assert "victim@company.com" in parsed.recipient
    assert "Urgent" in parsed.subject


def test_parse_full_email_extracts_url():
    parsed = parse_email(FULL_EMAIL)
    assert any("evil.example.com" in u for u in parsed.urls)


def test_parse_full_email_extracts_domains():
    parsed = parse_email(FULL_EMAIL)
    assert any("evil.example.com" in d or "example.com" in d for d in parsed.domains)


def test_parse_body_only():
    parsed = parse_email(BODY_ONLY)
    assert parsed.body == BODY_ONLY or BODY_ONLY in parsed.body


def test_parse_html_email_extracts_url():
    parsed = parse_email(HTML_EMAIL)
    assert any("evil.net" in u or "bank-secure" in u for u in parsed.urls)


def test_sender_domain_extraction():
    parsed = parse_email(FULL_EMAIL)
    assert parsed.sender_domain == "evil-domain.com"


def test_reply_to_domain_extraction():
    parsed = parse_email(FULL_EMAIL)
    assert parsed.reply_to_domain == "other-evil.net"


def test_empty_body():
    parsed = parse_email("")
    assert parsed.body == "" or parsed.body is not None
    assert parsed.urls == []


def test_url_deduplication():
    email_text = "Visit http://dup.example.com and also http://dup.example.com again."
    parsed = parse_email(email_text)
    url_count = sum(1 for u in parsed.urls if "dup.example.com" in u)
    assert url_count == 1


# ── New tests: quoted display-name sender, BEC format, preamble handling ──────

BEC_EMAIL = """\
From: "Robert Johnson" <ceo.johnson@company-corp.net>
Reply-To: r.johnson.ceo@gmail.com
To: finance@company.com
Subject: Confidential - Urgent Wire Transfer
Date: Fri, 17 May 2024 09:12:00 +0000

Please wire $47,500 immediately. Keep this confidential.
"""

PREAMBLE_EMAIL = """\
--- Forwarded message ---
Please review the email below.

From: sender@example.org
To: analyst@corp.com
Subject: Test message
Date: Mon, 20 May 2024 10:00:00 +0000

Body text here.
"""


def test_quoted_display_name_sender_extracted():
    """Parser must extract the email address from a quoted display-name header."""
    parsed = parse_email(BEC_EMAIL)
    assert parsed.sender is not None
    # Should contain the email address (parser may include display name)
    assert "ceo.johnson@company-corp.net" in parsed.sender


def test_bec_email_no_false_no_sender_finding():
    """A BEC email with a proper From header must NOT produce a 'no visible sender' finding."""
    from app.services.header_analyzer import analyze_headers
    parsed = parse_email(BEC_EMAIL)
    findings = analyze_headers(parsed)
    no_sender_findings = [
        f for f in findings
        if "no visible sender" in f.finding.lower() or "no sender" in f.finding.lower()
    ]
    assert no_sender_findings == [], (
        f"Unexpected 'no sender' finding on BEC email: {no_sender_findings}"
    )


def test_bec_email_reply_to_extracted():
    """Reply-To header must be parsed correctly from BEC-style email."""
    parsed = parse_email(BEC_EMAIL)
    assert parsed.reply_to is not None
    assert "gmail.com" in parsed.reply_to


def test_preamble_before_headers_still_parses():
    """Parser must find headers even when preceded by forwarding/preamble text."""
    parsed = parse_email(PREAMBLE_EMAIL)
    assert parsed.sender is not None
    assert "example.org" in parsed.sender
    assert parsed.subject is not None
    assert "Test" in parsed.subject
