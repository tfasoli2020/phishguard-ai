"""
Parses raw email text.

Handles three input types:
1. Full RFC-2822 email with MIME structure (stdlib parser)
2. Simple pasted email where headers appear at the top followed by a blank line
3. Emails with preamble text before the headers (e.g. forwarding banners)

Strategy: stdlib parser first, then a header-block scanner that finds the first
contiguous block of "Header: value" lines anywhere in the text and uses those
to fill in any fields the stdlib parser missed. Headers are NEVER extracted
from body text (only from the contiguous block before the first blank line
following the first recognized header).
"""
from __future__ import annotations

import re
import email
from email import policy
from dataclasses import dataclass, field
from urllib.parse import urlparse

import tldextract
from bs4 import BeautifulSoup

from app.utils.regex_patterns import RE_EMAIL_IN_HEADER, RE_URL
from app.utils.security_helpers import truncate


# Matches a valid RFC-2822-like header field line: "Word: value"
_HEADER_LINE_RE = re.compile(r'^([A-Za-z][A-Za-z0-9-]*)\s*:\s*(.+)$')

# Folded header continuation (starts with whitespace)
_FOLD_RE = re.compile(r'^[ \t]+(.+)$')

# Maps normalized header names to canonical field names
_HEADER_FIELD_MAP = {
    'from':       'from',
    'reply-to':   'reply-to',
    'reply to':   'reply-to',   # non-standard but seen in pasted emails
    'to':         'to',
    'subject':    'subject',
    'date':       'date',
}


@dataclass
class ParsedEmail:
    sender: str = ""
    reply_to: str = ""
    recipient: str = ""
    subject: str = ""
    date: str = ""
    body: str = ""
    raw_headers: str = ""
    has_headers: bool = False
    urls: list = field(default_factory=list)
    domains: list = field(default_factory=list)
    sender_domain: str = ""
    reply_to_domain: str = ""


def _extract_domain(email_addr: str) -> str:
    match = RE_EMAIL_IN_HEADER.search(email_addr)
    if match:
        parts = match.group(1).split("@")
        return parts[-1].lower().strip() if len(parts) == 2 else ""
    return ""


def _extract_urls_from_text(text: str) -> list:
    raw = RE_URL.findall(text)
    seen: set = set()
    result = []
    for url in raw:
        url = url.rstrip(".,;:\"')")
        if url not in seen:
            seen.add(url)
            result.append(url)
    return result


def _extract_domains_from_urls(urls: list) -> list:
    seen: set = set()
    domains = []
    for url in urls:
        try:
            parsed = urlparse(url if url.startswith("http") else f"http://{url}")
            hostname = parsed.hostname or ""
            ext = tldextract.extract(hostname)
            registered = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
            if registered and registered not in seen:
                seen.add(registered)
                domains.append(registered)
        except Exception:
            continue
    return domains


def _body_from_message(msg: email.message.Message) -> str:
    """Walk MIME parts and extract the best text body."""
    plain_parts = []
    html_parts = []

    for part in msg.walk():
        ct = part.get_content_type()
        disposition = str(part.get("Content-Disposition", ""))
        if "attachment" in disposition:
            continue
        try:
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            charset = part.get_content_charset() or "utf-8"
            decoded = payload.decode(charset, errors="replace")
        except Exception:
            continue

        if ct == "text/plain":
            plain_parts.append(decoded)
        elif ct == "text/html":
            html_parts.append(decoded)

    if plain_parts:
        return "\n".join(plain_parts)
    if html_parts:
        soup = BeautifulSoup("\n".join(html_parts), "html.parser")
        return soup.get_text(separator="\n")
    return ""


def _scan_header_block(raw_text: str) -> tuple:
    """
    Scan raw_text for the first contiguous block of RFC-2822-like header lines.

    Returns (header_dict, body_text):
    - header_dict: maps canonical field names ('from', 'reply-to', etc.) to values
    - body_text: everything after the blank line that terminates the header block

    Only recognized fields are returned. Extraction stops at the first blank line
    after the first valid header is found, so body text is never mistaken for headers.
    """
    lines = raw_text.splitlines(keepends=False)
    header_start = None

    # Find the first line that looks like a real header
    for i, line in enumerate(lines):
        m = _HEADER_LINE_RE.match(line)
        if m:
            field_key = m.group(1).strip().lower()
            if field_key in _HEADER_FIELD_MAP:
                header_start = i
                break

    if header_start is None:
        return {}, raw_text

    # Collect the contiguous header block
    headers: dict = {}
    current_key = None
    current_val = None
    body_start = len(lines)

    for i in range(header_start, len(lines)):
        line = lines[i]

        if not line.strip():
            # Blank line ends the header block
            body_start = i + 1
            break

        m = _HEADER_LINE_RE.match(line)
        fold_m = _FOLD_RE.match(line)

        if m:
            # Save previous field
            if current_key is not None:
                headers[current_key] = current_val
            raw_key = m.group(1).strip().lower()
            canonical = _HEADER_FIELD_MAP.get(raw_key)
            if canonical:
                current_key = canonical
                current_val = m.group(2).strip()
            else:
                current_key = None
                current_val = None
        elif fold_m and current_key is not None:
            # Folded header continuation
            current_val = (current_val or "") + " " + fold_m.group(1).strip()
        else:
            # Non-header, non-fold line inside header block — stop
            body_start = i
            break
    else:
        body_start = len(lines)

    # Save last field
    if current_key is not None:
        headers[current_key] = current_val

    body_text = "\n".join(lines[body_start:])
    return headers, body_text


def parse_email(raw_text: str) -> ParsedEmail:
    result = ParsedEmail()

    # ── Stage 1: stdlib RFC-2822 parser ──────────────────────────────────────
    # Handles properly structured MIME emails.
    try:
        msg = email.message_from_string(raw_text, policy=policy.compat32)
        from_val = msg.get("From", "")
        to_val = msg.get("To", "")
        subject_val = msg.get("Subject", "")
        date_val = msg.get("Date", "")
        reply_to_val = msg.get("Reply-To", "")

        if any([from_val, to_val, subject_val, date_val]):
            result.has_headers = True
            result.sender = truncate(from_val, 512)
            result.recipient = truncate(to_val, 512)
            result.subject = truncate(subject_val, 1024)
            result.date = truncate(date_val, 256)
            result.reply_to = truncate(reply_to_val, 512)
            result.body = _body_from_message(msg) or raw_text
    except Exception:
        pass

    # ── Stage 2: header-block scanner ────────────────────────────────────────
    # Always run to fill in any missing fields. This handles:
    #   - Emails with preamble/banner text before the headers
    #   - Pasted emails where stdlib found no valid headers
    #   - Cases where stdlib found some headers but missed others
    scanned_headers, scanned_body = _scan_header_block(raw_text)

    if scanned_headers:
        result.has_headers = True

        if not result.sender and scanned_headers.get('from'):
            result.sender = truncate(scanned_headers['from'], 512)

        if not result.reply_to and scanned_headers.get('reply-to'):
            result.reply_to = truncate(scanned_headers['reply-to'], 512)

        if not result.recipient and scanned_headers.get('to'):
            result.recipient = truncate(scanned_headers['to'], 512)

        if not result.subject and scanned_headers.get('subject'):
            result.subject = truncate(scanned_headers['subject'], 1024)

        if not result.date and scanned_headers.get('date'):
            result.date = truncate(scanned_headers['date'], 256)

        # Use scanned body if stdlib gave us nothing useful
        if not result.body or result.body == raw_text:
            result.body = scanned_body or raw_text

    # ── Stage 3: body-only fallback ──────────────────────────────────────────
    if not result.body:
        result.body = raw_text

    # ── URL and domain extraction (full raw text) ─────────────────────────────
    result.urls = _extract_urls_from_text(raw_text)
    result.domains = _extract_domains_from_urls(result.urls)

    # ── Sender/Reply-To domain resolution ────────────────────────────────────
    if result.sender:
        result.sender_domain = _extract_domain(result.sender)
    if result.reply_to:
        result.reply_to_domain = _extract_domain(result.reply_to)

    return result
