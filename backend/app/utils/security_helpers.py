import re
import html
from urllib.parse import urlparse


_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_NULL_BYTE = re.compile(r"\x00")


def sanitize_text(value: str) -> str:
    """Strip null bytes and non-printable control characters, then HTML-escape."""
    if not isinstance(value, str):
        return ""
    cleaned = _NULL_BYTE.sub("", value)
    cleaned = _CONTROL_CHARS.sub("", cleaned)
    return html.escape(cleaned, quote=True)


def is_safe_url_to_display(url: str) -> bool:
    """
    Returns True only if the URL scheme is http or https.
    We never fetch URLs; this gate is purely for display classification.
    """
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https")
    except Exception:
        return False


def truncate(value: str, max_len: int = 2048) -> str:
    if len(value) <= max_len:
        return value
    return value[:max_len] + " … [truncated]"
