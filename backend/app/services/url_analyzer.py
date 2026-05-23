"""
Analyzes URLs extracted from the email for phishing indicators.
No URLs are fetched — all analysis is structural/lexical.
"""
from dataclasses import dataclass
from urllib.parse import urlparse
import re

import tldextract

from app.utils.regex_patterns import (
    RE_IP_URL,
    RE_PUNYCODE,
    RE_EXCESSIVE_SUBDOMAINS,
    URL_SHORTENER_DOMAINS,
    SUSPICIOUS_URL_KEYWORDS,
    IMPERSONATED_BRANDS,
)


@dataclass
class Finding:
    category: str
    severity: str
    finding: str
    evidence: str
    recommendation: str


def _registered_domain(url: str) -> str:
    try:
        parsed = urlparse(url if url.startswith("http") else f"http://{url}")
        ext = tldextract.extract(parsed.hostname or "")
        return f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ext.domain.lower()
    except Exception:
        return ""


def _hostname(url: str) -> str:
    try:
        parsed = urlparse(url if url.startswith("http") else f"http://{url}")
        return (parsed.hostname or "").lower()
    except Exception:
        return ""


def _subdomain_count(url: str) -> int:
    try:
        parsed = urlparse(url if url.startswith("http") else f"http://{url}")
        ext = tldextract.extract(parsed.hostname or "")
        if not ext.subdomain:
            return 0
        return len(ext.subdomain.split("."))
    except Exception:
        return 0


def analyze_urls(urls: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    seen_issues: set[str] = set()  # deduplicate same finding for different URLs

    for url in urls:
        host = _hostname(url)
        reg_domain = _registered_domain(url)

        # ── HTTP (no TLS) ─────────────────────────────────────────────────
        if url.lower().startswith("http://"):
            key = "http_no_tls"
            if key not in seen_issues:
                seen_issues.add(key)
                findings.append(Finding(
                    category="URL Analysis",
                    severity="medium",
                    finding="URL uses unencrypted HTTP instead of HTTPS.",
                    evidence=url[:300],
                    recommendation=(
                        "Legitimate services use HTTPS. An HTTP link could expose credentials "
                        "in transit and is a common phishing indicator."
                    ),
                ))

        # ── IP address as hostname ────────────────────────────────────────
        if RE_IP_URL.search(url):
            findings.append(Finding(
                category="URL Analysis",
                severity="high",
                finding="URL uses a raw IP address instead of a domain name.",
                evidence=url[:300],
                recommendation=(
                    "Phishing pages frequently use IP addresses to evade domain-based blocklists. "
                    "Do not visit this URL."
                ),
            ))

        # ── URL shortener ─────────────────────────────────────────────────
        if reg_domain in URL_SHORTENER_DOMAINS:
            findings.append(Finding(
                category="URL Analysis",
                severity="high",
                finding="URL uses a known link-shortening service, concealing the real destination.",
                evidence=url[:300],
                recommendation=(
                    "Shortened URLs hide the true destination. Do not click. "
                    "If needed, use a safe URL expander in a sandboxed environment."
                ),
            ))

        # ── Excessive subdomains ──────────────────────────────────────────
        if _subdomain_count(url) >= 4 or RE_EXCESSIVE_SUBDOMAINS.search(url):
            findings.append(Finding(
                category="URL Analysis",
                severity="medium",
                finding="URL contains an unusually high number of subdomains.",
                evidence=url[:300],
                recommendation=(
                    "Attackers add subdomains to make malicious domains appear legitimate "
                    "(e.g., secure.paypal.com.evil.com). Check the registered domain carefully."
                ),
            ))

        # ── Punycode / IDN homograph ──────────────────────────────────────
        if RE_PUNYCODE.search(host):
            findings.append(Finding(
                category="URL Analysis",
                severity="high",
                finding="URL contains punycode (internationalized domain name), possible homograph attack.",
                evidence=url[:300],
                recommendation=(
                    "Punycode domains can visually mimic trusted domains using Unicode characters. "
                    "Verify the domain exactly before interacting."
                ),
            ))

        # ── Suspicious keywords in URL ────────────────────────────────────
        url_lower = url.lower()
        matched_kw = [kw for kw in SUSPICIOUS_URL_KEYWORDS if kw in url_lower]
        if matched_kw:
            findings.append(Finding(
                category="URL Analysis",
                severity="medium",
                finding="URL contains suspicious security-related keywords.",
                evidence=f"{url[:300]} [keywords: {', '.join(matched_kw[:5])}]",
                recommendation=(
                    "Phishing pages often embed words like 'login', 'verify', 'secure' to appear trustworthy. "
                    "Verify the domain belongs to the legitimate service."
                ),
            ))

        # ── Brand impersonation ───────────────────────────────────────────
        matched_brands = [
            b for b in IMPERSONATED_BRANDS
            if b in host and b not in reg_domain.split(".")[0]
        ]
        if matched_brands:
            findings.append(Finding(
                category="URL Analysis",
                severity="critical",
                finding="URL appears to impersonate a known brand in a subdomain or path.",
                evidence=f"{url[:300]} [brand match: {', '.join(matched_brands[:3])}]",
                recommendation=(
                    "This is a strong phishing indicator. The registered domain is not the brand's "
                    "official domain. Do not interact with this link."
                ),
            ))

        # ── Lookalike domain (brand in registered domain with typos) ──────
        for brand in IMPERSONATED_BRANDS:
            domain_core = reg_domain.split(".")[0] if "." in reg_domain else reg_domain
            if brand in domain_core and brand != domain_core:
                findings.append(Finding(
                    category="URL Analysis",
                    severity="high",
                    finding="Registered domain appears to be a lookalike of a known brand.",
                    evidence=f"{url[:300]} [possible lookalike of '{brand}']",
                    recommendation=(
                        "Lookalike domains differ by one character or added words. "
                        "Always navigate directly to official sites rather than clicking email links."
                    ),
                ))
                break

        # ── Long URL with many query parameters (evasion) ────────────────
        if len(url) > 200 and url.count("&") >= 4:
            findings.append(Finding(
                category="URL Analysis",
                severity="low",
                finding="URL is unusually long and complex, possibly for tracking or evasion.",
                evidence=url[:300],
                recommendation=(
                    "Complex URLs can be used to obscure the true destination or bypass filters."
                ),
            ))

    return findings
