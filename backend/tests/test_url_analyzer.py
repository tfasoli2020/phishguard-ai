"""Tests for url_analyzer service."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services.url_analyzer import analyze_urls


def test_http_url_flagged():
    findings = analyze_urls(["http://example.com/login"])
    assert any("HTTP" in f.finding or "unencrypted" in f.finding for f in findings)


def test_https_url_not_flagged_for_http():
    findings = analyze_urls(["https://legitimate.com/page"])
    assert not any("unencrypted" in f.finding for f in findings)


def test_ip_address_url_flagged():
    findings = analyze_urls(["http://192.168.1.1/phish"])
    assert any("IP address" in f.finding for f in findings)


def test_url_shortener_flagged():
    findings = analyze_urls(["https://bit.ly/abc123"])
    assert any("shortening" in f.finding.lower() or "shortener" in f.finding.lower() for f in findings)


def test_brand_impersonation_flagged():
    findings = analyze_urls(["http://secure-paypal.evil-domain.com/verify"])
    assert any("impersonat" in f.finding.lower() or "brand" in f.finding.lower() for f in findings)


def test_suspicious_keyword_in_url():
    findings = analyze_urls(["https://bank-secure-login.example.com/verify"])
    # Should flag suspicious keywords
    assert any("keyword" in f.finding.lower() or "suspicious" in f.finding.lower() for f in findings)


def test_punycode_domain_flagged():
    findings = analyze_urls(["https://xn--pple-43d.com/account"])
    assert any("punycode" in f.finding.lower() for f in findings)


def test_empty_url_list():
    findings = analyze_urls([])
    assert findings == []


def test_multiple_urls_only_http_flagged():
    findings = analyze_urls([
        "https://legit.com/page",
        "http://bad.com/phish",
    ])
    http_findings = [f for f in findings if "unencrypted" in f.finding]
    assert len(http_findings) == 1  # deduplicated, one finding for HTTP


def test_severity_levels_are_valid():
    findings = analyze_urls(["http://192.168.0.1/fake", "https://bit.ly/xxx"])
    valid_severities = {"critical", "high", "medium", "low", "info"}
    for f in findings:
        assert f.severity.lower() in valid_severities
