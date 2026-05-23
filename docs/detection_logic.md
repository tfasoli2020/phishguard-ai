# Detection Logic — PhishGuard AI

## Rule-Based Detection

PhishGuard AI uses a three-stage rule-based detection pipeline covering header
analysis, URL analysis, and body content analysis.

---

## Stage 1: Header Analysis

| Rule | Severity | Indicator |
|------|----------|-----------|
| Sender ↔ Reply-To domain mismatch | High | Reply-To redirects to attacker-controlled domain |
| Free email provider (From) | Medium | Gmail/Yahoo used for business-like request |
| Free email provider (Reply-To) | High | Replies route to consumer account |
| Missing From header | Medium | Anonymized or malformed sender |
| Subject contains urgency language | Medium | Psychological pressure tactic |
| Subject is ALL CAPS | Low | Spam/phishing signal |

**Why header analysis matters:** BEC and spear-phishing attacks frequently use
lookalike display names while hiding malicious Reply-To addresses. A sender
of `"PayPal Security" <noreply@paypa1.evil.com>` with Reply-To pointing to
Gmail is a textbook BEC/phishing pattern.

---

## Stage 2: URL Analysis

All analysis is **structural and lexical**. No URLs are fetched.

| Rule | Severity | Detection Method |
|------|----------|-----------------|
| HTTP (no TLS) | Medium | URL scheme check |
| IP address as hostname | High | Regex `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` |
| URL shortener | High | Domain allowlist (bit.ly, tinyurl, etc.) |
| Excessive subdomains (≥4) | Medium | tldextract subdomain count |
| Punycode / IDN homograph | High | `xn--` prefix detection |
| Suspicious keywords | Medium | Keyword set: login, verify, secure, etc. |
| Brand impersonation (subdomain) | Critical | Brand name in subdomain ≠ registered domain |
| Lookalike domain | High | Brand name in registered domain core |
| Long complex URL (evasion) | Low | Length + query parameter count |

**Homograph example:**
`https://xn--pple-43d.com` renders as `https://аpple.com` using Cyrillic 'а'.

**Brand impersonation example:**
`http://secure-paypal.com.login-verify.net/` — registered domain is
`login-verify.net`, not `paypal.com`.

---

## Stage 3: Content Analysis

| Rule | Severity | Pattern Examples |
|------|----------|-----------------|
| Multiple urgency phrases (≥2) | High | "urgent", "act now", "expires in 24 hours" |
| Single urgency phrase | Medium | Any urgency match |
| Threatening language | High | "legal action", "terminated", "suspended" |
| Credential harvesting language | Critical | "verify your account", "enter your password" |
| Multiple payment indicators (≥2) | Critical | "wire transfer" + "invoice due" |
| Single payment indicator | High | "wire transfer", "gift card", "ACH" |
| BEC indicators (≥3) | Critical | CEO language + secrecy + payment |
| BEC indicators (1-2) | High | "are you available", "keep this confidential" |
| Secrecy request | High | "don't tell anyone", "keep this between us" |
| Generic greeting | Low | "Dear Customer", "To Whom It May Concern" |
| MFA / password reset language | High | "reset your password", "one-time code" |
| Gift card request | Critical | "gift card" (any context) |
| Non-standard phrasing | Low | "kindly do the needful", "revert back" |

---

## Risk Scoring Model

### Weight Table

| Severity | Points |
|----------|--------|
| Critical | +30 |
| High | +20 |
| Medium | +10 |
| Low | +5 |
| Info | +0 |

Score is capped at **100**.

### Risk Level Thresholds

| Score Range | Risk Level |
|-------------|------------|
| 76–100 | Critical |
| 51–75 | High |
| 21–50 | Medium |
| 0–20 | Low |

### ML Confidence Nudge

When the ML model is ≥80% confident in a phishing or BEC classification AND
the rule-based score is below 50 (borderline), the score receives a +10 point
boost. This allows the ML to break ties on ambiguous emails while keeping the
rule-based system authoritative for clear-cut cases.

---

## Classification Logic

```
if (risk_level ∈ {Critical, High}) AND (has_credential_findings OR has_url_findings):
    → "phishing"

elif (risk_level ∈ {Critical, High}) AND has_bec_findings:
    → "business_email_compromise"

elif risk_level == "Medium":
    if ml_confidence ≥ 0.65:
        → ml_prediction
    elif has_credential OR has_url:
        → "phishing"
    elif has_bec OR has_payment:
        → "business_email_compromise"
    else:
        → "spam"

else:
    → "likely_legitimate"
```

---

## Known Limitations

1. **No attachment analysis** — PhishGuard AI does not process file attachments.
2. **No link following** — URLs are analyzed structurally; malicious pages
   behind benign-looking URLs will not be detected.
3. **Small ML training corpus** — The baseline ML model was trained on 70
   synthetic samples. False positives and negatives are expected.
4. **No DKIM/SPF validation** — Email authentication headers (DKIM, SPF, DMARC)
   are not validated because they require DNS resolution.
5. **Language support** — Pattern matching is English-focused.
6. **No real-time threat intel** — Domains are not checked against live
   blocklists (VirusTotal, SURBL, etc.) by design.
