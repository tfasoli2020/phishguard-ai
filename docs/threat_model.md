# Threat Model — PhishGuard AI

## Threats the Tool Helps Identify

### 1. Phishing Attacks
**What it is:** Fraudulent emails that impersonate trusted organizations to steal
credentials, financial data, or personally identifiable information.

**How PhishGuard AI detects it:**
- Lookalike and impersonation domains in URLs
- Credential harvesting language in body content
- Reply-To header mismatch
- Urgency and threat language designed to bypass rational decision-making

**Real-world impact:** The FBI's IC3 2023 report cited phishing as the #1
reported cybercrime type. A single successful credential phish can lead to
network intrusion, ransomware deployment, and data breaches.

---

### 2. Business Email Compromise (BEC)
**What it is:** Targeted fraud where attackers impersonate executives, vendors,
or trusted partners to authorize fraudulent wire transfers or gift card purchases.

**How PhishGuard AI detects it:**
- CEO/CFO impersonation language
- Wire transfer, ACH, and gift card request patterns
- Requests for secrecy ("don't tell anyone")
- Phone avoidance tactics ("I'm in a meeting, don't call")
- Vendor banking detail change requests
- Free email provider used as Reply-To

**Real-world impact:** BEC caused over $2.9 billion in losses in 2023 (FBI IC3).
It is the highest-dollar cybercrime category, targeting finance, government, and
healthcare organizations.

---

### 3. Credential Harvesting
**What it is:** Fake login pages linked from phishing emails that capture
usernames, passwords, and MFA tokens.

**How PhishGuard AI detects it:**
- "Verify your account" / "Enter your credentials" language
- Suspicious or impersonating URLs (IP-hosted, HTTP-only, brand lookalikes)
- MFA reset request language

---

### 4. Spam and Malicious Marketing
**What it is:** Unsolicited bulk email used for fraud, scams, or delivering
malware via links or attachments.

**How PhishGuard AI detects it:**
- Generic greetings and impersonal mass-email phrasing
- Too-good-to-be-true prize / work-from-home offers
- URL shorteners that obscure final destinations

---

## Threats the Tool Itself Must Avoid

### SSRF (Server-Side Request Forgery)
**Risk:** If PhishGuard AI fetched URLs extracted from analyzed emails, an
attacker could submit an email containing `http://169.254.169.254/` (AWS
metadata endpoint) or internal service URLs to probe the infrastructure.

**Mitigation:** The tool **never fetches any URL**. All URL analysis is
structural and lexical only. This is a hard architectural constraint.

---

### Stored XSS
**Risk:** Malicious email content stored in the database and later rendered
in the frontend could execute JavaScript.

**Mitigation:**
- Backend sanitizes all text with `html.escape()` before storage and API output
- Frontend uses React's JSX (which escapes by default); no use of `dangerouslySetInnerHTML`
- Content Security Policy header on the frontend restricts script execution

---

### SQL Injection
**Risk:** Raw email content passed directly into SQL queries could manipulate
the database.

**Mitigation:** SQLAlchemy ORM with parameterized queries is used exclusively.
No raw SQL string concatenation.

---

### Denial of Service (Input Exhaustion)
**Risk:** A 10MB email body containing thousands of URLs or regex-triggering
content could cause excessive CPU/memory usage.

**Mitigation:**
- Hard 500KB input size cap enforced at both Pydantic schema level and route level
- URL list truncated to 50 entries for storage
- Evidence strings truncated to 500 characters

---

### Path Traversal / Arbitrary File Read
**Risk:** User-supplied email content containing file paths could be
misinterpreted if the app ever reads from disk based on email content.

**Mitigation:** The application never reads files based on email content. The
only disk operations are ML model load/save and SQLite database writes.

---

### Secret Exposure
**Risk:** API keys, database credentials, or internal addresses could be
accidentally committed to the repository.

**Mitigation:**
- `.env` is in `.gitignore`
- `.env.example` contains only placeholder values
- No third-party API keys required — the application is fully self-contained

---

## Out-of-Scope Threats (Not Addressed)

| Threat | Reason Not in Scope |
|--------|-------------------|
| Malicious attachments / macros | Attachments are not processed |
| Zero-day phishing pages | URLs are not fetched or rendered |
| Sophisticated homograph attacks | Punycode detected, but Unicode rendering is browser-dependent |
| Account takeover via the app itself | No user authentication system exists |
| Multi-tenant data isolation | Single-user local deployment model |
