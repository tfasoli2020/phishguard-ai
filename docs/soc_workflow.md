# SOC Analyst Workflow — PhishGuard AI

## Overview

PhishGuard AI is designed as a **Tier 1 / Tier 2 SOC triage assistance tool**.
It does not make final decisions — it surfaces and explains indicators so that
a human analyst can make an informed determination faster.

---

## Typical Workflow

### Step 1 — Email Received
A user or automated rule flags an email as potentially suspicious and either:
- Forwards the raw email to the analyst, or
- Copies the email content (headers + body) from their mail client

### Step 2 — Paste into PhishGuard AI
The analyst opens the PhishGuard AI dashboard and pastes the full email content
(including headers if available) into the input panel.

> **Tip:** Always include headers when possible. The `From:`, `Reply-To:`,
> `Received:`, and `Authentication-Results:` headers provide crucial context
> that body-only analysis cannot replicate.

### Step 3 — Review the Risk Score and Classification
The Risk Assessment card shows:
- **Risk Score (0–100):** Quantitative threat estimate
- **Risk Level:** Low / Medium / High / Critical
- **Classification:** Phishing / BEC / Spam / Likely Legitimate
- **ML Prediction + Confidence:** Supporting signal from the ML baseline model

> **Critical or High score → Escalate immediately.** Do not wait for full
> analysis before isolating the email and notifying the user.

### Step 4 — Review Findings by Category
The Detection Findings panel groups findings into:
- **Header Analysis** — Sender anomalies, Reply-To mismatches
- **URL Analysis** — Suspicious link structures
- **Content Analysis** — Social engineering language
- **BEC Analysis** — Business Email Compromise indicators

Each finding includes:
- **Severity badge** (Critical / High / Medium / Low)
- **Finding** — What was detected
- **Evidence** — The specific text or URL that triggered the rule
- **Recommendation** — Analyst guidance for this specific finding

### Step 5 — Review URL and Header Detail Panels
- **URL Analysis tab:** All extracted URLs, highlighted if suspicious
- **Headers tab:** Sender, Reply-To, Subject, domains — with mismatch alerts

### Step 6 — Download the SOC Report
Click **SOC Report** tab → **Download .txt** to export a structured analyst
report (Report ID: `PG-XXXXXX`) that can be:
- Attached to a ticketing system (ServiceNow, Jira, etc.)
- Included in an incident report
- Sent to the user's manager as documentation of the analysis

### Step 7 — Complete the Analyst Notes Section
The report includes an "Analyst Notes" section left blank for human completion:
```
6. ANALYST NOTES
  Disposition   : [ ] Confirmed Malicious  [ ] Benign  [ ] Escalated
  Analyst Name  : ___________________________
  Review Date   : ___________________________
```
The analyst records their disposition and any additional context.

### Step 8 — Take Action
Based on the analysis:

| Disposition | Actions |
|-------------|---------|
| **Confirmed Phishing** | Block sender domain, submit URLs to threat intel, notify user, check for similar emails in inbox, reset credentials if clicked |
| **Confirmed BEC** | Alert finance team, verify no transfers were processed, contact purported sender via phone, preserve email for forensics |
| **Spam** | Block sender, add to spam filter, no further escalation unless volume indicates campaign |
| **Likely Legitimate** | Close ticket, advise user on awareness training if appropriate |

---

## Analysis History

All analyses are stored in the **Analysis History** panel. Analysts can:
- Click any prior record to reload the full analysis
- Delete records when no longer needed

---

## Limitations Analysts Should Know

1. **This tool assists — it does not decide.** A High or Critical score does
   not guarantee malicious intent, and a Low score does not guarantee safety.

2. **Headers improve accuracy.** Body-only analysis misses sender/reply-to
   domain mismatches. Always attempt to include headers.

3. **URLs are not verified.** A URL that looks clean structurally may still
   lead to a malicious page. Verify suspicious links in a sandbox.

4. **DKIM/SPF is not validated.** The tool does not verify email authentication
   headers. An email can appear legitimate and still fail DKIM/SPF.

5. **The ML model is baseline.** Trained on 70 synthetic samples. Use the
   ML confidence as a supporting signal, not a primary indicator.

---

## Integration Use Cases

- **SOC Tier 1 Triage:** Rapidly score and document suspicious emails before
  escalating to Tier 2
- **Security Awareness Training:** Show employees why specific emails are
  dangerous using the evidence-based findings
- **Incident Documentation:** Use generated reports as attachments to tickets
- **Tabletop Exercises:** Use BEC and phishing samples to walk through the
  triage process with finance and HR teams
