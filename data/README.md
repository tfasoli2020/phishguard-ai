# Sample Email Data

All files in this directory are **100% synthetic** and created solely for
testing PhishGuard AI. They do not represent real emails, real people, or
real organizations.

## Files

| File | Type | Key Indicators |
|------|------|---------------|
| `phishing_email_1.txt` | Phishing | Lookalike domain, credential harvesting, urgency, Reply-To mismatch |
| `bec_email_1.txt` | BEC | CEO impersonation, wire transfer, secrecy request, phone avoidance |
| `spam_email_1.txt` | Spam | Prize scam, work-from-home fraud, urgency, generic greeting |
| `legitimate_email_1.txt` | Legitimate | HR communication, no suspicious indicators |

## Usage

Load any sample into the PhishGuard AI frontend using the **"Load sample"**
buttons, or submit them directly to the API:

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d "{\"email_text\": \"$(cat phishing_email_1.txt)\"}"
```
