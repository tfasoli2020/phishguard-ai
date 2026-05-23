# PhishGuard AI — AI-Powered Phishing Email Triage System

> **A full-stack defensive security application for automated phishing and
> Business Email Compromise (BEC) detection, risk scoring, and SOC-grade
> analyst reporting.**

---

## Security & Ethical Disclaimer

This is a **defensive security education and portfolio project**. It is designed
to help detect and explain phishing and social engineering indicators.

- No URLs are fetched, executed, or resolved
- No real email content was used in development or training
- All sample emails are 100% synthetic
- This tool does not generate phishing content
- Do not submit emails containing sensitive personal data
- Not intended for production use without additional hardening

---

## Problem Statement

Phishing and Business Email Compromise (BEC) are the leading causes of
organizational security breaches. The FBI's IC3 2023 report identified BEC alone
as responsible for over $2.9 billion in reported losses. Security Operations
Center (SOC) analysts manually triage hundreds of suspicious emails per week,
a time-consuming and cognitively demanding process.

PhishGuard AI provides automated first-pass triage that:
- Surfaces specific indicators with evidence and severity ratings
- Explains *why* an email is suspicious in plain English
- Generates a structured analyst report suitable for incident documentation
- Maintains a searchable history of prior analyses

---

## Why This Project Matters

### Government & Public Sector Use Case
Federal agencies, state governments, and defense contractors are prime targets
for spear-phishing and BEC attacks. Tools like PhishGuard AI align with:

- **NIST Cybersecurity Framework (CSF)** — Detect function: DE.CM-3
  (monitoring for personnel activity to detect cybersecurity events)
- **CISA Phishing Guidance** — Automated indicator detection supports
  CISA's recommended layered email security approach
- **FISMA compliance support** — Supports documentation requirements for
  incident detection and response

### Demonstrated Skills for Government Technology Roles
- Defensive security tooling and threat detection logic
- Full-stack application development (Python/React)
- AI/ML integration in a security context
- DevSecOps: automated security scanning, containerization, CI/CD
- Threat modeling and security documentation

---

## Features

| Feature | Description |
|---------|-------------|
| Multi-stage detection | Header, URL, and content analysis in three independent stages |
| 40+ detection rules | Covering phishing, BEC, credential harvesting, payment fraud |
| ML classification | TF-IDF + LinearSVC classifier (phishing/BEC/spam/legitimate) |
| ML confidence thresholding | Predictions below 65% confidence shown as "Inconclusive" — prevents false alarms |
| 0–100 risk score | Severity-weighted scoring with plain-English explanation |
| SOC report generation | Downloadable structured analyst report (PG-XXXXXX format) |
| Analysis history | Persistent SQLite storage with search and delete |
| Sample emails | 5 synthetic samples (phishing, BEC, spam, legitimate, low-confidence marketing) |
| Docker deployment | Full-stack docker-compose in one command |
| CI/CD pipeline | GitHub Actions: tests + Bandit + pip-audit + build |

---

## Tech Stack

### Backend
| Technology | Purpose |
|-----------|---------|
| Python 3.9+ | Runtime |
| FastAPI | REST API framework |
| Pydantic v2 | Input validation and schemas |
| SQLAlchemy | ORM for SQLite |
| scikit-learn | ML classification (TF-IDF + LinearSVC) |
| BeautifulSoup4 | HTML email body extraction |
| tldextract | Accurate domain/subdomain parsing |

### Frontend
| Technology | Purpose |
|-----------|---------|
| React 18 | UI framework |
| Vite | Build tool and dev server |
| Tailwind CSS | Utility-first styling |
| Axios | API client |
| Recharts | Risk score gauge visualization |

### DevOps
| Technology | Purpose |
|-----------|---------|
| Docker + Docker Compose | Containerization |
| GitHub Actions | CI/CD pipeline |
| Bandit | Python SAST security scanning |
| pip-audit | Dependency CVE scanning |
| ESLint | Frontend code quality |

---

## Architecture

```
Browser (React)  →  FastAPI  →  Email Parser
                              →  Header Analyzer  ─┐
                              →  URL Analyzer      ─┼→  Risk Scoring  →  Report  →  SQLite
                              →  Content Analyzer  ─┘
                              →  ML Classifier     ─┘
```

See [docs/architecture.md](docs/architecture.md) for the full system diagram.

---

## Getting Started

### Prerequisites
- Docker and Docker Compose (recommended)
- OR: Python 3.12+ and Node.js 20+ for local development

### Run with Docker (recommended)

```bash
git clone <your-repo-url>
cd phishguard-ai

cp .env.example .env

docker compose up --build
```

- Frontend: [http://localhost:3000](http://localhost:3000)
- Backend API: [http://localhost:8000](http://localhost:8000)
- API Docs: [http://localhost:8000/docs](http://localhost:8000/docs)

### Local Development (without Docker)

**Backend:**
```bash
cd backend
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt

uvicorn app.main:app --reload --port 8000
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

Frontend runs at [http://localhost:5173](http://localhost:5173).

---

## API Documentation

### POST /analyze

Analyzes a suspicious email.

**Request:**
```json
{
  "email_text": "From: attacker@evil.com\nSubject: Urgent...\n\nClick here: http://phish.net"
}
```

**Response:**
```json
{
  "analysis_id": 1,
  "classification": "phishing",
  "classification_label": "Phishing",
  "risk_score": 75,
  "risk_level": "High",
  "summary": "This email is highly suspicious (risk score: 75/100, 4 finding(s) detected)...",
  "email_metadata": {
    "sender": "attacker@evil.com",
    "reply_to": "",
    "recipient": "",
    "subject": "Urgent",
    "date": "",
    "domains": ["phish.net"],
    "urls": ["http://phish.net"]
  },
  "ml_prediction": "phishing",
  "ml_confidence": 0.84,
  "findings": [
    {
      "category": "URL Analysis",
      "severity": "medium",
      "finding": "URL uses unencrypted HTTP instead of HTTPS.",
      "evidence": "http://phish.net",
      "recommendation": "Legitimate services use HTTPS..."
    }
  ],
  "recommended_actions": [
    "Do not click any links or download any attachments in this email.",
    "Report this email to your security operations team immediately."
  ],
  "report": "======== PHISHGUARD AI — SOC ANALYST REPORT ..."
}
```

### GET /health
Returns API and ML model status.

### GET /history
Returns the 50 most recent analyses (configurable via `?limit=N`).

### GET /history/{id}
Returns full detail for a specific analysis.

### DELETE /history/{id}
Deletes a specific analysis record.

---

## Running Tests

```bash
cd backend
pip install -r requirements.txt
pytest tests/ -v
```

**Test coverage includes (55 tests):**
- Email parser: headers, body, URL extraction, quoted display-name sender, preamble handling, deduplication
- URL analyzer: HTTP detection, IP-hosted URLs, shorteners, punycode, brand impersonation
- Risk scoring: thresholds, capping, classification labels, ML confidence thresholding, ML score nudge
- API integration: analyze, history CRUD, validation, classification_label field propagation

---

## Sample Analysis Output

Running the included phishing sample through the API produces:

```
Classification : PHISHING
Risk Score     : 75/100
Risk Level     : HIGH

Findings:
  [Header Analysis]
    [HIGH] Sender domain and Reply-To domain do not match.
      Evidence: From domain: paypa1-verify.evil.net | Reply-To domain: attacker.com

  [URL Analysis]
    [CRITICAL] URL appears to impersonate a known brand in a subdomain or path.
      Evidence: http://paypa1-secure.verify-account.net/confirm [brand match: paypal]

  [Content Analysis]
    [HIGH] Email body contains multiple urgency-inducing phrases.
    [CRITICAL] Email contains credential harvesting language.
```

---

## Project Structure

```
phishguard-ai/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI app entry point
│   │   ├── config.py            # Settings (pydantic-settings)
│   │   ├── database.py          # SQLAlchemy engine + session
│   │   ├── models/              # ORM model + Pydantic schemas
│   │   ├── services/            # Core detection pipeline
│   │   │   ├── email_parser.py
│   │   │   ├── header_analyzer.py
│   │   │   ├── url_analyzer.py
│   │   │   ├── content_analyzer.py
│   │   │   ├── risk_scoring.py
│   │   │   ├── ml_classifier.py
│   │   │   └── report_generator.py
│   │   ├── routes/              # FastAPI routers
│   │   └── utils/               # Regex patterns, security helpers
│   └── tests/                   # pytest test suite
├── frontend/
│   └── src/
│       ├── components/          # React dashboard components
│       └── api/                 # Axios API client
├── data/sample_emails/          # Synthetic test emails
├── docs/                        # Architecture, threat model, SOC workflow
└── .github/workflows/ci.yml     # GitHub Actions CI/CD
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/architecture.md](docs/architecture.md) | System architecture and component design |
| [docs/detection_logic.md](docs/detection_logic.md) | Rule-based detection and risk scoring |
| [docs/threat_model.md](docs/threat_model.md) | Security threat model for the tool itself |
| [docs/soc_workflow.md](docs/soc_workflow.md) | How a SOC analyst uses this tool |
| [docs/resume_bullets.md](docs/resume_bullets.md) | Resume bullets for this project |

---

## Classifications

| Code | Display Label | Description |
|------|--------------|-------------|
| `phishing` | Phishing | Credential harvesting or malicious link email |
| `business_email_compromise` | Business Email Compromise | CEO/vendor impersonation, wire fraud |
| `spam` | Spam | Unsolicited bulk/promotional email |
| `likely_legitimate` | Likely Legitimate | No significant threat indicators found |
| `inconclusive` | Inconclusive | ML confidence below 65% threshold; rule-based engine is authoritative |

### ML Confidence Thresholding

The ML classifier returns a calibrated confidence score (0–1.0) alongside its prediction.
Predictions below the **65% confidence threshold** are surfaced to the user as **"Inconclusive"**
rather than the raw model label. This prevents alarming analysts when the model is uncertain,
particularly when the rule-based engine independently found zero indicators.

The raw ML prediction is still passed to the risk scoring engine (which applies the same threshold
before using it in classification), so the threshold is enforced consistently end-to-end.

---

## Limitations

1. No attachment scanning — file-based payloads are not analyzed
2. No URL fetching — malicious pages behind benign-looking links are not detected
3. No DKIM/SPF validation — email authentication not verified
4. ML model trained on 70 synthetic samples — expect false positives/negatives
5. English-language pattern matching only
6. No real-time threat intelligence integration (VirusTotal, SURBL, etc.)

---

## Future Improvements

- [ ] DKIM/SPF/DMARC header parsing and validation
- [ ] VirusTotal API integration for URL reputation (optional, requires API key)
- [ ] Larger, more diverse ML training corpus
- [ ] MITRE ATT&CK technique tagging on findings
- [ ] Email file attachment type detection (without execution)
- [ ] Multi-user authentication and role-based access
- [ ] Export to JSON/CSV for SIEM ingestion
- [ ] Slack/Teams webhook notification on critical findings

---

## License

MIT License — see [LICENSE](LICENSE).

---

*PhishGuard AI is a defensive security portfolio project. It is not affiliated
with any government agency, law enforcement body, or commercial security vendor.*
