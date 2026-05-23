# System Architecture — PhishGuard AI

## Overview

PhishGuard AI is a full-stack, containerized web application built on a
**defense-in-depth** analysis pipeline. The system accepts raw email content,
runs it through a multi-stage detection engine, and returns a structured risk
assessment with a SOC-grade report.

```
┌─────────────────────────────────────────────────────────┐
│                    Browser Client                       │
│           React + Vite + Tailwind CSS                   │
└───────────────────────┬─────────────────────────────────┘
                        │ HTTP/REST (JSON)
                        ▼
┌─────────────────────────────────────────────────────────┐
│                  FastAPI Backend                        │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │              Email Parser                        │   │
│  │  RFC-2822 / regex fallback / HTML body strip     │   │
│  └─────────────────────┬───────────────────────────┘   │
│                        │ ParsedEmail dataclass           │
│         ┌──────────────┼──────────────┐                 │
│         ▼              ▼              ▼                  │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐          │
│  │  Header    │ │   URL      │ │  Content   │          │
│  │  Analyzer  │ │  Analyzer  │ │  Analyzer  │          │
│  └─────┬──────┘ └─────┬──────┘ └─────┬──────┘          │
│        └──────────────┼──────────────┘                  │
│                       │ findings[]                       │
│                       ▼                                  │
│  ┌─────────────────────────────────────────────────┐   │
│  │              ML Classifier                       │   │
│  │        TF-IDF + LinearSVC + Calibration          │   │
│  └─────────────────────┬───────────────────────────┘   │
│                        │ MLResult                        │
│                       ▼                                  │
│  ┌─────────────────────────────────────────────────┐   │
│  │             Risk Scoring Engine                  │   │
│  │  Weighted severity aggregation + classification  │   │
│  └─────────────────────┬───────────────────────────┘   │
│                        │ ScoringResult                   │
│                       ▼                                  │
│  ┌─────────────────────────────────────────────────┐   │
│  │            Report Generator                      │   │
│  │         SOC-format plain-text report             │   │
│  └─────────────────────┬───────────────────────────┘   │
│                        │                                 │
│                       ▼                                  │
│  ┌─────────────────────────────────────────────────┐   │
│  │              SQLite + SQLAlchemy                 │   │
│  │            Persistent analysis history           │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

## Component Responsibilities

### Email Parser (`services/email_parser.py`)
- Attempts Python stdlib `email.message_from_string()` for full RFC-2822 emails
- Falls back to regex-based header extraction for pasted body text
- Extracts: sender, reply-to, recipient, subject, date, body, URLs, domains
- Never fetches or resolves any extracted URLs

### Header Analyzer (`services/header_analyzer.py`)
- Sender ↔ Reply-To domain mismatch detection
- Free email provider identification
- Urgency language in subject lines

### URL Analyzer (`services/url_analyzer.py`)
- 100% structural/lexical — no HTTP requests are made
- Detects: HTTP-only, IP-as-hostname, URL shorteners, punycode, excessive
  subdomains, suspicious keywords, brand impersonation, lookalike domains

### Content Analyzer (`services/content_analyzer.py`)
- Urgency, threat, and pressure language pattern matching
- Credential harvesting language detection
- Payment/wire transfer/gift card request detection
- BEC-specific pattern detection (CEO/CFO impersonation, secrecy requests)
- MFA reset language, generic greetings

### ML Classifier (`services/ml_classifier.py`)
- TF-IDF (n-grams 1-2, 10k features) + CalibratedClassifierCV(LinearSVC)
- Trained on 70 synthetic labeled samples (phishing / BEC / spam / legitimate)
- Model persisted to disk after first training run
- Returns prediction label + calibrated confidence probability
- Supporting role only — does not override rule-based findings

### Risk Scoring Engine (`services/risk_scoring.py`)
- Aggregates findings: critical=+30, high=+20, medium=+10, low=+5
- Caps at 100; applies optional ML confidence nudge for borderline scores
- Derives risk level: Critical (76-100), High (51-75), Medium (21-50), Low (0-20)
- Derives classification: phishing / business_email_compromise / spam / likely_legitimate
- Generates natural-language summary and recommended actions list

### Report Generator (`services/report_generator.py`)
- Produces a structured SOC-analyst-ready plain-text report
- Sections: Executive Summary, Email Metadata, ML Analysis, Detection Findings,
  Recommended Actions, Analyst Notes (for human completion)

## Data Flow

```
POST /analyze
  → input validation (Pydantic, size limit)
  → email_parser.parse_email()
  → [header_analyzer, url_analyzer, content_analyzer] in sequence
  → ml_classifier.classify_email()
  → risk_scoring.calculate_risk_score()
  → report_generator.generate_report()
  → persist to SQLite
  → return AnalyzeResponse JSON
```

## Security Design Decisions

| Decision | Rationale |
|----------|-----------|
| No URL fetching | Prevents SSRF, protects analyst machine |
| Non-root Docker user | Reduces container escape blast radius |
| Pydantic input validation | Prevents oversized inputs, null bytes |
| Output HTML-escaping | Prevents XSS in frontend display |
| SQLite with SQLAlchemy ORM | Parameterized queries prevent SQL injection |
| CORS restricted origins | Prevents cross-origin API abuse |
| 500KB input cap | Prevents memory exhaustion attacks |
| CSP header on frontend | Mitigates XSS and code injection |
