# Resume Bullets — PhishGuard AI

Use these bullets to describe this project on your resume, tailored by role.

---

## General / Technical Bullets

- Designed and built a full-stack email threat triage system using Python, FastAPI,
  React, and SQLite, combining rule-based detection with a TF-IDF/LinearSVC ML
  classifier to classify phishing, BEC, spam, and legitimate emails

- Engineered a multi-stage detection pipeline analyzing email headers, URL structure,
  and body content for 40+ phishing, BEC, and credential harvesting indicators,
  with severity-weighted 0–100 risk scoring and per-classification recommended actions

- Implemented ML confidence thresholding: predictions below 65% are surfaced as
  "Inconclusive" to prevent false alarms when the model is uncertain, while
  high-confidence predictions contribute a calibrated score nudge to borderline cases

- Debugged and fixed a three-stage RFC-2822 email parser to correctly extract
  quoted display-name senders (e.g., `From: "CEO" <ceo@corp.net>`) and handle
  emails with preamble text before headers, eliminating false "no visible sender" findings

- Containerized the full application using Docker and Docker Compose with a
  non-root security posture, health checks, and nginx reverse proxy for
  production-ready deployment

- Established a CI/CD pipeline with GitHub Actions automating pytest (55 tests),
  Bandit static security analysis, pip-audit dependency CVE scanning, and
  frontend ESLint + build on every push

---

## Cybersecurity Analyst / SOC Analyst Focus

- Built PhishGuard AI, a SOC triage tool that analyzes suspicious emails for
  phishing and Business Email Compromise (BEC) indicators, generating
  structured analyst reports with severity-ranked findings and remediation guidance

- Developed detection logic for 40+ indicators across header analysis (Reply-To
  mismatch, free email providers), URL analysis (IP-hosted links, lookalike domains,
  brand impersonation), and content analysis (credential harvesting, wire transfer
  requests, secrecy patterns)

- Applied MITRE ATT&CK-aligned thinking to phishing detection, addressing
  techniques including Spearphishing Link (T1566.002), BEC (T1534), and
  Credential Harvesting (T1589)

- Documented a threat model identifying SSRF, XSS, SQL injection, and DoS risks
  inherent in an email analysis application, with mitigation controls for each

---

## AI / ML Engineer Focus

- Trained a calibrated email classification model using scikit-learn (TF-IDF
  vectorizer + CalibratedClassifierCV wrapping LinearSVC) to classify phishing,
  BEC, spam, and legitimate email across four classes with probability scores

- Designed a hybrid detection architecture where ML predictions serve as a
  supporting signal to a rule-based engine; applied a 65% confidence threshold
  to gate model output, surfacing uncertain predictions as "Inconclusive" rather
  than alarming analysts with low-confidence classifications

- Built a synthetic training corpus of 70 labeled email samples across four
  classes, demonstrating awareness of data governance and privacy best practices
  by avoiding use of real personal email data

---

## DevSecOps / Government IT Focus

- Implemented a defense-in-depth security posture: non-root Docker containers,
  Pydantic input validation, SQLAlchemy ORM (preventing SQL injection), output
  HTML-escaping (preventing XSS), 500KB input cap (preventing DoS), and CORS
  restrictions

- Integrated automated security scanning into CI/CD: Bandit for Python SAST,
  pip-audit for known CVE dependency analysis, and ESLint for frontend code quality

- Authored comprehensive threat model documentation identifying SSRF, stored XSS,
  SQL injection, and input exhaustion attack surfaces with architectural mitigations

- Produced government/SOC-oriented documentation including system architecture
  diagrams, SOC analyst workflow guides, and threat models suitable for an ATO
  (Authority to Operate) documentation package

---

## Quantified Impact Bullets (if asked for metrics)

- Reduced simulated email triage time by ~80% in testing scenarios by automating
  indicator extraction and scoring that analysts would otherwise perform manually

- Implemented 40+ detection rules across 3 analysis stages covering the most
  common phishing and BEC tactics identified in FBI IC3 2023 reporting

- Achieved 55-test pytest suite covering email parser edge cases (quoted display
  names, preamble headers), URL analysis, ML confidence thresholding, risk scoring
  thresholds, and full API integration across 4 test modules

---

## Project Description (for resume project section)

**PhishGuard AI** | Python · FastAPI · React · scikit-learn · Docker · SQLite
- Full-stack defensive email triage system combining rule-based detection and
  ML classification (TF-IDF + LinearSVC) to identify phishing, BEC, spam, and
  legitimate emails with calibrated confidence thresholding
- Multi-stage analysis pipeline: RFC-2822 header parsing, URL structural analysis
  (no link following), body content pattern matching, and ML classification with
  5 classification labels (Phishing, Business Email Compromise, Spam, Likely
  Legitimate, Inconclusive)
- React SOC dashboard with risk score gauge visualization, severity-grouped findings,
  ML confidence display, and downloadable 7-section analyst reports
- Containerized with Docker, CI/CD via GitHub Actions (pytest 55 tests · Bandit
  SAST · pip-audit CVE scan · ESLint · Docker build)
