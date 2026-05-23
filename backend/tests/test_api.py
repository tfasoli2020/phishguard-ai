"""Integration tests for the FastAPI endpoints."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.database import Base, get_db

# Use an in-memory SQLite database for tests
TEST_DB_URL = "sqlite:///./test_phishguard.db"
test_engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def override_get_db():
    db = TestSession()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(scope="module")
def client():
    Base.metadata.create_all(bind=test_engine)
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)
    # Clean up test DB file
    if os.path.exists("test_phishguard.db"):
        os.remove("test_phishguard.db")


PHISHING_EMAIL = """\
From: security@paypa1-verify.evil.net
Reply-To: harvest@attacker.com
To: victim@company.com
Subject: URGENT: Verify your account now

Dear Customer, your account has been suspended.
Verify immediately: http://paypa1-login.evil.net/verify
Failure to act in 24 hours will result in permanent closure.
"""

LEGITIMATE_EMAIL = """\
From: hr@acmecorp.com
To: employee@acmecorp.com
Subject: Quarterly review scheduled

Hi,
Your performance review is scheduled for June 3rd at 2pm in Room 4B.
Please complete your self-assessment in the HR portal by May 31st.

Thanks,
Sarah
"""


class TestHealthEndpoint:
    def test_health_ok(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "version" in data
        assert "ml_model_loaded" in data


class TestAnalyzeEndpoint:
    def test_analyze_phishing_email(self, client):
        response = client.post("/analyze", json={"email_text": PHISHING_EMAIL})
        assert response.status_code == 200
        data = response.json()
        assert "analysis_id" in data
        assert data["risk_score"] >= 0
        assert data["risk_level"] in ("Low", "Medium", "High", "Critical")
        assert data["classification"] in (
            "phishing", "business_email_compromise", "spam", "likely_legitimate"
        )
        assert isinstance(data["findings"], list)
        assert isinstance(data["recommended_actions"], list)
        assert "report" in data

    def test_analyze_legitimate_email(self, client):
        response = client.post("/analyze", json={"email_text": LEGITIMATE_EMAIL})
        assert response.status_code == 200
        data = response.json()
        assert data["risk_score"] < 50  # legitimate email should score low

    def test_analyze_returns_email_metadata(self, client):
        response = client.post("/analyze", json={"email_text": PHISHING_EMAIL})
        assert response.status_code == 200
        data = response.json()
        meta = data["email_metadata"]
        assert "sender" in meta
        assert "subject" in meta
        assert "urls" in meta
        assert "domains" in meta

    def test_analyze_empty_email_rejected(self, client):
        response = client.post("/analyze", json={"email_text": "   "})
        assert response.status_code == 422

    def test_analyze_missing_field_rejected(self, client):
        response = client.post("/analyze", json={})
        assert response.status_code == 422

    def test_analyze_report_is_string(self, client):
        response = client.post("/analyze", json={"email_text": PHISHING_EMAIL})
        assert response.status_code == 200
        assert isinstance(response.json()["report"], str)
        assert "PhishGuard" in response.json()["report"]


class TestHistoryEndpoints:
    def test_history_returns_list(self, client):
        # Ensure there's at least one record
        client.post("/analyze", json={"email_text": PHISHING_EMAIL})
        response = client.get("/history")
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_get_analysis_by_id(self, client):
        create = client.post("/analyze", json={"email_text": PHISHING_EMAIL})
        analysis_id = create.json()["analysis_id"]

        response = client.get(f"/history/{analysis_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["analysis_id"] == analysis_id
        assert "findings" in data
        assert "report" in data

    def test_get_nonexistent_analysis_returns_404(self, client):
        response = client.get("/history/999999")
        assert response.status_code == 404

    def test_delete_analysis(self, client):
        create = client.post("/analyze", json={"email_text": PHISHING_EMAIL})
        analysis_id = create.json()["analysis_id"]

        delete_resp = client.delete(f"/history/{analysis_id}")
        assert delete_resp.status_code == 204

        get_resp = client.get(f"/history/{analysis_id}")
        assert get_resp.status_code == 404

    def test_history_limit_validation(self, client):
        response = client.get("/history?limit=0")
        assert response.status_code == 422


BEC_EMAIL_API = """\
From: "Robert Johnson" <ceo.johnson@company-corp.net>
Reply-To: r.johnson.ceo@gmail.com
To: finance@company.com
Subject: Confidential - Urgent Wire Transfer
Date: Fri, 17 May 2024 09:12:00 +0000

Please wire $47,500 immediately to the escrow account.
Keep this strictly between us — do not call me, confirm by email only.
"""

LOW_CONFIDENCE_EMAIL = """\
From: newsletter@shopdeals.example.com
To: subscriber@example.com
Subject: Summer Sale — Up to 40% off this weekend only
Date: Fri, 17 May 2024 14:00:00 +0000

Hi there, our biggest summer sale starts tomorrow. Up to 40% off select items.
Visit http://shopdeals.example.com/sale for details. Unsubscribe anytime.
"""


class TestClassificationLabel:
    def test_analyze_returns_classification_label(self, client):
        response = client.post("/analyze", json={"email_text": PHISHING_EMAIL})
        assert response.status_code == 200
        data = response.json()
        assert "classification_label" in data
        assert isinstance(data["classification_label"], str)
        assert len(data["classification_label"]) > 0

    def test_bec_email_classification_label_full_name(self, client):
        response = client.post("/analyze", json={"email_text": BEC_EMAIL_API})
        assert response.status_code == 200
        data = response.json()
        assert "classification_label" in data
        # If classified as BEC, must use full display name
        if data["classification"] == "business_email_compromise":
            assert data["classification_label"] == "Business Email Compromise"

    def test_history_record_has_classification_label(self, client):
        client.post("/analyze", json={"email_text": PHISHING_EMAIL})
        response = client.get("/history")
        assert response.status_code == 200
        records = response.json()
        assert len(records) > 0
        assert "classification_label" in records[0]
        assert isinstance(records[0]["classification_label"], str)

    def test_ml_prediction_field_present_in_response(self, client):
        response = client.post("/analyze", json={"email_text": PHISHING_EMAIL})
        assert response.status_code == 200
        data = response.json()
        assert "ml_prediction" in data
        assert "ml_confidence" in data

    def test_low_risk_email_classification_label(self, client):
        response = client.post("/analyze", json={"email_text": LEGITIMATE_EMAIL})
        assert response.status_code == 200
        data = response.json()
        assert "classification_label" in data
        if data["classification"] == "likely_legitimate":
            assert data["classification_label"] == "Likely Legitimate"
