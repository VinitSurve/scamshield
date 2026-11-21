"""Unit tests for FastAPI Inference API Server and Platform Integration."""

from fastapi.testclient import TestClient
from scamshield_ml.inference.server import app

client = TestClient(app)


def test_health_endpoint():
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "key_health" in data


def test_model_status_endpoint():
    res = client.get("/api/v1/models/status")
    assert res.status_code == 200
    data = res.json()
    assert "models_count" in data
    assert "next_action" in data


def test_analyze_message_endpoint():
    payload = {
        "inputType": "message",
        "text": "URGENT: SBI account blocked today! Complete KYC at https://sbi-online-kyc.top/verify Call: 9876543210",
        "source": "whatsapp",
    }
    res = client.post("/api/v1/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["verdict"] in ("HIGH_RISK", "CONFIRMED_MALICIOUS")
    assert data["riskScore"] >= 80
    assert len(data["evidence"]) > 0
    assert "urls" in data["extractedIndicators"]
    assert "https://sbi-online-kyc.top/verify" in data["extractedIndicators"]["urls"]


def test_analyze_url_endpoint():
    payload = {
        "inputType": "url",
        "url": "https://testsafebrowsing.appspot.com/s/malware.html",
        "source": "extension",
    }
    res = client.post("/api/v1/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["verdict"] == "CONFIRMED_MALICIOUS"
    assert data["riskScore"] >= 95


def test_analyze_empty_payload_rejects_with_400():
    payload = {"inputType": "message", "text": "   "}
    res = client.post("/api/v1/analyze", json=payload)
    assert res.status_code == 400
