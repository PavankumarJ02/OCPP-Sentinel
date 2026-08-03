# =============================================================================
# test_api.py — Integration tests for FastAPI endpoints
# =============================================================================

import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from ocpp_sentinel.api.app import app

SAMPLES_DIR = Path(__file__).parent.parent / "data" / "samples"
client = TestClient(app)


def load_sample(filename: str) -> dict:
    filepath = SAMPLES_DIR / filename
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data
    assert data["kb_chunks"] > 0


def test_root_serves_ui():
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 200
    assert "OCPP Sentinel" in response.text


def test_analyze_benign_authorize():
    sample = load_sample("benign_authorize.json")
    response = client.post("/analyze", json={"message": sample})
    assert response.status_code == 200
    data = response.json()

    assert data["success"] is True
    assert data["processing_time_ms"] >= 0.0
    analysis = data["analysis"]
    assert analysis["verdict"] == "normal"
    assert analysis["matched_attack_category"] == "None"


def test_analyze_malicious_spoofing():
    sample = load_sample("malicious_spoofing.json")
    response = client.post("/analyze", json={"message": sample})
    assert response.status_code == 200
    data = response.json()

    analysis = data["analysis"]
    assert analysis["verdict"] == "suspicious"
    assert analysis["matched_attack_category"] == "Spoofing"
    assert analysis["rule_detected"] is True


def test_analyze_malicious_tampering():
    sample = load_sample("malicious_tampering.json")
    response = client.post("/analyze", json={"message": sample})
    assert response.status_code == 200
    data = response.json()

    analysis = data["analysis"]
    assert analysis["verdict"] == "suspicious"
    assert analysis["matched_attack_category"] == "Tampering"


def test_analyze_malicious_repudiation():
    sample = load_sample("malicious_repudiation.json")
    response = client.post("/analyze", json={"message": sample})
    assert response.status_code == 200
    data = response.json()

    analysis = data["analysis"]
    assert analysis["verdict"] == "suspicious"
    assert analysis["matched_attack_category"] == "Repudiation"


def test_analyze_malicious_info_disclosure():
    sample = load_sample("malicious_info_disclosure.json")
    response = client.post("/analyze", json={"message": sample})
    assert response.status_code == 200
    data = response.json()

    analysis = data["analysis"]
    assert analysis["verdict"] == "suspicious"
    assert analysis["matched_attack_category"] == "Information Disclosure"


def test_analyze_malicious_dos():
    sample = load_sample("malicious_dos.json")
    response = client.post("/analyze", json={"message": sample})
    assert response.status_code == 200
    data = response.json()

    analysis = data["analysis"]
    assert analysis["verdict"] == "suspicious"
    assert analysis["matched_attack_category"] == "Denial of Service"


def test_analyze_malformed_json():
    response = client.post("/analyze", json={"message": {"invalid": "payload"}})
    assert response.status_code == 200
    data = response.json()

    analysis = data["analysis"]
    assert analysis["verdict"] == "suspicious"
    assert analysis["matched_attack_category"] == "Malformed Input"
