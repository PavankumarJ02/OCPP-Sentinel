# =============================================================================
# test_logging.py — Unit tests for structured JSON audit logging
# =============================================================================

import json
from pathlib import Path
from fastapi.testclient import TestClient

from ocpp_sentinel.api.app import app
from ocpp_sentinel.logging_config import AUDIT_LOG_FILE, log_audit_event

client = TestClient(app)
SAMPLES_DIR = Path(__file__).parent.parent / "data" / "samples"


def test_log_audit_event_writes_valid_json():
    log_audit_event(
        action="Authorize",
        charge_point_id="CP-TEST-LOG",
        verdict="suspicious",
        attack_category="Repudiation",
        confidence=0.98,
        processing_time_ms=12.5,
        details="Test replay detection",
    )

    assert AUDIT_LOG_FILE.exists()
    lines = AUDIT_LOG_FILE.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) > 0

    # Parse last line as JSON
    last_entry = json.loads(lines[-1])
    assert "timestamp" in last_entry
    assert "audit" in last_entry
    audit_data = last_entry["audit"]
    assert audit_data["charge_point_id"] == "CP-TEST-LOG"
    assert audit_data["attack_category"] == "Repudiation"


def test_api_request_creates_audit_log_entry():
    filepath = SAMPLES_DIR / "malicious_spoofing.json"
    with open(filepath, "r", encoding="utf-8") as f:
        sample = json.load(f)

    response = client.post("/analyze", json={"message": sample})
    assert response.status_code == 200

    lines = AUDIT_LOG_FILE.read_text(encoding="utf-8").strip().splitlines()
    last_entry = json.loads(lines[-1])
    assert last_entry["audit"]["attack_category"] == "Spoofing"
    assert last_entry["audit"]["verdict"] == "suspicious"
