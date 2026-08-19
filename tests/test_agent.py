# =============================================================================
# test_agent.py — Tests for the LangGraph agent state machine
# =============================================================================

import json
from pathlib import Path
import pytest

from ocpp_sentinel.agent import run_sentinel_agent, VerdictResponse

SAMPLES_DIR = Path(__file__).parent.parent / "data" / "samples"


def load_sample_dict(filename: str) -> dict:
    filepath = SAMPLES_DIR / filename
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


# =============================================================================
# BENIGN SAMPLES
# =============================================================================

@pytest.mark.parametrize("filename", [
    "benign_authorize.json",
    "benign_boot_notification.json",
    "benign_meter_values.json",
    "benign_status_notification.json",
    "benign_start_transaction.json",
])
def test_agent_benign_samples(filename: str):
    data = load_sample_dict(filename)
    verdict: VerdictResponse = run_sentinel_agent(data)

    assert isinstance(verdict, VerdictResponse)
    assert verdict.verdict == "normal"
    assert verdict.matched_attack_category == "None"
    assert verdict.confidence >= 0.80
    assert len(verdict.plain_english_reason) > 10
    assert len(verdict.source_reference) > 0


# =============================================================================
# MALICIOUS SAMPLES
# =============================================================================

def test_agent_malicious_spoofing():
    data = load_sample_dict("malicious_spoofing.json")
    verdict: VerdictResponse = run_sentinel_agent(data)

    assert verdict.verdict == "suspicious"
    assert verdict.matched_attack_category == "Spoofing"
    assert verdict.rule_detected is True
    assert "idTag" in verdict.plain_english_reason
    assert "remote_start" in verdict.source_reference.lower() or "spoofing" in verdict.source_reference.lower()


def test_agent_malicious_tampering():
    data = load_sample_dict("malicious_tampering.json")
    verdict: VerdictResponse = run_sentinel_agent(data)

    assert verdict.verdict == "suspicious"
    assert verdict.matched_attack_category == "Tampering"
    assert verdict.rule_detected is True
    assert "energy" in verdict.plain_english_reason.lower() or "kwh" in verdict.plain_english_reason.lower()


def test_agent_malicious_repudiation():
    data = load_sample_dict("malicious_repudiation.json")
    verdict: VerdictResponse = run_sentinel_agent(data)

    assert verdict.verdict == "suspicious"
    assert verdict.matched_attack_category == "Repudiation"
    assert verdict.rule_detected is True
    assert "unique_id" in verdict.plain_english_reason.lower() or "replay" in verdict.plain_english_reason.lower()


def test_agent_malicious_info_disclosure():
    data = load_sample_dict("malicious_info_disclosure.json")
    verdict: VerdictResponse = run_sentinel_agent(data)

    assert verdict.verdict == "suspicious"
    assert verdict.matched_attack_category == "Information Disclosure"
    assert verdict.rule_detected is True
    assert "token" in verdict.plain_english_reason.lower() or "plaintext" in verdict.plain_english_reason.lower()


def test_agent_malicious_dos():
    data = load_sample_dict("malicious_dos.json")
    verdict: VerdictResponse = run_sentinel_agent(data)

    assert verdict.verdict == "suspicious"
    assert verdict.matched_attack_category == "Denial of Service"
    assert verdict.rule_detected is True
    assert "burst" in verdict.plain_english_reason.lower() or "messages" in verdict.plain_english_reason.lower()


# =============================================================================
# MALFORMED INPUT
# =============================================================================

def test_agent_malformed_input():
    bad_data = {"invalid": "data"}
    verdict: VerdictResponse = run_sentinel_agent(bad_data)
hi this project idia
    assert verdict.verdict == "suspicious"
    assert verdict.matched_attack_category == "Malformed Input"
    assert "validation" in verdict.plain_english_reason.lower()
