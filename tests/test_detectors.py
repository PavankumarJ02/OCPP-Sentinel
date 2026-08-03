# =============================================================================
# test_detectors.py — Tests for rule-based security detectors
# =============================================================================

import json
from pathlib import Path
import pytest

from ocpp_sentinel.models import OCPPMessage
from ocpp_sentinel.detectors.dispatcher import DetectorDispatcher
from ocpp_sentinel.detectors.spoofing import SpoofingDetector
from ocpp_sentinel.detectors.tampering import TamperingDetector
from ocpp_sentinel.detectors.repudiation import RepudiationDetector
from ocpp_sentinel.detectors.info_disclosure import InfoDisclosureDetector
from ocpp_sentinel.detectors.dos import DoSDetector

SAMPLES_DIR = Path(__file__).parent.parent / "data" / "samples"


def load_sample_msg(filename: str) -> OCPPMessage:
    filepath = SAMPLES_DIR / filename
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
    data.pop("_comment", None)
    return OCPPMessage(**data)


@pytest.fixture
def dispatcher() -> DetectorDispatcher:
    return DetectorDispatcher()


# =============================================================================
# TEST BENIGN SAMPLES — NONE should trigger an attack detection
# =============================================================================

@pytest.mark.parametrize("filename", [
    "benign_authorize.json",
    "benign_boot_notification.json",
    "benign_meter_values.json",
    "benign_status_notification.json",
    "benign_start_transaction.json",
])
def test_benign_samples_trigger_no_detection(dispatcher: DetectorDispatcher, filename: str):
    msg = load_sample_msg(filename)
    detected = dispatcher.get_first_detection(msg)
    assert detected is None or not detected.detected, f"False positive on benign sample {filename}: {detected}"


# =============================================================================
# TEST MALICIOUS SAMPLES — EACH must trigger its matching detector
# =============================================================================

def test_malicious_spoofing_detection(dispatcher: DetectorDispatcher):
    msg = load_sample_msg("malicious_spoofing.json")
    result = SpoofingDetector().detect(msg)
    assert result.detected is True
    assert result.attack_category == "Spoofing"
    assert result.confidence >= 0.90


def test_malicious_tampering_detection(dispatcher: DetectorDispatcher):
    msg = load_sample_msg("malicious_tampering.json")
    result = TamperingDetector().detect(msg)
    assert result.detected is True
    assert result.attack_category == "Tampering"
    assert result.confidence >= 0.90


def test_malicious_repudiation_detection(dispatcher: DetectorDispatcher):
    msg = load_sample_msg("malicious_repudiation.json")
    result = RepudiationDetector().detect(msg)
    assert result.detected is True
    assert result.attack_category == "Repudiation"
    assert result.confidence >= 0.90


def test_malicious_info_disclosure_detection(dispatcher: DetectorDispatcher):
    msg = load_sample_msg("malicious_info_disclosure.json")
    result = InfoDisclosureDetector().detect(msg)
    assert result.detected is True
    assert result.attack_category == "Information Disclosure"
    assert result.confidence >= 0.90


def test_malicious_dos_detection(dispatcher: DetectorDispatcher):
    msg = load_sample_msg("malicious_dos.json")
    result = DoSDetector().detect(msg)
    assert result.detected is True
    assert result.attack_category == "Denial of Service"
    assert result.confidence >= 0.90


def test_dispatcher_finds_attacks(dispatcher: DetectorDispatcher):
    malicious_files = [
        ("malicious_spoofing.json", "Spoofing"),
        ("malicious_tampering.json", "Tampering"),
        ("malicious_repudiation.json", "Repudiation"),
        ("malicious_info_disclosure.json", "Information Disclosure"),
        ("malicious_dos.json", "Denial of Service"),
    ]
    for filename, expected_category in malicious_files:
        msg = load_sample_msg(filename)
        result = dispatcher.get_first_detection(msg)
        assert result is not None, f"No detection for {filename}"
        assert result.detected is True
        assert result.attack_category == expected_category
