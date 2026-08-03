# =============================================================================
# test_models.py — Tests for OCPP message Pydantic models
# =============================================================================
#
# LEARNING NOTE:
# pytest is Python's most popular test framework. Key concepts:
#
# 1. Test functions start with "test_" — pytest discovers them automatically.
# 2. Use plain `assert` statements — pytest gives great error messages.
# 3. @pytest.fixture creates reusable test data (like a setup method).
# 4. @pytest.mark.parametrize runs the same test with different inputs.
#
# WHY WE TEST MODELS:
# Our Pydantic models are the "front door" of the application. If they
# accept bad data, everything downstream is compromised. These tests
# verify that:
#   - Valid OCPP messages parse correctly
#   - Invalid messages are rejected with clear errors
#   - Each message type can be round-tripped (dict → model → dict)
# =============================================================================

import json
from pathlib import Path

import pytest

from ocpp_sentinel.models import (
    OCPPMessage,
    AuthorizePayload,
    BootNotificationPayload,
    StartTransactionPayload,
    MeterValuesPayload,
    StatusNotificationPayload,
    RemoteStartTransactionPayload,
)


# =============================================================================
# FIXTURES — Reusable test data
# =============================================================================
#
# LEARNING NOTE:
# A fixture is a function decorated with @pytest.fixture. When a test
# function has a parameter with the same name as a fixture, pytest
# automatically calls the fixture and passes its return value.
#
# Think of fixtures as "test setup that's shared across tests".
# =============================================================================

# Path to our sample data directory
SAMPLES_DIR = Path(__file__).parent.parent / "data" / "samples"


def load_sample(filename: str) -> dict:
    """
    Load a sample JSON file from the data/samples directory.

    LEARNING NOTE:
    Path is from Python's pathlib module — it's the modern way to handle
    file paths (instead of string concatenation with os.path.join).
    """
    filepath = SAMPLES_DIR / filename
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def benign_authorize() -> dict:
    """Load the benign Authorize sample."""
    return load_sample("benign_authorize.json")


@pytest.fixture
def benign_boot_notification() -> dict:
    """Load the benign BootNotification sample."""
    return load_sample("benign_boot_notification.json")


@pytest.fixture
def benign_meter_values() -> dict:
    """Load the benign MeterValues sample."""
    return load_sample("benign_meter_values.json")


@pytest.fixture
def benign_status_notification() -> dict:
    """Load the benign StatusNotification sample."""
    return load_sample("benign_status_notification.json")


@pytest.fixture
def benign_start_transaction() -> dict:
    """Load the benign StartTransaction sample."""
    return load_sample("benign_start_transaction.json")


@pytest.fixture
def malicious_spoofing() -> dict:
    """Load the malicious spoofing (RemoteStartTransaction) sample."""
    return load_sample("malicious_spoofing.json")


@pytest.fixture
def malicious_tampering() -> dict:
    """Load the malicious tampering (MeterValues) sample."""
    return load_sample("malicious_tampering.json")


@pytest.fixture
def malicious_repudiation() -> dict:
    """Load the malicious repudiation (replayed Authorize) sample."""
    return load_sample("malicious_repudiation.json")


@pytest.fixture
def malicious_info_disclosure() -> dict:
    """Load the malicious info disclosure (StatusNotification) sample."""
    return load_sample("malicious_info_disclosure.json")


@pytest.fixture
def malicious_dos() -> dict:
    """Load the malicious DoS (StatusNotification flood) sample."""
    return load_sample("malicious_dos.json")


# =============================================================================
# TEST: All sample files parse into valid OCPPMessage models
# =============================================================================
#
# LEARNING NOTE:
# @pytest.mark.parametrize is one of pytest's superpowers. It lets you
# run the SAME test function with DIFFERENT inputs. Each line in the
# parameter list becomes a separate test case.
# =============================================================================

@pytest.mark.parametrize("filename", [
    "benign_authorize.json",
    "benign_boot_notification.json",
    "benign_meter_values.json",
    "benign_status_notification.json",
    "benign_start_transaction.json",
    "malicious_spoofing.json",
    "malicious_tampering.json",
    "malicious_repudiation.json",
    "malicious_info_disclosure.json",
    "malicious_dos.json",
])
def test_sample_parses_as_ocpp_message(filename: str):
    """
    Every sample JSON file should successfully parse into an OCPPMessage.

    This is our "smoke test" — if any sample fails to parse, something
    is wrong with either the sample data or the model definition.
    """
    data = load_sample(filename)

    # Remove _comment field (it's for humans, not for Pydantic)
    data.pop("_comment", None)

    # This will raise a ValidationError if the data doesn't match
    message = OCPPMessage(**data)

    # Basic assertions — these should always hold
    assert message.unique_id is not None
    assert message.action is not None
    assert message.charge_point_id is not None
    assert message.received_at is not None


# =============================================================================
# TEST: Typed payload parsing works for each message type
# =============================================================================

def test_authorize_typed_payload(benign_authorize: dict):
    """
    An Authorize message's payload should parse into AuthorizePayload.
    """
    benign_authorize.pop("_comment", None)
    message = OCPPMessage(**benign_authorize)

    # get_typed_payload() looks at message.action and returns the right class
    payload = message.get_typed_payload()

    # isinstance() checks if an object is an instance of a specific class
    assert isinstance(payload, AuthorizePayload)
    assert payload.idTag == "RFID-A1B2C3"


def test_boot_notification_typed_payload(benign_boot_notification: dict):
    """
    A BootNotification payload should have vendor and model fields.
    """
    benign_boot_notification.pop("_comment", None)
    message = OCPPMessage(**benign_boot_notification)
    payload = message.get_typed_payload()

    assert isinstance(payload, BootNotificationPayload)
    assert payload.chargePointVendor == "VoltWave"
    assert payload.chargePointModel == "VW-DC-50"
    assert payload.firmwareVersion == "3.2.1"


def test_start_transaction_typed_payload(benign_start_transaction: dict):
    """
    A StartTransaction payload should have connectorId, idTag, and meterStart.
    """
    benign_start_transaction.pop("_comment", None)
    message = OCPPMessage(**benign_start_transaction)
    payload = message.get_typed_payload()

    assert isinstance(payload, StartTransactionPayload)
    assert payload.connectorId == 1
    assert payload.idTag == "RFID-A1B2C3"
    assert payload.meterStart == 100


def test_meter_values_typed_payload(benign_meter_values: dict):
    """
    MeterValues should have a list of meter readings with sampled values.
    """
    benign_meter_values.pop("_comment", None)
    message = OCPPMessage(**benign_meter_values)
    payload = message.get_typed_payload()

    assert isinstance(payload, MeterValuesPayload)
    assert payload.connectorId == 1
    assert payload.transactionId == 1001
    # Should have 2 meter readings
    assert len(payload.meterValue) == 2
    # First reading should be 100 Wh
    assert payload.meterValue[0].sampledValue[0].value == "100"


def test_status_notification_typed_payload(benign_status_notification: dict):
    """
    StatusNotification should have connectorId, errorCode, and status.
    """
    benign_status_notification.pop("_comment", None)
    message = OCPPMessage(**benign_status_notification)
    payload = message.get_typed_payload()

    assert isinstance(payload, StatusNotificationPayload)
    assert payload.connectorId == 1
    assert payload.errorCode == "NoError"
    assert payload.status == "Charging"


def test_remote_start_typed_payload(malicious_spoofing: dict):
    """
    RemoteStartTransaction should have an idTag and optional connectorId.
    """
    malicious_spoofing.pop("_comment", None)
    message = OCPPMessage(**malicious_spoofing)
    payload = message.get_typed_payload()

    assert isinstance(payload, RemoteStartTransactionPayload)
    assert payload.idTag == "FAKE-TAG-999"
    assert payload.connectorId == 1


# =============================================================================
# TEST: Context fields are populated correctly
# =============================================================================

def test_context_authorized_tags(benign_authorize: dict):
    """
    The analysis context should carry the list of authorized ID tags.
    """
    benign_authorize.pop("_comment", None)
    message = OCPPMessage(**benign_authorize)

    assert "RFID-A1B2C3" in message.context.authorized_id_tags
    assert len(message.context.authorized_id_tags) == 3


def test_context_known_message_ids(malicious_repudiation: dict):
    """
    The repudiation sample should have known_message_ids populated,
    and the message's own unique_id should be IN that list (it's a replay).
    """
    malicious_repudiation.pop("_comment", None)
    message = OCPPMessage(**malicious_repudiation)

    # The replayed message's unique_id "auth-001" should be in known IDs
    assert message.unique_id in message.context.known_message_ids


def test_context_dos_message_count(malicious_dos: dict):
    """
    The DoS sample should show an abnormally high recent message count.
    """
    malicious_dos.pop("_comment", None)
    message = OCPPMessage(**malicious_dos)

    # 150 messages in 60 seconds is way above normal
    assert message.context.recent_message_count == 150
    assert message.context.time_window_seconds == 60


# =============================================================================
# TEST: Invalid data is rejected
# =============================================================================
#
# LEARNING NOTE:
# Testing that BAD input is rejected is just as important as testing
# that GOOD input is accepted. These are "negative tests".
# pytest.raises() is a context manager that expects a specific exception.
# =============================================================================

def test_reject_empty_payload():
    """An OCPPMessage with no payload should be rejected."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        OCPPMessage(
            unique_id="test-001",
            action="Authorize",
            # Missing: payload, charge_point_id, received_at
        )


def test_reject_unknown_action():
    """An OCPPMessage with an invalid action should be rejected."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        OCPPMessage(
            unique_id="test-002",
            action="MadeUpAction",  # Not in OCPPAction enum
            payload={"idTag": "test"},
            charge_point_id="CP-001",
            received_at="2024-01-15T10:00:00Z",
        )


def test_reject_authorize_empty_id_tag():
    """An Authorize payload with an empty idTag should be rejected."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        AuthorizePayload(idTag="")  # min_length=1 should reject this


def test_reject_negative_connector_id():
    """A StartTransaction with a negative connectorId should be rejected."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        StartTransactionPayload(
            connectorId=-1,  # ge=1 should reject this
            idTag="RFID-TEST",
            meterStart=0,
            timestamp="2024-01-15T10:00:00Z",
        )


# =============================================================================
# TEST: Default context is created when not provided
# =============================================================================

def test_default_context():
    """
    If no context is provided, a default AnalysisContext should be created
    with empty lists and zero counts.
    """
    message = OCPPMessage(
        unique_id="test-defaults",
        action="Authorize",
        payload={"idTag": "RFID-TEST"},
        charge_point_id="CP-TEST",
        received_at="2024-01-15T10:00:00Z",
        # No context provided — should get defaults
    )

    assert message.context.authorized_id_tags == []
    assert message.context.known_message_ids == []
    assert message.context.recent_message_count == 0
    assert message.context.time_window_seconds == 60  # default
