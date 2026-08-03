# =============================================================================
# ocpp_messages.py — Pydantic models for OCPP 1.6-J message types
# =============================================================================
#
# LEARNING NOTE:
# Pydantic is a data validation library. You define a class that inherits
# from BaseModel, declare the fields with type hints, and Pydantic will:
#   1. Validate that incoming data has the right types
#   2. Convert types where possible (e.g., "123" → 123 for an int field)
#   3. Raise clear errors if validation fails
#
# This is HUGE for security tools — we want to reject malformed input
# before we even start analyzing it.
#
# OCPP 1.6-J SPEC NOTES:
# OCPP (Open Charge Point Protocol) defines how EV charging stations
# ("charge points") communicate with a central management system ("CSMS").
# Messages are sent as JSON over WebSocket. Each message has:
#   - messageTypeId: 2 = Call (request), 3 = CallResult, 4 = CallError
#   - uniqueId: correlates requests with responses
#   - action: the message type name (e.g., "Authorize", "MeterValues")
#   - payload: the actual data, whose shape depends on the action
#
# We model the 7 most security-relevant message types below.
# Field names match the OCPP 1.6-J specification exactly (camelCase).
# =============================================================================

from __future__ import annotations  # Allows forward references in type hints

from datetime import datetime
from enum import Enum
from typing import Any, Optional, Union

from pydantic import BaseModel, Field


# =============================================================================
# ENUMS — Fixed sets of valid values from the OCPP 1.6-J spec
# =============================================================================
#
# LEARNING NOTE:
# An Enum (enumeration) is a class with a fixed set of named values.
# Using enums instead of raw strings means:
#   - Typos are caught at validation time ("Charing" won't slip through)
#   - Your IDE can autocomplete valid values
#   - The code is self-documenting
# =============================================================================

class OCPPAction(str, Enum):
    """
    The OCPP message types we care about for security analysis.

    LEARNING NOTE:
    This inherits from BOTH str and Enum. That means each value IS a string
    (so it serializes to JSON naturally) but also has enum behavior
    (restricted to these specific values).
    """
    AUTHORIZE = "Authorize"
    BOOT_NOTIFICATION = "BootNotification"
    START_TRANSACTION = "StartTransaction"
    STOP_TRANSACTION = "StopTransaction"
    METER_VALUES = "MeterValues"
    STATUS_NOTIFICATION = "StatusNotification"
    REMOTE_START_TRANSACTION = "RemoteStartTransaction"


class ChargePointStatus(str, Enum):
    """
    Possible states a charge point connector can be in.
    Reference: OCPP 1.6-J, Section 7.27 ChargePointStatus
    """
    AVAILABLE = "Available"
    PREPARING = "Preparing"
    CHARGING = "Charging"
    SUSPENDED_EVSE = "SuspendedEVSE"
    SUSPENDED_EV = "SuspendedEV"
    FINISHING = "Finishing"
    RESERVED = "Reserved"
    UNAVAILABLE = "Unavailable"
    FAULTED = "Faulted"


class ChargePointErrorCode(str, Enum):
    """
    Error codes that a charge point can report.
    Reference: OCPP 1.6-J, Section 7.3 ChargePointErrorCode
    """
    CONNECTOR_LOCK_FAILURE = "ConnectorLockFailure"
    EV_COMMUNICATION_ERROR = "EVCommunicationError"
    GROUND_FAILURE = "GroundFailure"
    HIGH_TEMPERATURE = "HighTemperature"
    INTERNAL_ERROR = "InternalError"
    LOCAL_LIST_CONFLICT = "LocalListConflict"
    NO_ERROR = "NoError"
    OTHER_ERROR = "OtherError"
    OVER_CURRENT_FAILURE = "OverCurrentFailure"
    OVER_VOLTAGE = "OverVoltage"
    POWER_METER_FAILURE = "PowerMeterFailure"
    POWER_SWITCH_FAILURE = "PowerSwitchFailure"
    READER_FAILURE = "ReaderFailure"
    RESET_FAILURE = "ResetFailure"
    UNDER_VOLTAGE = "UnderVoltage"
    WEAK_SIGNAL = "WeakSignal"


# =============================================================================
# PAYLOAD MODELS — One per OCPP message type
# =============================================================================
#
# LEARNING NOTE:
# Each OCPP action has a specific payload shape. We model each as its
# own Pydantic class. Field(...) lets us add descriptions and mark
# fields as required/optional.
#
# Optional[str] means "this field can be a string OR None (missing)".
# Field(default=None) means "if not provided, default to None".
# =============================================================================


class AuthorizePayload(BaseModel):
    """
    Authorize.req — Sent by the charge point to verify an ID tag (RFID card,
    app token, etc.) before allowing a charging session.

    Reference: OCPP 1.6-J, Section 5.2
    Security relevance: Repudiation attacks may replay this message.
    """
    idTag: str = Field(
        ...,  # ... means "required" — must be provided
        description="The identifier (e.g., RFID tag) to authorize",
        min_length=1,
        max_length=20,  # OCPP spec: IdToken is max 20 chars
    )


class BootNotificationPayload(BaseModel):
    """
    BootNotification.req — Sent by the charge point when it boots up,
    telling the CSMS about its hardware.

    Reference: OCPP 1.6-J, Section 5.3
    Security relevance: Can reveal hardware info if intercepted.
    """
    chargePointVendor: str = Field(
        ...,
        description="Vendor name of the charge point",
        max_length=20,
    )
    chargePointModel: str = Field(
        ...,
        description="Model of the charge point",
        max_length=20,
    )
    # Optional fields — the charge point MAY include these
    chargePointSerialNumber: Optional[str] = Field(
        default=None, max_length=25,
        description="Serial number of the charge point",
    )
    chargeBoxSerialNumber: Optional[str] = Field(
        default=None, max_length=25,
        description="Serial number of the charge box (enclosure)",
    )
    firmwareVersion: Optional[str] = Field(
        default=None, max_length=50,
        description="Firmware version installed on the charge point",
    )
    iccid: Optional[str] = Field(
        default=None, max_length=20,
        description="SIM card ICCID (for cellular-connected chargers)",
    )
    imsi: Optional[str] = Field(
        default=None, max_length=20,
        description="SIM card IMSI",
    )
    meterType: Optional[str] = Field(
        default=None, max_length=25,
        description="Type of energy meter installed",
    )
    meterSerialNumber: Optional[str] = Field(
        default=None, max_length=25,
        description="Serial number of the energy meter",
    )


class StartTransactionPayload(BaseModel):
    """
    StartTransaction.req — Sent when a charging session actually begins
    (after authorization).

    Reference: OCPP 1.6-J, Section 5.15
    Security relevance: Must correlate with a prior Authorize for the same idTag.
    """
    connectorId: int = Field(
        ...,
        description="ID of the connector being used (1-based)",
        ge=1,  # ge = "greater than or equal to"
    )
    idTag: str = Field(
        ...,
        description="ID tag that authorized this session",
        min_length=1,
        max_length=20,
    )
    meterStart: int = Field(
        ...,
        description="Meter reading at session start (in Wh)",
        ge=0,
    )
    timestamp: str = Field(
        ...,
        description="Timestamp when the session started (ISO 8601)",
    )
    reservationId: Optional[int] = Field(
        default=None,
        description="If this session is fulfilling a reservation, its ID",
    )


class StopTransactionPayload(BaseModel):
    """
    StopTransaction.req — Sent when a charging session ends.

    Reference: OCPP 1.6-J, Section 5.16
    Security relevance: meterStop must be consistent with MeterValues reported.
    """
    meterStop: int = Field(
        ...,
        description="Meter reading at session end (in Wh)",
        ge=0,
    )
    timestamp: str = Field(
        ...,
        description="Timestamp when the session ended (ISO 8601)",
    )
    transactionId: int = Field(
        ...,
        description="ID of the transaction being stopped",
    )
    idTag: Optional[str] = Field(
        default=None,
        description="ID tag that was used for this session",
        max_length=20,
    )
    reason: Optional[str] = Field(
        default=None,
        description="Reason the session was stopped (e.g., 'EVDisconnected')",
    )
    transactionData: Optional[list[dict[str, Any]]] = Field(
        default=None,
        description="Optional meter data samples from the session",
    )


# ---- MeterValues sub-models ----
# MeterValues has a nested structure: the payload contains a list of
# MeterValue objects, each of which contains a list of SampledValue objects.
# We model these from the inside out (leaf → root).

class SampledValue(BaseModel):
    """
    A single measurement sample from the energy meter.
    Reference: OCPP 1.6-J, Section 7.33
    """
    value: str = Field(
        ...,
        description="The measured value as a string (e.g., '12345')",
    )
    # All other fields are optional — the spec allows partial reporting
    context: Optional[str] = Field(
        default=None,
        description="Reading context: 'Sample.Periodic', 'Transaction.Begin', etc.",
    )
    format: Optional[str] = Field(
        default=None,
        description="Format: 'Raw' or 'SignedData'",
    )
    measurand: Optional[str] = Field(
        default=None,
        description="What's being measured: 'Energy.Active.Import.Register', etc.",
    )
    phase: Optional[str] = Field(
        default=None,
        description="Electrical phase: 'L1', 'L2', 'L3', 'L1-N', etc.",
    )
    location: Optional[str] = Field(
        default=None,
        description="Where the measurement was taken: 'Outlet', 'Inlet', 'Body'",
    )
    unit: Optional[str] = Field(
        default=None,
        description="Unit of measure: 'Wh', 'kWh', 'W', 'kW', 'A', 'V', etc.",
    )


class MeterValue(BaseModel):
    """
    A timestamped collection of meter samples.
    Reference: OCPP 1.6-J, Section 7.23
    """
    timestamp: str = Field(
        ...,
        description="Time the measurement was taken (ISO 8601)",
    )
    sampledValue: list[SampledValue] = Field(
        ...,
        description="One or more sampled values at this timestamp",
        min_length=1,  # Must have at least one sample
    )


class MeterValuesPayload(BaseModel):
    """
    MeterValues.req — Periodic energy meter readings during a session.

    Reference: OCPP 1.6-J, Section 5.11
    Security relevance: Tampering detection — implausibly low values = billing fraud.
    """
    connectorId: int = Field(
        ...,
        description="Connector these readings are for (0 = main meter)",
        ge=0,
    )
    meterValue: list[MeterValue] = Field(
        ...,
        description="List of timestamped meter readings",
        min_length=1,
    )
    transactionId: Optional[int] = Field(
        default=None,
        description="Transaction these readings belong to",
    )


class StatusNotificationPayload(BaseModel):
    """
    StatusNotification.req — Reports the current status of a connector.

    Reference: OCPP 1.6-J, Section 5.18
    Security relevance: DoS via rapid-fire status notifications;
                        Info disclosure if sensitive data leaks into info/vendorId fields.
    """
    connectorId: int = Field(
        ...,
        description="Connector ID (0 = charge point itself)",
        ge=0,
    )
    errorCode: str = Field(
        ...,
        description="Error code from the ChargePointErrorCode enum",
    )
    status: str = Field(
        ...,
        description="Current status from the ChargePointStatus enum",
    )
    # Optional fields
    timestamp: Optional[str] = Field(
        default=None,
        description="Time of the status change (ISO 8601)",
    )
    info: Optional[str] = Field(
        default=None, max_length=50,
        description="Additional free-text info about the error",
    )
    vendorId: Optional[str] = Field(
        default=None, max_length=255,
        description="Vendor-specific identifier",
    )
    vendorErrorCode: Optional[str] = Field(
        default=None, max_length=50,
        description="Vendor-specific error code",
    )


class RemoteStartTransactionPayload(BaseModel):
    """
    RemoteStartTransaction.req — Sent BY the CSMS TO the charge point,
    requesting it to start a session for a specific ID tag.

    Reference: OCPP 1.6-J, Section 5.13
    Security relevance: Spoofing — if this arrives with an idTag that
                        was never authorized, it could be an attacker
                        trying to start a free session.
    """
    idTag: str = Field(
        ...,
        description="ID tag to start the session for",
        min_length=1,
        max_length=20,
    )
    connectorId: Optional[int] = Field(
        default=None,
        description="Specific connector to start on (optional)",
        ge=1,
    )
    chargingProfile: Optional[dict[str, Any]] = Field(
        default=None,
        description="Optional charging profile with power/schedule limits",
    )


# =============================================================================
# ANALYSIS CONTEXT — Extra info needed for attack detection
# =============================================================================
#
# LEARNING NOTE:
# A single OCPP message often isn't enough to detect an attack. For example:
#   - Spoofing: we need to know which ID tags are authorized
#   - DoS: we need to know how many messages came recently
#   - Repudiation: we need to know if this message ID was seen before
#
# In a real system, this context comes from the CSMS database. For our
# analysis tool, the user provides it alongside the message.
# =============================================================================

class AnalysisContext(BaseModel):
    """
    Optional context that enriches the security analysis.
    In production, this would come from your CSMS database automatically.
    """
    # For spoofing detection: list of ID tags that ARE authorized
    authorized_id_tags: list[str] = Field(
        default_factory=list,  # default_factory=list creates a new empty list
        description="List of currently authorized ID tags",
    )

    # For repudiation detection: message IDs we've already processed
    known_message_ids: list[str] = Field(
        default_factory=list,
        description="Previously seen message unique IDs (for replay detection)",
    )

    # For DoS detection: how many messages from this charge point recently
    recent_message_count: int = Field(
        default=0,
        description="Number of messages from this charge point in the time window",
        ge=0,
    )
    time_window_seconds: int = Field(
        default=60,
        description="Size of the time window for rate-based detection (seconds)",
        ge=1,
    )


# =============================================================================
# THE MAIN MESSAGE ENVELOPE
# =============================================================================
#
# LEARNING NOTE:
# This is the "outer wrapper" that contains both the OCPP message itself
# and the context needed for analysis. When a user sends a request to our
# API, they'll send one of these.
#
# The `payload` field uses Union[...] — it can be ANY of the payload types.
# Pydantic uses a "discriminated union" strategy to figure out which one
# based on the `action` field (we handle this in a validator).
# =============================================================================

class OCPPMessage(BaseModel):
    """
    The complete OCPP message envelope for security analysis.

    This wraps an OCPP 1.6-J Call message with metadata needed
    for analysis. In the real OCPP wire format, messages look like:
        [2, "uniqueId", "Action", {payload}]

    We expand this into a structured object for easier processing.
    """
    # ---- OCPP wire format fields ----
    message_type_id: int = Field(
        default=2,
        description="OCPP message type: 2=Call, 3=CallResult, 4=CallError",
        ge=2,
        le=4,
    )
    unique_id: str = Field(
        ...,
        description="Unique identifier correlating request ↔ response",
    )
    action: OCPPAction = Field(
        ...,
        description="The OCPP action (message type name)",
    )
    payload: dict[str, Any] = Field(
        ...,
        description="The message payload (validated per action type)",
    )

    # ---- Metadata added by our system ----
    charge_point_id: str = Field(
        ...,
        description="ID of the charge point that sent/receives this message",
    )
    received_at: str = Field(
        ...,
        description="When this message was received (ISO 8601 timestamp)",
    )

    # ---- Analysis context (optional) ----
    context: AnalysisContext = Field(
        default_factory=AnalysisContext,
        description="Optional context for enriched analysis",
    )

    def get_typed_payload(
        self,
    ) -> Union[
        AuthorizePayload,
        BootNotificationPayload,
        StartTransactionPayload,
        StopTransactionPayload,
        MeterValuesPayload,
        StatusNotificationPayload,
        RemoteStartTransactionPayload,
    ]:
        """
        Parse the raw payload dict into the correct typed Pydantic model
        based on the action field.

        LEARNING NOTE:
        This is a form of the "factory pattern" — we look at the action
        to decide which class to instantiate. The ** operator "unpacks"
        the dictionary into keyword arguments:
            AuthorizePayload(**{"idTag": "ABC123"})
        is equivalent to:
            AuthorizePayload(idTag="ABC123")

        Returns:
            The payload parsed as the correct Pydantic model.

        Raises:
            ValueError: If the action is not recognized.
        """
        # This dictionary maps action names to their payload classes.
        # It's defined inside the method to keep it close to where it's used.
        action_to_payload_class = {
            OCPPAction.AUTHORIZE: AuthorizePayload,
            OCPPAction.BOOT_NOTIFICATION: BootNotificationPayload,
            OCPPAction.START_TRANSACTION: StartTransactionPayload,
            OCPPAction.STOP_TRANSACTION: StopTransactionPayload,
            OCPPAction.METER_VALUES: MeterValuesPayload,
            OCPPAction.STATUS_NOTIFICATION: StatusNotificationPayload,
            OCPPAction.REMOTE_START_TRANSACTION: RemoteStartTransactionPayload,
        }

        payload_class = action_to_payload_class.get(self.action)
        if payload_class is None:
            raise ValueError(f"Unknown OCPP action: {self.action}")

        # ** unpacks the dict into keyword arguments for the constructor
        return payload_class(**self.payload)
