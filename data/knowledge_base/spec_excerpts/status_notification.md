# OCPP 1.6-J Spec Excerpt: StatusNotification (Section 5.18)

## Message Flow
The Charge Point sends a `StatusNotification.req` to the Central System
whenever a connector's status changes or an error occurs. This is one
of the most frequently sent messages in the OCPP protocol.

## StatusNotification.req Fields
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| connectorId | Integer (>= 0) | Yes | Connector ID (0 = Charge Point itself) |
| errorCode | ChargePointErrorCode | Yes | Error code (see below) |
| status | ChargePointStatus | Yes | Current connector status |
| timestamp | dateTime | No | Time of the status change |
| info | String (max 50) | No | Additional free-text information about the error |
| vendorId | String (max 255) | No | Vendor-specific identifier |
| vendorErrorCode | String (max 50) | No | Vendor-specific error code |

## ChargePointStatus Values (Section 7.27)
| Status | Description |
|--------|-------------|
| Available | Connector is available for a new session |
| Preparing | Connector is preparing (user authenticated, not yet charging) |
| Charging | EV is connected and actively charging |
| SuspendedEVSE | Charging paused by the charger (e.g., load management) |
| SuspendedEV | Charging paused by the EV |
| Finishing | Session is finishing (EV still connected) |
| Reserved | Connector is reserved for a specific user |
| Unavailable | Connector is not available (maintenance, etc.) |
| Faulted | Connector has a fault |

## ChargePointErrorCode Values (Section 7.3)
NoError, ConnectorLockFailure, EVCommunicationError, GroundFailure,
HighTemperature, InternalError, LocalListConflict, OtherError,
OverCurrentFailure, OverVoltage, PowerMeterFailure, PowerSwitchFailure,
ReaderFailure, ResetFailure, UnderVoltage, WeakSignal.

## Key Behaviors (from spec)
1. The Charge Point SHALL send a `StatusNotification.req` when its status
   changes or when an error occurs/clears.
2. Connector ID 0 refers to the Charge Point as a whole, not a specific
   connector.
3. The `info` field is intended for human-readable diagnostic information.
4. The Central System SHALL respond with a `StatusNotification.conf`
   (which has no fields — it's just an acknowledgment).

## Security Considerations
- The `info` and `vendorId` fields are free-text and may inadvertently
  contain sensitive data (tokens, credentials, user identifiers).
- High-frequency `StatusNotification` messages can indicate a DoS attack
  or a malfunctioning Charge Point.
- Normal Charge Points send at most a few status notifications per minute.
  Receiving dozens or hundreds per minute from a single Charge Point is
  anomalous.
