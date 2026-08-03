# OCPP 1.6-J Spec Excerpt: RemoteStartTransaction (Section 5.13)

## Message Flow
The Central System sends a `RemoteStartTransaction.req` to a Charge Point
to request it to start a charging transaction for a specified `idTag`.
This is used when the user initiates charging remotely, e.g., from a
mobile application.

## RemoteStartTransaction.req Fields
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| idTag | IdToken (String, max 20) | Yes | The identifier to start the transaction for |
| connectorId | Integer | No | Specific connector to use (if not specified, Charge Point selects) |
| chargingProfile | ChargingProfile | No | Charging profile to apply for this session |

## RemoteStartTransaction.conf Fields
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| status | RemoteStartStopStatus | Yes | "Accepted" or "Rejected" |

## Key Behaviors (from spec)
1. Upon receipt of a `RemoteStartTransaction.req`, the Charge Point SHALL
   respond with a `RemoteStartTransaction.conf` indicating acceptance or
   rejection.
2. If the `idTag` is present in the Local Authorization List or
   Authorization Cache with status "Accepted", the Charge Point SHOULD
   accept the request.
3. If a `connectorId` is specified, the Charge Point SHALL start the
   transaction on that specific connector if it is available.
4. After accepting, the Charge Point SHALL send a `StartTransaction.req`
   to inform the Central System that the transaction has started.
5. The Charge Point MAY reject the request if the specified connector is
   not available or if the `idTag` is not authorized.

## Security Considerations
- This message originates from the Central System, so the Charge Point
  trusts it implicitly in basic OCPP 1.6 security profiles.
- If an attacker compromises the CSMS or the WebSocket connection, they
  can send arbitrary `RemoteStartTransaction` requests.
- The `idTag` in the request should be validated against the authorization
  system — a `RemoteStartTransaction` with an unknown `idTag` is suspicious.
- OCPP Security Profile 2 and 3 use TLS client certificates to
  authenticate the Central System, mitigating this risk.
