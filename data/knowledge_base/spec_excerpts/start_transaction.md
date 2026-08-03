# OCPP 1.6-J Spec Excerpt: StartTransaction (Section 5.15)

## Message Flow
The Charge Point sends a `StartTransaction.req` to the Central System to
inform it that a charging transaction has begun. This follows a successful
authorization (either via `Authorize.conf` or Local Authorization List).

## StartTransaction.req Fields
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| connectorId | Integer (>= 1) | Yes | Connector where the transaction started |
| idTag | IdToken (String, max 20) | Yes | Identifier that authorized this session |
| meterStart | Integer | Yes | Meter reading at transaction start (in Wh) |
| timestamp | dateTime | Yes | When the transaction started |
| reservationId | Integer | No | If fulfilling a reservation |

## StartTransaction.conf Fields
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| transactionId | Integer | Yes | Unique transaction ID assigned by the CSMS |
| idTagInfo | IdTagInfo | Yes | Authorization status for this idTag |

## Key Behaviors (from spec)
1. A `StartTransaction.req` SHALL be sent by the Charge Point after it
   has accepted the authorization (locally or from the Central System).
2. The Central System SHALL respond with a `transactionId` that uniquely
   identifies this charging session.
3. The `meterStart` value establishes the baseline for energy metering.
   All subsequent `MeterValues` readings should be compared against this.
4. If the Central System's `idTagInfo.status` in the response is not
   "Accepted", the Charge Point SHOULD stop the transaction.

## Security Considerations
- The `idTag` in `StartTransaction.req` should match a recently authorized
  `idTag`. A `StartTransaction` without a corresponding `Authorize` is
  suspicious.
- The `meterStart` value is important for billing integrity — it should
  be consistent with the Charge Point's actual meter reading.
- The `transactionId` returned by the CSMS is used in all subsequent
  messages (`MeterValues`, `StopTransaction`) to correlate with this session.
