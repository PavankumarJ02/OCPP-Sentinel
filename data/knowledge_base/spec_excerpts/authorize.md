# OCPP 1.6-J Spec Excerpt: Authorize (Section 5.2)

## Message Flow
The Charge Point sends an `Authorize.req` to the Central System to verify
whether an `idTag` is authorized to start a charging session.

## Authorize.req Fields
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| idTag | IdToken (String, max 20) | Yes | The identifier to authorize |

## Authorize.conf Fields
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| idTagInfo | IdTagInfo | Yes | Authorization status and details |

## IdTagInfo Structure
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| status | AuthorizationStatus | Yes | One of: Accepted, Blocked, Expired, Invalid, ConcurrentTx |
| expiryDate | dateTime | No | When the authorization expires |
| parentIdTag | IdToken | No | Group identifier for this idTag |

## Key Behaviors (from spec)
1. When a Charge Point needs to charge an EV, it SHALL first verify the
   presented `idTag` by sending an `Authorize.req`.
2. Upon receipt, the Central System SHALL respond with an `Authorize.conf`
   indicating whether the `idTag` is accepted.
3. If the `idTag` is present in the Local Authorization List or
   Authorization Cache with status "Accepted", the Charge Point MAY
   start the transaction without waiting for the Central System response.
4. The `uniqueId` field in the message frame correlates the request with
   its response. Each `uniqueId` SHOULD be unique within a session.

## Security Considerations
- The `idTag` is effectively a bearer token — anyone who knows it can
  authorize a session.
- Replay protection depends on tracking `uniqueId` values.
- Without TLS (wss://), the `idTag` is transmitted in plaintext.

commit **1**
