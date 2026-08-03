# Attack: Repudiation via Replayed Authorize Message

## STRIDE Category
**Repudiation** — An attacker performs an action and then denies having
done it, or reuses a legitimate action to gain unauthorized access.

## Attack Description
In normal OCPP 1.6-J operation, an `Authorize` message is sent from the
Charge Point to the CSMS when a user presents their RFID card or app
credential. The CSMS validates the `idTag` and responds with
`Authorize.conf` containing `idTagInfo.status: "Accepted"` or "Blocked", etc.

In a replay attack, an attacker captures a legitimate `Authorize` message
(including its `uniqueId` and `idTag`) and **re-sends it** to the CSMS.
If the CSMS does not track message IDs for deduplication, it may accept the
replayed message as a new authorization. This allows the attacker to:
- Start a second charging session without the original RFID card present
- Charge for free by replaying someone else's authorization
- Create **non-repudiable** sessions — the real cardholder can deny they
  started the second session, but the system logged their `idTag`.

## Detection Signals
1. The `unique_id` (messageId) of the incoming `Authorize` message has been
   **seen before** — it exists in the `known_message_ids` list.
2. The same `idTag` + `unique_id` combination was previously processed
   within a defined time window.
3. The message arrives from a **different Charge Point** than the original
   (the original was at CP-NORTH-01, but the replay comes from CP-SOUTH-02).

## Impact
- Free charging sessions at the expense of the legitimate cardholder
- Audit trail confusion — logs show the same user at two places simultaneously
- Undermines the integrity of the authorization system

## Relevant OCPP Spec Sections
- Section 5.2: Authorize
- Section 4.1: Message structure and uniqueId correlation
- Section 3.7: Authorization Cache

## OCPP Security Recommendation
The CSMS should maintain a **message deduplication cache** that tracks recently
processed `uniqueId` values. Any incoming message with a `uniqueId` that has
already been processed should be rejected or flagged. Additionally, using
TLS for the WebSocket connection (wss://) prevents message interception that
enables replay attacks. OCPP 2.0.1 adds improved security profiles with
certificate-based authentication that mitigate this attack class.
