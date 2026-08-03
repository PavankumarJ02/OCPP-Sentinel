# Attack: Spoofing via RemoteStartTransaction

## STRIDE Category
**Spoofing** — An attacker pretends to be a legitimate user or system.

## Attack Description
In OCPP 1.6-J, the `RemoteStartTransaction` message is sent by the Central System
(CSMS) to a Charge Point, instructing it to start a charging session for a specific
`idTag`. This is the legitimate use case — for example, a user starts charging from
a mobile app, and the CSMS tells the charger to begin.

The spoofing attack occurs when an attacker sends a `RemoteStartTransaction` with
an `idTag` that has **never been authorized** by the system. If the Charge Point
does not independently verify the `idTag` against a local authorization list or
cache, it may blindly start a session. This results in **free charging** at the
expense of the station operator.

## Detection Signals
1. The `idTag` in the `RemoteStartTransaction.req` payload does NOT appear in
   the system's list of authorized ID tags.
2. There is no corresponding `Authorize.conf` with `status: "Accepted"` for
   this `idTag` in recent history.
3. The `idTag` format doesn't match the expected pattern (e.g., wrong prefix,
   unexpected length).

## Impact
- Financial loss: attacker charges for free
- Accountability gap: no valid identity tied to the session
- Potential for large-scale abuse if automated

## Relevant OCPP Spec Sections
- Section 5.13: RemoteStartTransaction
- Section 5.2: Authorize
- Section 3.7: Authorization Cache / Local Authorization List

## OCPP Security Recommendation
The OCPP 1.6-J spec recommends that Charge Points maintain a Local Authorization
List and/or Authorization Cache. Before accepting a `RemoteStartTransaction`, the
Charge Point should verify the `idTag` against these lists. The CSMS should also
validate that the `idTag` is known and active before sending the command.
