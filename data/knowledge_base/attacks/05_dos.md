# Attack: Denial of Service via StatusNotification Flood

## STRIDE Category
**Denial of Service (DoS)** — An attacker makes a system unavailable to
legitimate users by overwhelming it with traffic.

## Attack Description
The `StatusNotification` message in OCPP 1.6-J is sent by the Charge Point
to the CSMS whenever its status changes (e.g., from "Available" to
"Preparing" to "Charging"). Under normal operation, a Charge Point sends
these messages infrequently — typically a few per minute at most, and
often only during state transitions.

In a DoS attack, a compromised or malicious Charge Point sends a massive
flood of `StatusNotification` messages — potentially hundreds or thousands
per minute. Each message must be processed by the CSMS, consuming:
- **Network bandwidth** on the WebSocket connection
- **CPU time** for message parsing and validation
- **Database writes** if all status updates are logged
- **Memory** for maintaining connection state

If enough messages are sent, the CSMS may become overwhelmed and unable
to process legitimate messages from other Charge Points. This can cause:
- Legitimate charging sessions to fail to start
- Billing records to be lost
- Monitoring and alerting systems to become unreliable

## Detection Signals
1. Count the number of messages received from a single `chargePointId`
   within a sliding time window (e.g., 60 seconds).
2. Flag as suspicious if the count exceeds a threshold — for example:
   - **> 30 messages per minute** is unusual for most Charge Points
   - **> 60 messages per minute** is almost certainly a flood
   - **> 100 messages per minute** is definite DoS
3. Check if the status values are cycling rapidly (e.g., Available →
   Charging → Available → Charging in quick succession), which has no
   legitimate physical cause.

## Impact
- CSMS becomes unavailable for other Charge Points
- Revenue loss from failed charging sessions
- Customer frustration and trust erosion
- Potential cascade failure if the CSMS is shared across multiple sites

## Relevant OCPP Spec Sections
- Section 5.18: StatusNotification
- Section 7.27: ChargePointStatus (valid status values)
- Section 3.1: Connection management and WebSocket handling

## OCPP Security Recommendation
The CSMS should implement **rate limiting** per Charge Point connection.
Messages exceeding a configurable threshold should be dropped or queued.
The CSMS should also monitor for abnormal patterns and alert operators.
Network-level protections (firewall rules, connection throttling) provide
an additional layer of defense. OCPP 2.0.1's security profiles include
certificate-based mutual authentication, which makes it harder for
rogue devices to connect to the CSMS.
