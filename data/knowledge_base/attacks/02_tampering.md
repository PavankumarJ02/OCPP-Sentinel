# Attack: Tampering via MeterValues Manipulation

## STRIDE Category
**Tampering** — An attacker modifies data in transit or at rest to achieve
a malicious goal.

## Attack Description
During an active charging session, the Charge Point periodically sends
`MeterValues` messages to the CSMS reporting how much energy has been delivered.
These readings are used for **billing** — the customer is charged based on the
energy consumed (measured in Wh or kWh).

In a tampering attack, the Charge Point's firmware is modified (or the messages
are intercepted and altered in transit) to report **implausibly low energy
values**. For example, a session that actually delivered 15 kWh over 2 hours
might report only 0.05 kWh. This is **billing fraud** — the customer (or a
complicit operator) pays almost nothing for the energy consumed.

## Detection Signals
1. Calculate the energy delivered: difference between the last and first
   `sampledValue` with `measurand: "Energy.Active.Import.Register"`.
2. Calculate the session duration from the `timestamp` fields in the
   `meterValue` array.
3. Compute the **effective charging rate**: energy (kWh) ÷ duration (hours).
4. Flag as suspicious if the rate is **below 0.5 kWh/hour** for a session
   where the Charge Point status is "Charging". A typical Level 2 AC charger
   delivers 7-19 kWh/hr; a DC fast charger delivers 50-350 kWh/hr. Even a
   slow trickle charge delivers at least 1-2 kWh/hr.

## Impact
- Revenue loss for charging station operators
- Energy theft at scale
- Undermines trust in metering infrastructure

## Relevant OCPP Spec Sections
- Section 5.11: MeterValues
- Section 7.33: SampledValue (data format for meter readings)
- Section 7.23: MeterValue (timestamped collection of samples)

## OCPP Security Recommendation
The CSMS should implement plausibility checks on meter readings. If a Charge
Point reports energy consumption that is physically impossible given the
connector type, rated power, and session duration, the reading should be
flagged for manual review. Signed meter data (using the `format: "SignedData"`
field) provides cryptographic integrity protection but is not universally
deployed.
