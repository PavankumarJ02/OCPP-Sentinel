# OCPP 1.6-J Spec Excerpt: MeterValues (Section 5.11)

## Message Flow
The Charge Point sends `MeterValues.req` to the Central System to report
meter readings (energy consumption, power, voltage, current, etc.) for a
specific connector. These readings can be sent periodically during a
transaction or at transaction boundaries.

## MeterValues.req Fields
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| connectorId | Integer (>= 0) | Yes | Connector ID (0 = main power meter) |
| meterValue | MeterValue[1..*] | Yes | One or more timestamped meter readings |
| transactionId | Integer | No | Transaction these readings belong to |

## MeterValue Structure (Section 7.23)
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| timestamp | dateTime | Yes | Time the measurement was taken |
| sampledValue | SampledValue[1..*] | Yes | One or more measured values |

## SampledValue Structure (Section 7.33)
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| value | String | Yes | The measured value |
| context | String | No | Reading context: "Sample.Periodic", "Transaction.Begin", "Transaction.End", etc. |
| format | String | No | "Raw" or "SignedData" |
| measurand | String | No | What's being measured, default: "Energy.Active.Import.Register" |
| phase | String | No | Electrical phase: "L1", "L2", "L3", "L1-N", "L2-N", "L3-N", "L1-L2", "L2-L3", "L3-L1" |
| location | String | No | Measurement point: "Cable", "EV", "Inlet", "Outlet", "Body" |
| unit | String | No | Unit: "Wh", "kWh", "varh", "kvarh", "W", "kW", "VA", "kVA", "var", "kvar", "A", "V", "Celsius", "Fahrenheit", "K", "Percent" |

## Key Behaviors (from spec)
1. The Charge Point SHALL send `MeterValues.req` at intervals configured
   by the Central System via the `MeterValueSampleInterval` configuration key.
2. The `measurand` defaults to "Energy.Active.Import.Register" if not specified,
   which represents the cumulative active energy imported (consumed) in Wh.
3. Multiple `SampledValue` entries can be included in a single `MeterValue`
   to report different measurands at the same timestamp.
4. The `value` field is always a string representation of the numeric value.

## Security Considerations
- Meter values are critical for billing accuracy. Tampered values directly
  impact revenue.
- The `format: "SignedData"` option allows cryptographic signing of meter
  readings for integrity verification, but adoption is not universal.
- Plausibility checks (comparing reported energy to rated power × time)
  are recommended as a defense against tampered readings.
