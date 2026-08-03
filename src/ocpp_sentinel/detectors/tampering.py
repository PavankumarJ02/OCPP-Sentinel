# =============================================================================
# detectors/tampering.py — Tampering Attack Detector
# =============================================================================

from datetime import datetime
from typing import Optional
from ocpp_sentinel.models import OCPPMessage, OCPPAction, MeterValuesPayload
from ocpp_sentinel.detectors.base import BaseDetector, DetectionResult


class TamperingDetector(BaseDetector):
    """
    Detects Tampering attacks: MeterValues reporting implausibly low energy for session duration.
    """

    @property
    def target_action(self) -> Optional[OCPPAction]:
        return OCPPAction.METER_VALUES

    def detect(self, message: OCPPMessage) -> DetectionResult:
        if message.action != OCPPAction.METER_VALUES:
            return DetectionResult(
                detected=False,
                attack_category="Tampering",
                confidence=0.0,
                rule_name="MeterValuePlausibilityCheck",
                details="Not a MeterValues message.",
            )

        payload: MeterValuesPayload = message.get_typed_payload()
        readings = payload.meterValue

        if len(readings) < 2:
            return DetectionResult(
                detected=False,
                attack_category="Tampering",
                confidence=0.0,
                rule_name="MeterValuePlausibilityCheck",
                details="Fewer than 2 meter readings provided; rate cannot be computed.",
            )

        try:
            # Sort readings by timestamp
            sorted_readings = sorted(
                readings, key=lambda r: datetime.fromisoformat(r.timestamp.replace("Z", "+00:00"))
            )
            t_start = datetime.fromisoformat(sorted_readings[0].timestamp.replace("Z", "+00:00"))
            t_end = datetime.fromisoformat(sorted_readings[-1].timestamp.replace("Z", "+00:00"))

            duration_hours = (t_end - t_start).total_seconds() / 3600.0

            if duration_hours <= 0.1:  # Less than 6 minutes
                return DetectionResult(
                    detected=False,
                    attack_category="Tampering",
                    confidence=0.0,
                    rule_name="MeterValuePlausibilityCheck",
                    details="Session duration too short to determine energy rate.",
                )

            # Get first and last active energy import values (in Wh)
            val_start = float(sorted_readings[0].sampledValue[0].value)
            val_end = float(sorted_readings[-1].sampledValue[0].value)

            energy_delivered_kwh = (val_end - val_start) / 1000.0
            rate_kwh_per_hour = energy_delivered_kwh / duration_hours

            # An active session under 0.5 kWh/hr is implausibly low (billing fraud)
            if rate_kwh_per_hour < 0.5:
                return DetectionResult(
                    detected=True,
                    attack_category="Tampering",
                    confidence=0.90,
                    rule_name="ImplausibleEnergyRateRule",
                    details=(
                        f"Implausibly low energy delivery rate: {rate_kwh_per_hour:.3f} kWh/hr "
                        f"({energy_delivered_kwh:.3f} kWh delivered over {duration_hours:.2f} hours). "
                        f"Threshold for active charging is 0.5 kWh/hr."
                    ),
                    suggested_query="MeterValues reporting very low energy billing fraud tampering",
                )
        except (ValueError, IndexError, KeyError) as e:
            return DetectionResult(
                detected=False,
                attack_category="Tampering",
                confidence=0.0,
                rule_name="MeterValuePlausibilityCheck",
                details=f"Could not parse meter values: {str(e)}",
            )

        return DetectionResult(
            detected=False,
            attack_category="Tampering",
            confidence=0.0,
            rule_name="MeterValuePlausibilityCheck",
            details="Energy rate is within normal parameters.",
        )
