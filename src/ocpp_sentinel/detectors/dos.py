# =============================================================================
# detectors/dos.py — Denial of Service Detector
# =============================================================================

from typing import Optional
from ocpp_sentinel.models import OCPPMessage, OCPPAction
from ocpp_sentinel.detectors.base import BaseDetector, DetectionResult


class DoSDetector(BaseDetector):
    """
    Detects Denial of Service: abnormal burst of StatusNotification messages in a short time window.
    """

    @property
    def target_action(self) -> Optional[OCPPAction]:
        return OCPPAction.STATUS_NOTIFICATION

    def detect(self, message: OCPPMessage) -> DetectionResult:
        if message.action != OCPPAction.STATUS_NOTIFICATION:
            return DetectionResult(
                detected=False,
                attack_category="Denial of Service",
                confidence=0.0,
                rule_name="RateLimitCheck",
                details="Not a StatusNotification message.",
            )

        recent_count = message.context.recent_message_count
        window_seconds = message.context.time_window_seconds

        # Threshold: > 30 messages in 60s window (or equivalent rate > 0.5 msgs/sec)
        threshold_rate = 30 / 60.0  # 0.5 msgs / second
        actual_rate = recent_count / max(1, window_seconds)

        if recent_count >= 30 and actual_rate >= threshold_rate:
            return DetectionResult(
                detected=True,
                attack_category="Denial of Service",
                confidence=0.95,
                rule_name="StatusNotificationBurstRule",
                details=(
                    f"Abnormal message burst from charge point '{message.charge_point_id}': "
                    f"{recent_count} messages in {window_seconds} seconds "
                    f"({actual_rate:.1f} msgs/sec). Threshold is 30 msgs in 60s."
                ),
                suggested_query="flood of StatusNotification messages overwhelming the system denial of service",
            )

        return DetectionResult(
            detected=False,
            attack_category="Denial of Service",
            confidence=0.0,
            rule_name="RateLimitCheck",
            details="Message frequency is within acceptable rate limits.",
        )
