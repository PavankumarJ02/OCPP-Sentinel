# =============================================================================
# detectors/repudiation.py — Repudiation Attack Detector
# =============================================================================

from typing import Optional
from ocpp_sentinel.models import OCPPMessage, OCPPAction
from ocpp_sentinel.detectors.base import BaseDetector, DetectionResult


class RepudiationDetector(BaseDetector):
    """
    Detects Repudiation / Replay attacks: Authorize message with a unique_id that was already processed.
    """

    @property
    def target_action(self) -> Optional[OCPPAction]:
        return OCPPAction.AUTHORIZE

    def detect(self, message: OCPPMessage) -> DetectionResult:
        if message.action != OCPPAction.AUTHORIZE:
            return DetectionResult(
                detected=False,
                attack_category="Repudiation",
                confidence=0.0,
                rule_name="ReplayCheck",
                details="Not an Authorize message.",
            )

        unique_id = message.unique_id
        known_ids = message.context.known_message_ids

        # If unique_id is already in known_message_ids -> Replay / Repudiation attack!
        if known_ids and unique_id in known_ids:
            return DetectionResult(
                detected=True,
                attack_category="Repudiation",
                confidence=0.98,
                rule_name="DuplicateMessageIdReplayRule",
                details=(
                    f"Authorize message has unique_id '{unique_id}', which was "
                    f"already processed in known_message_ids: {known_ids}."
                ),
                suggested_query="replayed Authorize message duplicate messageId repudiation",
            )

        return DetectionResult(
            detected=False,
            attack_category="Repudiation",
            confidence=0.0,
            rule_name="ReplayCheck",
            details="unique_id is fresh and not seen before.",
        )
