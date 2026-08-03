# =============================================================================
# detectors/spoofing.py — Spoofing Attack Detector
# =============================================================================

from typing import Optional
from ocpp_sentinel.models import OCPPMessage, OCPPAction, RemoteStartTransactionPayload
from ocpp_sentinel.detectors.base import BaseDetector, DetectionResult


class SpoofingDetector(BaseDetector):
    """
    Detects Spoofing attacks: RemoteStartTransaction with an idTag not present in authorized list.
    """

    @property
    def target_action(self) -> Optional[OCPPAction]:
        return OCPPAction.REMOTE_START_TRANSACTION

    def detect(self, message: OCPPMessage) -> DetectionResult:
        if message.action != OCPPAction.REMOTE_START_TRANSACTION:
            return DetectionResult(
                detected=False,
                attack_category="Spoofing",
                confidence=0.0,
                rule_name="RemoteStartAuthorizationCheck",
                details="Not a RemoteStartTransaction message.",
            )

        payload: RemoteStartTransactionPayload = message.get_typed_payload()
        id_tag = payload.idTag
        authorized_tags = message.context.authorized_id_tags

        # If authorized list is provided and id_tag is not in it -> Spoofing detected!
        if authorized_tags and id_tag not in authorized_tags:
            return DetectionResult(
                detected=True,
                attack_category="Spoofing",
                confidence=0.95,
                rule_name="RemoteStartUnauthTagRule",
                details=(
                    f"RemoteStartTransaction requested for idTag '{id_tag}', "
                    f"which is NOT present in the authorized tags list: {authorized_tags}."
                ),
                suggested_query="RemoteStartTransaction with fake unauthorized idTag spoofing",
            )

        return DetectionResult(
            detected=False,
            attack_category="Spoofing",
            confidence=0.0,
            rule_name="RemoteStartAuthorizationCheck",
            details="idTag is authorized or no authorization list provided.",
        )
