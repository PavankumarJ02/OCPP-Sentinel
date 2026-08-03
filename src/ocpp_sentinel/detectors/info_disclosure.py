# =============================================================================
# detectors/info_disclosure.py — Information Disclosure Detector
# =============================================================================

import re
from typing import Optional
from ocpp_sentinel.models import OCPPMessage, OCPPAction, StatusNotificationPayload
from ocpp_sentinel.detectors.base import BaseDetector, DetectionResult

# Pattern to look for tokens, idTags, or keys leaking in plaintext
SENSITIVE_PATTERNS = [
    r"idTag\s*=\s*[A-Za-z0-9_-]+",
    r"token\s*=\s*[A-Za-z0-9_-]+",
    r"sk_live_[A-Za-z0-9]+",
    r"sk_test_[A-Za-z0-9]+",
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",  # JWT pattern
    r"RFID-[A-Za-z0-9]+",
]


class InfoDisclosureDetector(BaseDetector):
    """
    Detects Information Disclosure: token / idTag appearing in plaintext in diagnostic fields (info, vendorId).
    """

    @property
    def target_action(self) -> Optional[OCPPAction]:
        return OCPPAction.STATUS_NOTIFICATION

    def detect(self, message: OCPPMessage) -> DetectionResult:
        if message.action != OCPPAction.STATUS_NOTIFICATION:
            return DetectionResult(
                detected=False,
                attack_category="Information Disclosure",
                confidence=0.0,
                rule_name="PlaintextTokenLeakCheck",
                details="Not a StatusNotification message.",
            )

        payload: StatusNotificationPayload = message.get_typed_payload()
        fields_to_check = {
            "info": payload.info or "",
            "vendorId": payload.vendorId or "",
            "vendorErrorCode": payload.vendorErrorCode or "",
        }

        matched_leaks = []

        for field_name, value in fields_to_check.items():
            for pattern in SENSITIVE_PATTERNS:
                matches = re.findall(pattern, value)
                if matches:
                    matched_leaks.append(f"{field_name} matches '{pattern}' ({matches})")

        if matched_leaks:
            return DetectionResult(
                detected=True,
                attack_category="Information Disclosure",
                confidence=0.92,
                rule_name="PlaintextTokenInDiagnosticFieldRule",
                details=(
                    f"Plaintext token/credential pattern detected in diagnostic fields: "
                    + ", ".join(matched_leaks)
                ),
                suggested_query="idTag token appearing in plaintext in StatusNotification info field",
            )

        return DetectionResult(
            detected=False,
            attack_category="Information Disclosure",
            confidence=0.0,
            rule_name="PlaintextTokenLeakCheck",
            details="No plaintext tokens found in diagnostic fields.",
        )
