# =============================================================================
# detectors/dispatcher.py — Detector Dispatcher
# =============================================================================

from typing import Optional
from ocpp_sentinel.models import OCPPMessage
from ocpp_sentinel.detectors.base import BaseDetector, DetectionResult
from ocpp_sentinel.detectors.spoofing import SpoofingDetector
from ocpp_sentinel.detectors.tampering import TamperingDetector
from ocpp_sentinel.detectors.repudiation import RepudiationDetector
from ocpp_sentinel.detectors.info_disclosure import InfoDisclosureDetector
from ocpp_sentinel.detectors.dos import DoSDetector


class DetectorDispatcher:
    """
    Routes an incoming OCPP message to all applicable rule-based detectors.
    """

    def __init__(self):
        self.detectors: list[BaseDetector] = [
            SpoofingDetector(),
            TamperingDetector(),
            RepudiationDetector(),
            InfoDisclosureDetector(),
            DoSDetector(),
        ]

    def run_all(self, message: OCPPMessage) -> list[DetectionResult]:
        """
        Run all matching detectors against the given message.

        Returns:
            List of DetectionResult objects.
        """
        results: list[DetectionResult] = []

        for detector in self.detectors:
            # Run if detector applies to all actions or matches the message action
            if detector.target_action is None or detector.target_action == message.action:
                result = detector.detect(message)
                results.append(result)

        return results

    def get_first_detection(self, message: OCPPMessage) -> Optional[DetectionResult]:
        """
        Returns the first detected attack result, or None if no attack is detected.
        """
        results = self.run_all(message)
        for res in results:
            if res.detected:
                return res
        return None
