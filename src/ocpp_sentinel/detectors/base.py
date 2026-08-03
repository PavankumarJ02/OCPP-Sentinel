# =============================================================================
# detectors/base.py — Base class and data structures for rule-based detectors
# =============================================================================

from abc import ABC, abstractmethod
from typing import Optional
from pydantic import BaseModel, Field

from ocpp_sentinel.models import OCPPMessage, OCPPAction


class DetectionResult(BaseModel):
    """
    Structured outcome of a rule-based security detector check.
    """
    detected: bool = Field(
        ...,
        description="True if an attack pattern was detected",
    )
    attack_category: str = Field(
        ...,
        description="One of: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, or None",
    )
    confidence: float = Field(
        ...,
        description="Confidence score between 0.0 and 1.0",
        ge=0.0,
        le=1.0,
    )
    rule_name: str = Field(
        ...,
        description="Name of the detection rule triggered",
    )
    details: str = Field(
        ...,
        description="Plain-English summary of why the rule triggered",
    )
    suggested_query: Optional[str] = Field(
        default=None,
        description="Suggested search query for RAG retrieval in ChromaDB",
    )


class BaseDetector(ABC):
    """
    Abstract base class for all attack detectors.
    """
    @property
    @abstractmethod
    def target_action(self) -> Optional[OCPPAction]:
        """
        The OCPP action this detector targets (or None if it handles all actions).
        """
        pass

    @abstractmethod
    def detect(self, message: OCPPMessage) -> DetectionResult:
        """
        Run detection logic against an OCPP message.
        """
        pass
