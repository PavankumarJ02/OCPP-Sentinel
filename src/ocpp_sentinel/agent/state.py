# =============================================================================
# agent/state.py — Agent state schema and Verdict model
# =============================================================================

from typing import Any, Optional, TypedDict
from pydantic import BaseModel, Field

from ocpp_sentinel.models import OCPPMessage
from ocpp_sentinel.detectors import DetectionResult


class VerdictResponse(BaseModel):
    """
    Final security verdict returned by the LangGraph agent.
    Grounded in rule detection + vector RAG knowledge retrieval.
    """
    verdict: str = Field(
        ...,
        description="Verdict status: 'normal' or 'suspicious'",
    )
    matched_attack_category: str = Field(
        ...,
        description="One of: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, or None",
    )
    confidence: float = Field(
        ...,
        description="Confidence score between 0.0 and 1.0",
        ge=0.0,
        le=1.0,
    )
    plain_english_reason: str = Field(
        ...,
        description="Clear, accessible explanation of the analysis and finding",
    )
    source_reference: str = Field(
        ...,
        description="Specific knowledge-base document or spec section supporting this verdict",
    )
    rule_detected: bool = Field(
        default=False,
        description="Whether a deterministic rule triggered during analysis",
    )


class AgentState(TypedDict, total=False):
    """
    LangGraph state dictionary passed between nodes in the graph.
    """
    # Raw JSON message input
    raw_message: dict[str, Any]

    # Parsed & validated Pydantic OCPPMessage object
    message: Optional[OCPPMessage]

    # Result from Phase 3 rule-based detector
    detection_result: Optional[DetectionResult]

    # Retrived context documents from Phase 2 ChromaDB vector store
    retrieved_attacks: list[dict[str, Any]]
    retrieved_specs: list[dict[str, Any]]

    # Final verdict output
    verdict: Optional[VerdictResponse]

    # Errors encountered during execution
    error: Optional[str]
