# =============================================================================
# api/schemas.py — Request & Response schemas for REST API
# =============================================================================

from typing import Any, Optional
from pydantic import BaseModel, Field

from ocpp_sentinel.agent import VerdictResponse


class HealthResponse(BaseModel):
    """
    Response model for GET /health endpoint.
    """
    status: str = Field(..., json_schema_extra={"example": "ok"})
    version: str = Field(..., json_schema_extra={"example": "0.1.0"})
    kb_chunks: int = Field(..., json_schema_extra={"example": 70})


class AnalyzeRequest(BaseModel):
    """
    Request payload for POST /analyze endpoint.
    Accepts raw OCPP 1.6-J JSON structure or dictionary.
    """
    message: dict[str, Any] = Field(
        ...,
        description="The full OCPP 1.6-J JSON message envelope with action, payload, charge_point_id, and context.",
    )


class AnalyzeResponse(BaseModel):
    """
    Standardized response returned by POST /analyze endpoint.
    """
    success: bool = Field(default=True, description="Whether analysis completed successfully")
    processing_time_ms: float = Field(..., description="Time taken for complete triage in milliseconds")
    analysis: VerdictResponse = Field(..., description="Structured verdict from the LangGraph agent")
