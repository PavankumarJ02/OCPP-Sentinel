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


class StatsResponse(BaseModel):
    """
    Aggregate runtime statistics returned by GET /stats endpoint.
    Counters are in-memory and reset on server restart.
    """
    total_analyzed: int = Field(default=0, description="Total number of messages analyzed since server start")
    threats_detected: int = Field(default=0, description="Total suspicious verdicts issued since server start")
    normal_count: int = Field(default=0, description="Total normal (benign) verdicts issued since server start")
    avg_latency_ms: float = Field(default=0.0, description="Rolling average processing time in milliseconds")


class AuditEntry(BaseModel):
    """
    A single audit event record loaded from logs/audit.jsonl.
    """
    timestamp: str = Field(..., description="ISO-8601 timestamp of the event")
    action: str = Field(..., description="OCPP action (e.g., Authorize, MeterValues)")
    charge_point_id: str = Field(..., description="Charge point identifier")
    verdict: str = Field(..., description="'normal' or 'suspicious'")
    attack_category: str = Field(..., description="STRIDE category or 'None'")
    confidence: float = Field(..., description="Confidence score 0.0–1.0")
    processing_time_ms: float = Field(..., description="Analysis latency in milliseconds")
    details: str = Field(..., description="Plain-English triage summary")


class AuditLogResponse(BaseModel):
    """
    Response model for GET /audit endpoint.
    Returns the last N audit events from the persisted JSONL log file.
    """
    entries: list[AuditEntry] = Field(default_factory=list, description="List of recent audit events, newest first")
    total_returned: int = Field(..., description="Number of entries returned")

