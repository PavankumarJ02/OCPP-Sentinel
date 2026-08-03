# =============================================================================
# api/routes.py — FastAPI Endpoint Handlers
# =============================================================================

import time
from typing import Any
from fastapi import APIRouter, HTTPException, Request, status

from ocpp_sentinel import __version__
from ocpp_sentinel.agent import run_sentinel_agent
from ocpp_sentinel.knowledge import KnowledgeBaseRetriever
from ocpp_sentinel.logging_config import log_audit_event
from ocpp_sentinel.api.schemas import HealthResponse, AnalyzeRequest, AnalyzeResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse, summary="Check API health")
async def health_check() -> HealthResponse:
    """
    Check server status and Knowledge Base chunk count in ChromaDB.
    """
    try:
        retriever = KnowledgeBaseRetriever()
        kb_chunks = retriever.document_count
    except Exception:
        kb_chunks = 0

    return HealthResponse(
        status="ok",
        version=__version__,
        kb_chunks=kb_chunks,
    )


@router.post("/analyze", response_model=AnalyzeResponse, summary="Analyze an OCPP message for security threats")
async def analyze_ocpp_message(request: Request) -> AnalyzeResponse:
    """
    Triage an incoming OCPP 1.6-J JSON message using the LangGraph AI agent.

    Accepts either:
      1. Wrapped format:  {"message": { "action": "Authorize", ... }}
      2. Direct format:   { "action": "Authorize", ... }

    - Validates message schema
    - Runs 5 rule-based STRIDE attack detectors
    - Retrieves grounding documentation from ChromaDB vector store
    - Returns structured verdict with plain-English explanation & spec citations
    - Writes immutable structured JSON audit record to logs/audit.jsonl
    """
    start_time = time.perf_counter()

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON body.",
        )

    # Support both {"message": {...}} wrapped and raw message JSON
    if isinstance(body, dict) and "message" in body and isinstance(body["message"], dict):
        msg_dict = body["message"]
    elif isinstance(body, dict):
        msg_dict = body
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request body must be a JSON object.",
        )

    try:
        verdict = run_sentinel_agent(msg_dict)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Agent orchestration error: {str(e)}",
        )

    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    # Extract metadata for audit trail
    action = msg_dict.get("action", "Unknown")
    cp_id = msg_dict.get("charge_point_id", "Unknown")
    client_ip = request.client.host if request.client else "127.0.0.1"

    # Write audit log record
    log_audit_event(
        action=action,
        charge_point_id=cp_id,
        verdict=verdict.verdict,
        attack_category=verdict.matched_attack_category,
        confidence=verdict.confidence,
        processing_time_ms=round(elapsed_ms, 2),
        details=verdict.plain_english_reason,
        client_ip=client_ip,
    )

    return AnalyzeResponse(
        success=True,
        processing_time_ms=round(elapsed_ms, 2),
        analysis=verdict,
    )
