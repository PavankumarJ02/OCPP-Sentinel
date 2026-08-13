# =============================================================================
# api/routes.py — FastAPI Endpoint Handlers
# =============================================================================

import json
import time
from pathlib import Path
from typing import Any
from fastapi import APIRouter, HTTPException, Query, Request, status

from ocpp_sentinel import __version__
from ocpp_sentinel.agent import run_sentinel_agent
from ocpp_sentinel.knowledge import KnowledgeBaseRetriever
from ocpp_sentinel.logging_config import log_audit_event, AUDIT_LOG_FILE
from ocpp_sentinel.api.schemas import (
    HealthResponse,
    AnalyzeRequest,
    AnalyzeResponse,
    StatsResponse,
    AuditEntry,
    AuditLogResponse,
)

router = APIRouter()

# ---------------------------------------------------------------------------
# In-memory runtime stats (reset on server restart)
# ---------------------------------------------------------------------------
_stats: dict[str, Any] = {
    "total_analyzed": 0,
    "threats_detected": 0,
    "normal_count": 0,
    "total_latency_ms": 0.0,
}


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


@router.get("/stats", response_model=StatsResponse, summary="Get runtime analysis statistics")
async def get_stats() -> StatsResponse:
    """
    Return aggregate runtime statistics accumulated since the server started.
    Counters increment with every POST /analyze request and reset on restart.
    """
    total = _stats["total_analyzed"]
    avg_latency = (_stats["total_latency_ms"] / total) if total > 0 else 0.0
    return StatsResponse(
        total_analyzed=total,
        threats_detected=_stats["threats_detected"],
        normal_count=_stats["normal_count"],
        avg_latency_ms=round(avg_latency, 2),
    )


@router.get("/audit", response_model=AuditLogResponse, summary="Retrieve recent audit log entries")
async def get_audit_log(limit: int = Query(default=50, ge=1, le=500, description="Max entries to return")) -> AuditLogResponse:
    """
    Read the last `limit` entries from the persisted audit.jsonl file.
    Returns entries ordered newest-first for easy table display.
    Gracefully returns an empty list if the log file does not yet exist.
    """
    entries: list[AuditEntry] = []

    if not AUDIT_LOG_FILE.exists():
        return AuditLogResponse(entries=[], total_returned=0)

    try:
        lines = AUDIT_LOG_FILE.read_text(encoding="utf-8").splitlines()
        # Take the last `limit` lines (newest) and reverse for newest-first order
        recent_lines = lines[-limit:][::-1]

        for line in recent_lines:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                audit = record.get("audit", {})
                if not audit:
                    continue
                entries.append(
                    AuditEntry(
                        timestamp=record.get("timestamp", ""),
                        action=audit.get("action", "Unknown"),
                        charge_point_id=audit.get("charge_point_id", "Unknown"),
                        verdict=audit.get("verdict", "unknown"),
                        attack_category=audit.get("attack_category", "None"),
                        confidence=float(audit.get("confidence", 0.0)),
                        processing_time_ms=float(audit.get("processing_time_ms", 0.0)),
                        details=audit.get("details", ""),
                    )
                )
            except (json.JSONDecodeError, KeyError, ValueError):
                continue  # Skip malformed lines gracefully
    except OSError:
        pass

    return AuditLogResponse(entries=entries, total_returned=len(entries))


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

    # Update in-memory runtime stats
    _stats["total_analyzed"] += 1
    _stats["total_latency_ms"] += elapsed_ms
    if verdict.verdict.lower() == "suspicious":
        _stats["threats_detected"] += 1
    else:
        _stats["normal_count"] += 1

    return AnalyzeResponse(
        success=True,
        processing_time_ms=round(elapsed_ms, 2),
        analysis=verdict,
    )



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
