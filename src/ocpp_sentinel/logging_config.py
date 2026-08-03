# =============================================================================
# logging_config.py — Structured JSON Logging & Audit Trail Configuration
# =============================================================================
#
# LEARNING NOTE: WHY STRUCTURED LOGGING?
# Unstructured logs (plain text lines) are hard for machines to search or analyze.
# Structured logs (JSON lines) allow log management systems (Datadog, Elastic, Loki)
# to instantly filter, index, and alert on fields like:
#   - verdict: "suspicious"
#   - attack_category: "Spoofing"
#   - processing_time_ms > 100
#
# Each log line in `logs/audit.jsonl` is a valid JSON object.
# =============================================================================

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Directory where audit log files will be written
LOGS_DIR = Path(__file__).parent.parent.parent / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)

AUDIT_LOG_FILE = LOGS_DIR / "audit.jsonl"


class JSONFormatter(logging.Formatter):
    """
    Formats log records as single-line JSON objects (JSON Lines format).
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Include custom context extra fields passed to logger.info(..., extra={...})
        if hasattr(record, "audit_data") and isinstance(record.audit_data, dict):
            log_entry["audit"] = record.audit_data

        return json.dumps(log_entry)


def setup_logging(log_level: int = logging.INFO) -> logging.Logger:
    """
    Initialize and return the root application logger with both
    Console and JSON File (audit.jsonl) handlers.
    """
    logger = logging.getLogger("ocpp_sentinel")
    logger.setLevel(log_level)

    # Avoid duplicate handlers if already configured
    if logger.handlers:
        return logger

    # 1. File Handler (JSON lines -> logs/audit.jsonl)
    file_handler = logging.FileHandler(AUDIT_LOG_FILE, encoding="utf-8")
    file_handler.setLevel(log_level)
    file_handler.setFormatter(JSONFormatter())

    # 2. Console Handler (human readable)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_format = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    console_handler.setFormatter(console_format)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


# Shared logger instance
logger = setup_logging()


def log_audit_event(
    action: str,
    charge_point_id: str,
    verdict: str,
    attack_category: str,
    confidence: float,
    processing_time_ms: float,
    details: str,
    client_ip: str = "127.0.0.1",
):
    """
    Helper function to record an immutable audit event to audit.jsonl.
    """
    audit_data = {
        "event_type": "security_triage",
        "action": action,
        "charge_point_id": charge_point_id,
        "verdict": verdict,
        "attack_category": attack_category,
        "confidence": confidence,
        "processing_time_ms": processing_time_ms,
        "client_ip": client_ip,
        "details": details,
    }

    logger.info(
        f"Audit Event: {charge_point_id} -> {action} -> Verdict: {verdict.upper()} ({attack_category})",
        extra={"audit_data": audit_data},
    )
