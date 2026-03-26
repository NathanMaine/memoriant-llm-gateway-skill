"""Logging and telemetry for the governed LLM gateway.

Emits structured log records to stdout and appends them to an append-only
log file for local review.
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("gateway")


def setup_logging(log_file: str) -> None:
    """Configure the gateway logger with stdout and file handlers.

    Args:
        log_file: Path to the append-only log file.
    """
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        # Stdout handler
        stdout_handler = logging.StreamHandler()
        stdout_handler.setLevel(logging.INFO)
        stdout_fmt = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
        stdout_handler.setFormatter(stdout_fmt)
        logger.addHandler(stdout_handler)

        # File handler (append-only)
        log_path = Path(log_file)
        os.makedirs(log_path.parent, exist_ok=True)
        file_handler = logging.FileHandler(log_path, mode="a")
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(stdout_fmt)
        logger.addHandler(file_handler)


def log_request(
    *,
    client_id: str,
    alias: str,
    provider: Optional[str],
    outcome: str,
    usage: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None,
    request_id: Optional[str] = None
) -> None:
    """Log a single request event.

    This writes a structured JSON line to both stdout and the log file.

    Args:
        client_id: The caller's identifier.
        alias: The model alias requested.
        provider: The resolved provider name (None if routing failed).
        outcome: Short outcome label (e.g. "success", "rate_limited", "error").
        usage: Token usage dict if available.
        error: Error message if the request failed.
        request_id: Gateway-assigned request ID.
    """
    record: Dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": request_id,
        "client_id": client_id,
        "alias": alias,
        "provider": provider,
        "outcome": outcome,
    }

    if usage:
        record["usage"] = usage

    if error:
        record["error"] = error

    logger.info(json.dumps(record))
