"""Append-only local audit events for operational changes and scan lifecycle."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import threading


AUDIT_FILE = Path("audit.jsonl")
audit_lock = threading.Lock()

OPERATOR_ANONYMOUS = "local operator (identity not authenticated)"


def configure_audit_store(base_dir: Path) -> None:
    global AUDIT_FILE
    AUDIT_FILE = base_dir / "audit.jsonl"


def record_audit_event(event: str, *, actor: str = OPERATOR_ANONYMOUS, details=None) -> None:
    """Durably append one bounded JSON event without logging evidence content."""
    safe_details = details if isinstance(details, dict) else {}
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": str(event)[:128],
        "actor": str(actor)[:128],
        "details": safe_details,
    }
    encoded = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
    with audit_lock:
        AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_FILE, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded + "\n")
            handle.flush()
            os.fsync(handle.fileno())
