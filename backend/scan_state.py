"""Thread-safe state for the single manually triggered OCR scan."""

from datetime import datetime, timezone
from pathlib import Path
import threading
import uuid

from fastapi import HTTPException


scan_progress_lock = threading.Lock()
scan_progress = {
    "active": False,
    "job_id": "",
    "month": "",
    "started_at": "",
    "finished_at": "",
    "total": 0,
    "completed": 0,
    "current_file": "",
    "succeeded": 0,
    "failed": 0,
    "failed_files": [],
    "cancel_requested": False,
    "stopped": False,
    "cache_hits": 0,
    "content_cache_hits": 0,
    "fast_passes": 0,
    "full_quality_passes": 0,
    "full_quality_fallbacks": 0,
    "ai_fallbacks": 0,
    "ai_cache_hits": 0,
    "ai_failures": 0,
    "owner": None,
}

def reset_scan_progress(month: str, total: int):
    """Claim the single OCR job slot and initialise observable scan state."""
    with scan_progress_lock:
        if scan_progress.get("active"):
            raise HTTPException(status_code=409, detail="An OCR scan is already running.")
        scan_progress.update({
            "active": True,
            "job_id": uuid.uuid4().hex,
            "month": month,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "finished_at": "",
            "total": total,
            "completed": 0,
            "current_file": "",
            "succeeded": 0,
            "failed": 0,
            "failed_files": [],
            "cancel_requested": False,
            "stopped": False,
            "cache_hits": 0,
            "content_cache_hits": 0,
            "fast_passes": 0,
            "full_quality_passes": 0,
            "full_quality_fallbacks": 0,
            "ai_fallbacks": 0,
            "ai_cache_hits": 0,
            "ai_failures": 0,
            "owner": threading.get_ident(),
        })

def update_scan_progress(file_path: Path, *, failed: bool = False):
    """Record one attempted file without allowing failures to disappear."""
    with scan_progress_lock:
        scan_progress["completed"] = min(int(scan_progress.get("completed", 0)) + 1, int(scan_progress.get("total", 0)))
        scan_progress["current_file"] = file_path.name
        metric = "failed" if failed else "succeeded"
        scan_progress[metric] = int(scan_progress.get(metric, 0)) + 1
        if failed:
            failed_files = list(scan_progress.get("failed_files", []))
            if len(failed_files) < 20:
                failed_files.append(file_path.name)
            scan_progress["failed_files"] = failed_files

def increment_scan_metric(name: str):
    """Increment an OCR metric only while a user-triggered scan is active."""
    with scan_progress_lock:
        if scan_progress.get("active") and name in scan_progress:
            scan_progress[name] = int(scan_progress.get(name, 0)) + 1


def is_scan_cancel_requested(month: str = ""):
    """Read the cooperative cancellation flag without exposing mutable state."""
    with scan_progress_lock:
        return bool(
            scan_progress.get("active")
            and scan_progress.get("cancel_requested")
            and (not month or scan_progress.get("month") == month)
        )

def request_scan_cancel():
    """Ask the active job to stop before starting its next expensive OCR call."""
    with scan_progress_lock:
        if not scan_progress.get("active"):
            return False
        scan_progress["cancel_requested"] = True
        return True

def finish_scan_progress(month: str):
    with scan_progress_lock:
        if scan_progress.get("month") == month and scan_progress.get("owner") == threading.get_ident():
            was_stopped = bool(scan_progress.get("cancel_requested"))
            scan_progress["active"] = False
            scan_progress["cancel_requested"] = False
            scan_progress["stopped"] = was_stopped
            scan_progress["finished_at"] = datetime.now(timezone.utc).isoformat()
            scan_progress["owner"] = None

def get_scan_progress_snapshot():
    with scan_progress_lock:
        snapshot = scan_progress.copy()
    snapshot.pop("owner", None)
    total = int(snapshot.get("total", 0))
    completed = int(snapshot.get("completed", 0))
    snapshot["percent"] = round((completed / total) * 100) if total else 0
    if snapshot.get("active"):
        outcome = "running"
    elif snapshot.get("stopped"):
        outcome = "stopped"
    elif int(snapshot.get("failed", 0)):
        outcome = "completed_with_errors"
    else:
        outcome = "completed"
    snapshot["outcome"] = outcome

    return snapshot
