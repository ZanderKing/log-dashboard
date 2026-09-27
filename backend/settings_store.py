"""Persistent signature thresholds and manual verification decisions."""

from __future__ import annotations

from datetime import datetime, timezone
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import threading

from storage import write_json_atomic
from audit_store import OPERATOR_ANONYMOUS


DATA_DIR = Path(".")
THRESHOLDS_FILE = Path("thresholds.json")
VERIFICATIONS_FILE = Path("verifications.json")
threshold_lock = threading.Lock()
verification_lock = threading.Lock()
current_thresholds: dict[str, float] = {}
manual_verifications: dict[str, dict[str, object]] = {}


def configure_settings_store(base_dir: Path, data_dir: Path) -> None:
    """Bind portable paths and load state while preserving shared references."""
    global DATA_DIR, THRESHOLDS_FILE, VERIFICATIONS_FILE
    DATA_DIR = data_dir
    THRESHOLDS_FILE = base_dir / "thresholds.json"
    VERIFICATIONS_FILE = base_dir / "verifications.json"
    current_thresholds.clear()
    current_thresholds.update(load_thresholds())
    manual_verifications.clear()
    manual_verifications.update(load_verifications())


# --- PERSISTENT SETTINGS LOGIC ---
DEFAULT_THRESHOLDS = {
    "mcafee": 6127.0,
    "clamwin": 1.0,
    "trellix": 1.0,
    "symantec": 1.0,
    "zero_threat_confidence": 0.90,
    "ocr_strictness": "high",
}

def load_thresholds():
    if THRESHOLDS_FILE.exists():
        try:
            with open(THRESHOLDS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                # Merge defaults without coercing the string strictness profile
                # to float. Invalid individual values do not discard all other
                # persisted settings.
                merged = DEFAULT_THRESHOLDS.copy()
                for key, value in data.items():
                    if key not in DEFAULT_THRESHOLDS:
                        continue
                    if key == "ocr_strictness":
                        if value in {"high", "medium", "low"}:
                            merged[key] = value
                        continue
                    try:
                        merged[key] = float(value)
                    except (TypeError, ValueError):
                        continue
                return merged
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            pass
    return DEFAULT_THRESHOLDS.copy()


def save_thresholds():
    write_json_atomic(THRESHOLDS_FILE, current_thresholds, indent=2)

def normalize_saved_verification_key(value: str):
    """Convert legacy absolute ``.../2026/...`` keys to portable relative keys."""
    normalized = str(value).replace("\\", "/")
    marker = "/2026/"
    if marker in normalized:
        return normalized.split(marker, 1)[1].lstrip("/")
    return normalized.lstrip("./")

def load_verifications():
    if VERIFICATIONS_FILE.exists():
        try:
            with open(VERIFICATIONS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if not isinstance(data, dict):
                    return {}
                return {
                    normalize_saved_verification_key(key): value
                    for key, value in data.items()
                    if isinstance(value, dict)
                }
        except (OSError, json.JSONDecodeError):
            pass
    return {}


def save_verifications():
    write_json_atomic(VERIFICATIONS_FILE, manual_verifications, indent=2)

def verification_key(file_path: Path):
    """Use a stable key so decisions survive moving the portable folder."""
    return file_path.resolve().relative_to(DATA_DIR.resolve()).as_posix()

@lru_cache(maxsize=512)
def _content_sha256_cached(path: str, mtime_ns: int, size: int):
    del mtime_ns, size
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def evidence_identity(file_path: Path):
    file_stat = file_path.stat()
    return {
        "content_sha256": _content_sha256_cached(
            str(file_path.resolve()), file_stat.st_mtime_ns, file_stat.st_size
        ),
        "file_size": file_stat.st_size,
        "file_mtime_ns": file_stat.st_mtime_ns,
    }


def build_verification_record(file_path: Path, verdict: str, reviewer: str = "", reason: str = ""):
    return {
        "verdict": verdict,
        **evidence_identity(file_path),
        "reviewed_at": datetime.now(timezone.utc).isoformat(),
        "reviewer": reviewer.strip() or OPERATOR_ANONYMOUS,
        "reason": reason.strip(),
    }

def get_manual_verification(file_path: Path):
    key = verification_key(file_path)
    with verification_lock:
        stored = manual_verifications.get(key)
        value = dict(stored) if isinstance(stored, dict) else None
    if not value or not value.get("content_sha256"):
        # Legacy path-only decisions are retained on disk for audit/history but
        # cannot override current evidence until an operator reconfirms them.
        return None
    try:
        current_identity = evidence_identity(file_path)
    except OSError:
        return None
    if value.get("content_sha256") != current_identity["content_sha256"]:
        return None
    return value

def apply_manual_verification(file_path: Path, status: str, is_outdated: bool):
    verification = get_manual_verification(file_path)
    verdict = verification.get("verdict") if verification else None
    if verdict == "safe":
        return "Clean", False, verdict
    if verdict == "unsafe":
        return "Threats Found", False, verdict
    return status, is_outdated, None

