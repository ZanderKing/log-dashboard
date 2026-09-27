"""Optional local Qwen vision fallback with conservative OCR reconciliation."""

from __future__ import annotations

import atexit
import base64
from datetime import datetime, timezone
import hashlib
from io import BytesIO
import json
import logging
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time
from typing import Callable, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from PIL import Image

from ocr_analysis import (
    THREAT_RESULT_POSITIVE,
    THREAT_RESULT_UNKNOWN,
    THREAT_RESULT_ZERO,
    find_date_in_text,
    signature_number,
    signature_threshold_for,
)
from storage import write_json_atomic


logger = logging.getLogger(__name__)
PROMPT_VERSION = "security-evidence-v1"
MODEL_FILENAME = "Qwen3VL-2B-Instruct-Q4_K_M.gguf"
MMPROJ_FILENAME = "mmproj-Qwen3VL-2B-Instruct-Q8_0.gguf"
MAX_AI_CACHE_ENTRIES = 2_000
MAX_RESPONSE_BYTES = 64 * 1024
MAX_ENCODED_IMAGE_BYTES = 20 * 1024 * 1024

EXTRACTION_PROMPT = """Read this antivirus scan screenshot. Extract only information explicitly visible.
Return exactly one JSON object with these keys:
{"dat_version": string|null, "dat_evidence": string|null,
 "scan_date": string|null, "scan_date_evidence": string|null,
 "threat_count": integer|null, "threat_evidence": string|null}
Rules:
- Do not infer a clean result from colours, icons, layout, or general appearance.
- threat_count must be null unless an explicit numeric value is visible beside a threat-count label.
- Never silently convert an unknown value into zero.
- Preserve the exact supporting line in each evidence field.
- Use null when a value or its supporting line is unreadable.
- Output JSON only; no Markdown or explanation."""

BASE_DIR = Path(".")
INSTALL_ROOT = Path(".")
AI_CACHE_FILE = Path("ai_cache.json")
current_ai_settings: dict[str, object] = {}
metric_recorder: Callable[[str], None] = lambda _name: None
ai_cache_lock = threading.Lock()
ai_cache_write_lock = threading.Lock()
ai_cache: dict[str, dict] = {}


def _configured_port() -> int:
    try:
        return min(65535, max(1024, int(os.getenv("SECURITY_CENTER_AI_PORT", "8091"))))
    except ValueError:
        return 8091


def _configured_path(name: str, default: Path) -> Path:
    value = os.getenv(name, "").strip()
    return Path(value).expanduser().resolve() if value else default.resolve()


class LocalVisionService:
    """Own one loopback-only llama.cpp process and serialize CPU inference."""

    def __init__(self) -> None:
        self.process: Optional[subprocess.Popen] = None
        self.process_lock = threading.Lock()
        self.inference_lock = threading.Lock()
        self.last_error = ""

    @property
    def port(self) -> int:
        return _configured_port()

    @property
    def endpoint(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def runtime_path(self) -> Path:
        executable = "llama-server.exe" if sys.platform == "win32" else "llama-server"
        return _configured_path(
            "SECURITY_CENTER_AI_RUNTIME",
            INSTALL_ROOT / "runtime" / "llama" / executable,
        )

    @property
    def model_path(self) -> Path:
        return _configured_path(
            "SECURITY_CENTER_AI_MODEL",
            INSTALL_ROOT / "models" / "qwen3-vl-2b" / MODEL_FILENAME,
        )

    @property
    def mmproj_path(self) -> Path:
        return _configured_path(
            "SECURITY_CENTER_AI_MMPROJ",
            INSTALL_ROOT / "models" / "qwen3-vl-2b" / MMPROJ_FILENAME,
        )

    def files_available(self) -> bool:
        return all(path.is_file() for path in (self.runtime_path, self.model_path, self.mmproj_path))

    def healthy(self, timeout: float = 0.75) -> bool:
        try:
            with urlopen(f"{self.endpoint}/health", timeout=timeout) as response:
                return 200 <= response.status < 300
        except (OSError, HTTPError, URLError):
            return False

    def status(self) -> dict[str, object]:
        running = bool(self.process and self.process.poll() is None)
        return {
            "available": self.files_available(),
            "running": running and self.healthy(),
            "mode": current_ai_settings.get("mode", "off"),
            "model": MODEL_FILENAME,
            "runtime_present": self.runtime_path.is_file(),
            "model_present": self.model_path.is_file(),
            "vision_projector_present": self.mmproj_path.is_file(),
            "last_error": self.last_error,
            "cache_entries": len(ai_cache),
        }

    def ensure_started(self) -> None:
        with self.process_lock:
            if self.healthy():
                # Verify mmproj actually loaded by checking the server metadata.
                # A stale server started without --mmproj will pass /health but
                # reject image requests. Force a restart if multimodal is absent.
                try:
                    with urlopen(f"{self.endpoint}/slots", timeout=0.5) as resp:
                        slots = json.loads(resp.read())
                        if slots and isinstance(slots, list) and len(slots) > 0:
                            slot = slots[0]
                            has_mmproj = (
                                isinstance(slot, dict)
                                and slot.get("has_vision_encoder") is True
                            )
                            if not has_mmproj:
                                logger.info("Server running without mmproj; restarting.")
                                self._stop_locked()
                                self.last_error = ""
                            else:
                                return
                except (OSError, json.JSONDecodeError, HTTPError, URLError):
                    self._stop_locked()
                    self.last_error = ""
            if self.process and self.process.poll() is None:
                self._stop_locked()
            missing = [
                path.name
                for path in (self.runtime_path, self.model_path, self.mmproj_path)
                if not path.is_file()
            ]
            if missing:
                self.last_error = "Missing local AI files: " + ", ".join(missing)
                raise RuntimeError(self.last_error)

            threads = os.getenv("SECURITY_CENTER_AI_THREADS", "").strip()
            if not threads:
                threads = str(min(8, max(1, (os.cpu_count() or 2) - 1)))
            command = [
                str(self.runtime_path),
                "--model", str(self.model_path),
                "--mmproj", str(self.mmproj_path),
                "--host", "127.0.0.1",
                "--port", str(self.port),
                "--ctx-size", "4096",
                "--threads", threads,
                "--parallel", "1",
                "--no-mmproj-offload",
            ]
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
            self.process = subprocess.Popen(
                command,
                cwd=str(self.runtime_path.parent),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creationflags,
            )
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    self.last_error = "The local AI process exited during startup."
                    raise RuntimeError(self.last_error)
                if self.healthy():
                    self.last_error = ""
                    return
                time.sleep(0.25)
            self._stop_locked()
            self.last_error = "The local AI process did not become ready within 60 seconds."
            raise RuntimeError(self.last_error)

    def _stop_locked(self) -> None:
        process = self.process
        self.process = None
        if not process or process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    def stop(self) -> None:
        with self.process_lock:
            self._stop_locked()

    def infer(self, image_data_url: str, timeout_seconds: int) -> dict:
        with self.inference_lock:
            self.ensure_started()
            payload = {
                "model": "qwen3-vl-2b",
                "temperature": 0,
                "max_tokens": 220,
                "messages": [{
                    "role": "user",
                    "content": [
                        {"type": "text", "text": EXTRACTION_PROMPT},
                        {"type": "image_url", "image_url": {"url": image_data_url}},
                    ],
                }],
            }
            request = Request(
                f"{self.endpoint}/v1/chat/completions",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(request, timeout=timeout_seconds) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise ValueError("Local AI response exceeded the safe size limit.")
            body = json.loads(raw.decode("utf-8"))
            return _parse_json_object(body["choices"][0]["message"]["content"])


local_vision_service = LocalVisionService()
atexit.register(local_vision_service.stop)


def configure_ai_vision(
    base_dir: Path,
    install_root: Path,
    settings: dict[str, object],
    record_metric: Callable[[str], None],
) -> None:
    global BASE_DIR, INSTALL_ROOT, AI_CACHE_FILE, current_ai_settings, metric_recorder
    BASE_DIR = base_dir.resolve()
    INSTALL_ROOT = install_root.resolve()
    AI_CACHE_FILE = BASE_DIR / "ai_cache.json"
    current_ai_settings = settings
    metric_recorder = record_metric
    with ai_cache_lock:
        ai_cache.clear()
        try:
            if AI_CACHE_FILE.is_file():
                loaded = json.loads(AI_CACHE_FILE.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    ai_cache.update({k: v for k, v in loaded.items() if isinstance(v, dict)})
        except (OSError, json.JSONDecodeError):
            pass


def _save_ai_cache() -> None:
    with ai_cache_lock:
        snapshot = dict(ai_cache)
    with ai_cache_write_lock:
        write_json_atomic(AI_CACHE_FILE, snapshot)


def clear_ai_cache() -> None:
    with ai_cache_lock:
        ai_cache.clear()
    _save_ai_cache()


def _content_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _model_identity() -> str:
    parts = []
    for path in (local_vision_service.model_path, local_vision_service.mmproj_path):
        stat = path.stat()
        parts.append(f"{path.name}:{stat.st_size}:{stat.st_mtime_ns}")
    return "|".join(parts)


def _cache_key(path: Path, max_dimension: int) -> str:
    identity = f"{_content_sha256(path)}|{_model_identity()}|{PROMPT_VERSION}|{max_dimension}"
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _image_data_url(path: Path, max_dimension: int) -> str:
    with Image.open(path) as source:
        source.seek(0)
        image = source.convert("RGB")
        image.thumbnail((max_dimension, max_dimension), Image.Resampling.LANCZOS)
        output = BytesIO()
        image.save(output, format="PNG", optimize=False)
    encoded = output.getvalue()
    if len(encoded) > MAX_ENCODED_IMAGE_BYTES:
        raise ValueError("Prepared image exceeds the local AI size limit.")
    return "data:image/png;base64," + base64.b64encode(encoded).decode("ascii")


def _parse_json_object(content) -> dict:
    if not isinstance(content, str):
        raise ValueError("Local AI returned a non-text response.")
    value = content.strip()
    if value.startswith("```"):
        value = re.sub(r"^```(?:json)?\s*|\s*```$", "", value, flags=re.IGNORECASE)
    start = value.find("{")
    if start < 0:
        raise ValueError("Local AI response did not contain JSON.")
    parsed, _end = json.JSONDecoder().raw_decode(value[start:])
    if not isinstance(parsed, dict):
        raise ValueError("Local AI response was not a JSON object.")
    return parsed


def _limited_text(value, maximum: int = 500) -> str:
    return " ".join(str(value or "").split())[:maximum]


def _version_key(value: str) -> str:
    return re.sub(r"[^0-9]", "", value)


def validate_model_result(raw: dict, evidence_month: str) -> dict:
    """Accept a field only when its value also appears in a labelled evidence line."""
    result = {
        "dat_version": "",
        "dat_evidence": _limited_text(raw.get("dat_evidence")),
        "scan_date": "",
        "scan_date_evidence": _limited_text(raw.get("scan_date_evidence")),
        "threat_count": None,
        "threat_evidence": _limited_text(raw.get("threat_evidence")),
    }

    dat_value = _limited_text(raw.get("dat_version"), 80)
    dat_evidence = result["dat_evidence"]
    if (
        dat_value
        and signature_number(dat_value) is not None
        and re.search(r"\b(?:amcore|dat|signature|virus\s+db|definitions?)\b", dat_evidence, re.IGNORECASE)
        and _version_key(dat_value) in _version_key(dat_evidence)
    ):
        result["dat_version"] = dat_value

    date_value = _limited_text(raw.get("scan_date"), 100)
    date_from_value = find_date_in_text(date_value, evidence_month) if date_value else ""
    date_from_evidence = find_date_in_text(result["scan_date_evidence"], evidence_month)
    if date_from_value and date_from_value == date_from_evidence:
        result["scan_date"] = date_from_value

    count = raw.get("threat_count")
    if isinstance(count, str) and re.fullmatch(r"\d{1,7}", count.strip()):
        count = int(count)
    threat_evidence = result["threat_evidence"]
    label = re.search(
        r"\b(?:infected\s+files?|detections?|threats?|files?\s+with\s+detections?)\b",
        threat_evidence,
        re.IGNORECASE,
    )
    if isinstance(count, int) and not isinstance(count, bool) and 0 <= count <= 1_000_000 and label:
        tail = threat_evidence[label.end():]
        visible_count = re.search(r"(?<!\d)(\d{1,7})(?!\d)", tail)
        if visible_count and int(visible_count.group(1)) == count:
            result["threat_count"] = count
    return result


def analyze_with_qwen(path: Path, evidence_month: str, *, allow_inference: bool) -> Optional[dict]:
    if current_ai_settings.get("mode", "off") != "review_only":
        return None
    if not local_vision_service.files_available():
        local_vision_service.last_error = "Local AI is enabled but its runtime or model files are missing."
        metric_recorder("ai_failures")
        return None
    max_dimension = int(current_ai_settings.get("max_image_dimension", 1600))
    try:
        key = _cache_key(path, max_dimension)
        with ai_cache_lock:
            cached = ai_cache.get(key)
        if isinstance(cached, dict) and isinstance(cached.get("result"), dict):
            metric_recorder("ai_cache_hits")
            return dict(cached["result"])
        if not allow_inference:
            return None
        started = time.perf_counter()
        raw = local_vision_service.infer(
            _image_data_url(path, max_dimension),
            int(current_ai_settings.get("timeout_seconds", 120)),
        )
        result = validate_model_result(raw, evidence_month)
        result.update({
            "model": "Qwen3-VL-2B-Instruct-Q4_K_M",
            "prompt_version": PROMPT_VERSION,
            "elapsed_ms": round((time.perf_counter() - started) * 1000),
        })
        with ai_cache_lock:
            ai_cache[key] = {
                "result": result,
                "cached_at": datetime.now(timezone.utc).isoformat(),
            }
            while len(ai_cache) > MAX_AI_CACHE_ENTRIES:
                ai_cache.pop(next(iter(ai_cache)))
        _save_ai_cache()
        metric_recorder("ai_fallbacks")
        return result
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, json.JSONDecodeError, HTTPError, URLError) as exc:
        local_vision_service.last_error = str(exc)[:500]
        metric_recorder("ai_failures")
        logger.warning("Local AI fallback failed for %s: %s", path.name, exc)
        return None


def _versions_equal(left: str, right: str) -> bool:
    left_number = signature_number(left)
    right_number = signature_number(right)
    return left_number is not None and right_number is not None and abs(left_number - right_number) < 0.0001


def _without_reasons(reasons: list[str], fragments: tuple[str, ...]) -> list[str]:
    return [reason for reason in reasons if not any(fragment in reason.lower() for fragment in fragments)]


def reconcile_ocr_and_ai(
    status: str,
    dat_version: str,
    last_scan: str,
    is_outdated: bool,
    review_details: dict,
    ai_result: dict,
    system_name: str,
) -> tuple[str, str, str, bool, dict]:
    """Use agreement to resolve OCR candidates; never accept an AI-only zero."""
    details = dict(review_details)
    reasons = list(details.get("verification_reasons", []))
    agreements: list[str] = []
    conflicts: list[str] = []
    trusted_threat = details.get("threat_result", THREAT_RESULT_UNKNOWN)
    candidate_threat = details.get("threat_result_candidate", THREAT_RESULT_UNKNOWN)
    threat_zero_resolved = trusted_threat == THREAT_RESULT_ZERO
    threat_positive = trusted_threat == THREAT_RESULT_POSITIVE or status == "Threats Found"

    ai_count = ai_result.get("threat_count")
    if isinstance(ai_count, int) and ai_count > 0:
        threat_positive = True
        status = "Threats Found"
        reasons.append(f"Local AI read an explicit positive threat count ({ai_count}); verify the highlighted evidence.")
    elif ai_count == 0:
        if trusted_threat == THREAT_RESULT_ZERO or candidate_threat == THREAT_RESULT_ZERO:
            threat_zero_resolved = True
            agreements.append("threat_count")
            reasons = _without_reasons(reasons, ("zero-threat", "threat-count label", "threat-count value"))
        else:
            reasons.append("Local AI read zero, but OCR did not independently corroborate that value.")

    ai_dat = str(ai_result.get("dat_version") or "")
    dat_candidate = str(details.get("dat_version_candidate") or "")
    if ai_dat:
        if dat_version != "Unknown" and not _versions_equal(dat_version, ai_dat):
            conflicts.append("dat_version")
            reasons.append("Local AI and OCR disagree on the DAT/signature version.")
        elif dat_version == "Unknown" and dat_candidate and _versions_equal(dat_candidate, ai_dat):
            dat_version = dat_candidate
            agreements.append("dat_version")
            reasons = _without_reasons(reasons, ("dat version", "signature version"))
        elif dat_version == "Unknown" and not dat_candidate:
            details["dat_version_candidate"] = ai_dat

    ai_date = str(ai_result.get("scan_date") or "")
    date_candidate = str(details.get("last_scan_candidate") or "")
    if ai_date:
        if last_scan != "Unknown" and last_scan != ai_date:
            conflicts.append("scan_date")
            reasons.append("Local AI and OCR disagree on the completed-scan timestamp.")
        elif last_scan == "Unknown" and date_candidate == ai_date:
            last_scan = date_candidate
            agreements.append("scan_date")
            reasons = _without_reasons(reasons, ("valid date", "completed scan time", "completed-scan timestamp", "calendar-valid"))
        elif last_scan == "Unknown" and not date_candidate:
            details["last_scan_candidate"] = ai_date

    if dat_version != "Unknown" and "dat_version" in agreements:
        engine = str(details.get("av_engine") or ("clamwin" if system_name == "RADIO" else "mcafee"))
        version_number = signature_number(dat_version)
        is_outdated = bool(version_number is not None and version_number < signature_threshold_for(engine))

    reasons = list(dict.fromkeys(reasons))
    if not threat_positive:
        if conflicts:
            status = "Manual Verification Needed"
        elif threat_zero_resolved and dat_version != "Unknown" and last_scan != "Unknown" and not reasons:
            status = "Clean"
        else:
            status = "Manual Verification Needed"
        if is_outdated and status == "Clean":
            status = "Manual Verification Needed"

    details["verification_reasons"] = reasons
    details["ai_fallback"] = {
        "used": True,
        "model": ai_result.get("model", "Qwen3-VL-2B-Instruct-Q4_K_M"),
        "prompt_version": ai_result.get("prompt_version", PROMPT_VERSION),
        "elapsed_ms": ai_result.get("elapsed_ms", 0),
        "agreements": agreements,
        "conflicts": conflicts,
        "threat_count": ai_count,
        "threat_evidence": ai_result.get("threat_evidence", ""),
    }
    return status, dat_version, last_scan, is_outdated, details