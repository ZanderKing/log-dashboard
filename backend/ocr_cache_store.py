"""Content-addressed OCR result cache with duplicate-inference suppression."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import threading

from storage import write_json_atomic


OCR_CACHE_FILE = Path("ocr_cache.json")
OCR_FAST_MAG_RATIO = 1.0
MAX_OCR_CACHE_ENTRIES = 2_000
ocr_cache_lock = threading.Lock()
ocr_cache_write_lock = threading.Lock()
ocr_content_inflight_lock = threading.Lock()
ocr_content_inflight: dict[str, threading.Event] = {}
ocr_cache: dict = {}


def configure_ocr_cache(cache_file: Path) -> None:
    """Bind the portable cache path and load it into the shared dictionary."""
    global OCR_CACHE_FILE
    OCR_CACHE_FILE = cache_file
    ocr_cache.clear()
    ocr_cache.update(load_ocr_cache())


# --- OCR CACHING LOGIC ---
def load_ocr_cache():
    if OCR_CACHE_FILE.exists():
        try:
            with open(OCR_CACHE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            pass
    return {}


def save_ocr_cache():
    """Write a consistent cache snapshot; callers need not hold its lock."""
    with ocr_cache_lock:
        snapshot = dict(ocr_cache)
    with ocr_cache_write_lock:
        write_json_atomic(OCR_CACHE_FILE, snapshot)


def clear_ocr_cache():
    """Reset the OCR cache in-memory and on disk."""
    with ocr_cache_lock:
        ocr_cache.clear()
    save_ocr_cache()

def get_file_hash(file_path: Path):
    stats = file_path.stat()
    unique_string = f"{file_path.resolve()}:{stats.st_mtime_ns}:{stats.st_size}"
    # SHA-256 also avoids security scanners mistaking this cache identity for an
    # unsafe MD5 integrity check. Evidence content itself is never modified.
    return hashlib.sha256(unique_string.encode("utf-8")).hexdigest()

def get_content_cache_key(file_path: Path):
    """Hash image bytes so exact copies share one OCR inference."""
    digest = hashlib.sha256()
    with open(file_path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"content:{digest.hexdigest()}"

def unwrap_cached_ocr_results(entry):
    if isinstance(entry, list):
        return entry
    if isinstance(entry, dict) and isinstance(entry.get("results"), list):
        return entry["results"]
    return None

def resolve_cached_ocr_results_locked(file_id: str, legacy_id: str = ""):
    entry = ocr_cache.get(file_id)
    if entry is None and legacy_id and legacy_id in ocr_cache:
        entry = ocr_cache.pop(legacy_id)
        ocr_cache[file_id] = entry
    if isinstance(entry, dict) and isinstance(entry.get("content_key"), str):
        entry = ocr_cache.get(entry["content_key"])
    return unwrap_cached_ocr_results(entry)


def get_legacy_file_hash(file_path: Path):
    """Read pre-1.1 cache entries without forcing every image to be rescanned."""
    stats = file_path.stat()
    unique_string = f"{file_path.resolve()}:{stats.st_mtime_ns}:{stats.st_size}"
    return hashlib.md5(unique_string.encode("utf-8"), usedforsecurity=False).hexdigest()

def normalize_ocr_results(ocr_results):
    normalized = []
    for bbox, text, confidence in ocr_results:
        normalized_bbox = None
        if bbox is not None:
            try:
                points = [[float(point[0]), float(point[1])] for point in bbox]
                if len(points) >= 2:
                    normalized_bbox = points
            except (TypeError, ValueError, IndexError):
                normalized_bbox = None
        normalized.append({
            "bbox": normalized_bbox,
            "text": str(text),
            "confidence": float(confidence),
        })
    return normalized

def cached_results_have_spatial_data(cached_results):
    """Return whether cached OCR can safely associate table labels and values."""
    if not isinstance(cached_results, list):
        return False
    # An empty OCR result is a valid cached result. Non-empty legacy cache rows
    # omitted bounding boxes and must be refreshed once so adjacent table rows
    # cannot be combined into incorrect DAT/date/threat metadata.
    return not cached_results or all(
        isinstance(item, dict) and item.get("bbox") is not None
        for item in cached_results
    )

def denormalize_ocr_results(cached_results):
    return [
        (item.get("bbox"), item.get("text", ""), float(item.get("confidence", 0)))
        for item in cached_results
        if isinstance(item, dict)
    ]

def has_cached_ocr_results(file_path: Path):
    file_id = get_file_hash(file_path)
    legacy_id = get_legacy_file_hash(file_path)
    with ocr_cache_lock:
        cached_results = resolve_cached_ocr_results_locked(file_id, legacy_id)
        return cached_results_have_spatial_data(cached_results)

def run_cached_ocr(
    file_path: Path,
    *,
    reader_factory,
    magnification_plan_factory,
    extractor,
    completeness_checker,
    metric_recorder,
    persist: bool = True,
    system_name: str = "",
    evidence_month: str = "",
):
    """Return cached OCR or run a guarded native-resolution scan once."""
    file_id = get_file_hash(file_path)
    legacy_id = get_legacy_file_hash(file_path)
    with ocr_cache_lock:
        cached_results = resolve_cached_ocr_results_locked(file_id, legacy_id)
    if cached_results_have_spatial_data(cached_results):
        metric_recorder("cache_hits")
        return denormalize_ocr_results(cached_results)

    content_key = get_content_cache_key(file_path)
    owns_inference = False
    while not owns_inference:
        content_results = None
        with ocr_content_inflight_lock:
            with ocr_cache_lock:
                content_results = unwrap_cached_ocr_results(ocr_cache.get(content_key))
                if cached_results_have_spatial_data(content_results):
                    ocr_cache[file_id] = {"content_key": content_key}

            if not cached_results_have_spatial_data(content_results):
                pending = ocr_content_inflight.get(content_key)
                if pending is None:
                    pending = threading.Event()
                    ocr_content_inflight[content_key] = pending
                    owns_inference = True

        if cached_results_have_spatial_data(content_results):
            metric_recorder("cache_hits")
            metric_recorder("content_cache_hits")
            if persist:
                save_ocr_cache()
            return denormalize_ocr_results(content_results)
        if not owns_inference:
            pending.wait()

    try:
        local_reader = reader_factory()
        magnification_plan = magnification_plan_factory(file_path)
        primary_ratio = magnification_plan[0]
        primary_results = extractor(
            local_reader,
            str(file_path),
            mag_ratio=primary_ratio,
        )
        if primary_ratio == OCR_FAST_MAG_RATIO:
            metric_recorder("fast_passes")
        else:
            metric_recorder("full_quality_passes")

        if (
            len(magnification_plan) == 1
            or completeness_checker(
                primary_results,
                system_name,
                evidence_month,
            )
        ):
            ocr_results = primary_results
            applied_mag_ratio = primary_ratio
        else:
            ocr_results = extractor(
                local_reader,
                str(file_path),
                mag_ratio=magnification_plan[1],
            )
            applied_mag_ratio = magnification_plan[1]
            metric_recorder("full_quality_passes")
            metric_recorder("full_quality_fallbacks")

        normalized_results = normalize_ocr_results(ocr_results)
        with ocr_cache_lock:
            ocr_cache[content_key] = {
                "results": normalized_results,
                "mag_ratio": applied_mag_ratio,
            }
            ocr_cache[file_id] = {"content_key": content_key}
            while len(ocr_cache) > MAX_OCR_CACHE_ENTRIES:
                ocr_cache.pop(next(iter(ocr_cache)))
    finally:
        with ocr_content_inflight_lock:
            pending = ocr_content_inflight.pop(content_key, None)
            if pending is not None:
                pending.set()

    if persist:
        save_ocr_cache()
    return denormalize_ocr_results(normalized_results)



