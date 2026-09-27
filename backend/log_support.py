"""Safe log-file access, PDF metadata, and checklist coverage helpers."""

from __future__ import annotations

import math
from pathlib import Path
import re

from fastapi import HTTPException

from checklist import SYSTEM_TREE
from ocr_analysis import validated_scan_datetime


DATA_DIR = Path(".")
ALLOWED_LOG_EXTENSIONS: set[str] = set()
MAX_SIGNATURE_THRESHOLD = 1_000_000.0
MAX_TEXT_FILE_BYTES = 10 * 1024 * 1024
MAX_SUMMARY_CHARS = 250_000


def configure_log_support(data_dir: Path, allowed_extensions: set[str]) -> None:
    global DATA_DIR, ALLOWED_LOG_EXTENSIONS
    DATA_DIR = data_dir
    ALLOWED_LOG_EXTENSIONS = allowed_extensions


def extract_pdf_systems(content: str, evidence_month: str = ""):
    """Extract consolidated report rows while rejecting impossible timestamps."""
    detected = {}
    date_pattern = r'\d{1,2}/\d{1,2}/\d{2,4}\s+\d{1,2}:\d{2}(?::\d{2})?\s+[AP]M'
    system_pattern = r'[A-Z0-9][A-Z0-9_-]{1,}(?:-[A-Z0-9_-]+)?'

    patterns = [
        # EPM ePO: 6/9/26 1:07:52 AM HOST01 4954.0 192.168.1.10
        re.compile(rf'({date_pattern})\s+({system_pattern})\s+([456789]\d{{3}}\.\d+)', re.IGNORECASE),
        # INFO ePO: 6/9/26 3:03:39 AM 4042.0 1 SITE-A-PD11
        re.compile(rf'({date_pattern})\s+([456789]\d{{3}}\.\d+)\s+(?:<\s*)?\d+(?:\.\d+)?\s+({system_pattern})', re.IGNORECASE),
    ]

    for line in content.splitlines():
        line = " ".join(line.split())
        if not line:
            continue

        for index, pattern in enumerate(patterns):
            match = pattern.search(line)
            if not match:
                continue

            if index == 0:
                last_scan, name, dat_version = match.groups()
            else:
                last_scan, dat_version, name = match.groups()

            if name.lower() in {"page", "total", "date", "system"}:
                continue

            validated_last_scan = validated_scan_datetime(last_scan, evidence_month)
            detected.setdefault(name, {
                "name": name,
                "dat_version": dat_version,
                "last_scan": validated_last_scan or "Unknown",
            })
            break

    return list(detected.values())

def normalize_count_key(value: str):
    return re.sub(r'[^a-z0-9]', '', value.lower())

def resolve_log_path(raw_path: str, allowed_extensions=None):
    """Resolve a UI path token while containing access inside ``DATA_DIR``."""
    if not raw_path or len(raw_path) > 4096 or "\x00" in raw_path:
        raise HTTPException(status_code=400, detail="Invalid log path.")
    try:
        requested = Path(raw_path).expanduser()
        # Absolute paths are accepted only for compatibility with older UI
        # builds; new responses expose relative tokens instead.
        file_path = requested.resolve() if requested.is_absolute() else (DATA_DIR / requested).resolve()
        file_path.relative_to(DATA_DIR.resolve())
    except (OSError, RuntimeError, ValueError):
        raise HTTPException(status_code=400, detail="Log path is outside the log directory.")

    if not file_path.is_file():
        raise HTTPException(status_code=404, detail="Log file was not found.")
    if file_path.name.startswith('.') or file_path.name.lower() == 'thumbs.db':
        raise HTTPException(status_code=400, detail="Unsupported log file.")

    extensions = allowed_extensions if allowed_extensions is not None else ALLOWED_LOG_EXTENSIONS
    if file_path.suffix.lower() not in extensions:
        raise HTTPException(status_code=400, detail="Unsupported log file type.")
    return file_path

def public_log_path(file_path: Path):
    """Return a non-sensitive, portable identifier for API responses."""
    return file_path.resolve().relative_to(DATA_DIR.resolve()).as_posix()

def enforce_file_size(file_path: Path, maximum: int, label: str):
    """Reject unexpectedly large evidence before a parser allocates memory."""
    try:
        size = file_path.stat().st_size
    except OSError as exc:
        raise ValueError(f"Unable to inspect {label} file.") from exc
    if size > maximum:
        raise ValueError(f"{label} exceeds the configured processing limit.")

def read_text_content(file_path: Path):
    enforce_file_size(file_path, MAX_TEXT_FILE_BYTES, "Text log")
    with open(file_path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()

def truncate_summary(content: str):
    if len(content) <= MAX_SUMMARY_CHARS:
        return content
    return content[:MAX_SUMMARY_CHARS] + "\n\n[Output truncated for safe display.]"

def validate_threshold_value(engine: str, value):
    if engine == "ocr_strictness":
        if value not in ["high", "medium", "low"]:
            raise HTTPException(status_code=400, detail="Invalid ocr_strictness threshold.")
        return value
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail=f"Invalid {engine} threshold.")
    if not math.isfinite(number):
        raise HTTPException(status_code=400, detail=f"Invalid {engine} threshold.")
    if engine == "zero_threat_confidence":
        if number < 0.00 or number > 0.99:
            raise HTTPException(
                status_code=400,
                detail="Zero-threat OCR confidence must be between 0.00 and 0.99.",
            )
        return number
    if number < 0 or number > MAX_SIGNATURE_THRESHOLD:
        raise HTTPException(
            status_code=400,
            detail=f"{engine} threshold must be between 0 and {int(MAX_SIGNATURE_THRESHOLD)}.",
        )
    return number

def add_coverage_count(coverage_counts, system: str, location: str, count: int = 1):
    coverage_counts.setdefault(system, {})
    coverage_counts[system][location] = coverage_counts[system].get(location, 0) + count

def extract_site_code(filename: str):
    match = re.match(r'\s*([A-Za-z]{3})\b', filename)
    return match.group(1).upper() if match else ""

def add_pdf_coverage(coverage_counts, unknown_coverage_systems, system_name: str, pdf_systems):
    if system_name == "EPM":
        # EPM report host identifiers cannot be reconciled to checklist
        # locations reliably. Preserve the report but label coverage unknown.
        unknown_coverage_systems.add("EPM")
        add_coverage_count(coverage_counts, "EPM", "Report", len(pdf_systems) or 1)
    elif system_name == "INFO":
        # INFO rows include stable site prefixes (for example SITE-A-PD11).
        # Count only parsed rows; a report with no rows has unknown coverage.
        if not pdf_systems:
            unknown_coverage_systems.add("INFO")
        for pdf_system in pdf_systems:
            location = pdf_system.get("name", "").split("-", 1)[0].upper()
            if location:
                add_coverage_count(coverage_counts, "INFO", location)


def add_file_coverage(coverage_counts, unknown_coverage_systems, log_entry, subsystem_name: str, pdf_systems):
    system_name = log_entry["system"]
    filename = log_entry["filename"]
    filename_lower = filename.lower()
    location = subsystem_name

    if system_name in {"EPM", "INFO"} and log_entry["type"] == "PDF":
        add_pdf_coverage(coverage_counts, unknown_coverage_systems, system_name, pdf_systems)
        return

    if system_name == "CCTV" and log_entry["type"] == "PDF":
        # A consolidated report proves that evidence exists, not that every
        # expected endpoint is represented.
        unknown_coverage_systems.add("CCTV")
        add_coverage_count(coverage_counts, "CCTV", "Report")
        return

    if system_name == "RADIO" and subsystem_name == "Site Radio":
        site_code = extract_site_code(Path(log_entry["path"]).name)
        if site_code:
            add_coverage_count(coverage_counts, "RADIO", site_code)
        add_coverage_count(coverage_counts, "RADIO", "Site")
        return

    if system_name == "RADIO" and subsystem_name == "Depot":
        add_coverage_count(coverage_counts, "RADIO", "Depot")
        if any(token in filename_lower for token in ["as1", "as2"]):
            add_coverage_count(coverage_counts, "RADIO", "Operations Center")
        elif any(token in filename_lower for token in ["crs", "gw", "nms"]):
            add_coverage_count(coverage_counts, "RADIO", "HQ East")
        return

    if system_name == "PBX" and subsystem_name == "Depot":
        add_coverage_count(coverage_counts, "PBX", "HQ East")
        add_coverage_count(coverage_counts, "PBX", "Ops Center")
        return

    if system_name == "AUDIO" and subsystem_name == "Depot":
        add_coverage_count(coverage_counts, "AUDIO", "HQ East")
        return

    if system_name == "NET" and subsystem_name == "Depot":
        if "03" in filename_lower:
            add_coverage_count(coverage_counts, "NET", "Data Center")
        else:
            add_coverage_count(coverage_counts, "NET", "HQ East")
        return

    if system_name == "VOICE":
        if subsystem_name == "Depot":
            if "server" in filename_lower:
                add_coverage_count(coverage_counts, "VOICE", "HQ East")
            else:
                add_coverage_count(coverage_counts, "VOICE", "Ops Center")
        elif subsystem_name != "Base System":
            add_coverage_count(coverage_counts, "VOICE", subsystem_name)
        else:
            add_coverage_count(coverage_counts, "VOICE", "Site U")
        return

    if system_name == "FAC" and subsystem_name in {"Base System", "Depot"}:
        if "hmi1" in filename_lower:
            location = "Office 1"
        elif "hmi2" in filename_lower:
            location = "Office 2"
        elif "hmi3" in filename_lower:
            location = "Ops Center(PFR)"
        else:
            location = "HQ East"

    elif system_name == "FW" and subsystem_name == "Depot":
        location = "Ops Center"

    elif system_name == "GW":
        if filename_lower.startswith("occ"):
            location = "Ops Center"
        elif filename_lower.startswith("site"):
            location = "Site B"

    elif system_name == "NVR" and subsystem_name == "Depot":
        location = "Ops Center"

    add_coverage_count(coverage_counts, system_name, location)

def build_system_tree_status(coverage_counts, unknown_coverage_systems, source_tree=None):
    """Return honest per-location reconciliation without inferred completeness."""
    system_tree = []
    for system_entry in (SYSTEM_TREE if source_tree is None else source_tree):
        system_name = system_entry["system"]
        locations = []
        for location in system_entry["locations"]:
            expected = int(location.get("expected", 0))
            raw_found = int(coverage_counts.get(system_name, {}).get(location["name"], 0))
            found = min(raw_found, expected)
            unresolved_count = max(expected - found, 0)
            if found >= expected:
                coverage_status = "present"
                missing = 0
            elif system_name in unknown_coverage_systems:
                coverage_status = "unknown"
                missing = 0
            elif found > 0:
                coverage_status = "partial"
                missing = unresolved_count
            else:
                coverage_status = "missing"
                missing = unresolved_count

            enriched = location.copy()
            enriched.update({
                "found": found,
                "missing": missing,
                "extra": max(raw_found - expected, 0),
                "coverage_status": coverage_status,
                "unresolved": coverage_status == "unknown",
                "unresolved_count": unresolved_count if coverage_status == "unknown" else 0,
            })
            locations.append(enriched)
        enriched_system = system_entry.copy()
        enriched_system["locations"] = locations
        system_tree.append(enriched_system)
    return system_tree
