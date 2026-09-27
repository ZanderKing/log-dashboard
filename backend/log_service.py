"""Month discovery, bounded file analysis, and honest evidence reconciliation."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
import logging
from pathlib import Path
import re
from typing import Callable, Optional

from fastapi import HTTPException
import pypdf

from checklist import (
    SYSTEM_TREE,
    build_checklist_validation,
    get_month_checklist,
    match_checklist_rows,
)
from log_support import (
    add_file_coverage,
    build_system_tree_status,
    enforce_file_size,
    extract_pdf_systems,
    public_log_path,
    read_text_content,
)
from ocr_analysis import analyze_and_audit, analyze_text_content
from ocr_cache_store import has_cached_ocr_results, save_ocr_cache
from scan_state import (
    finish_scan_progress,
    is_scan_cancel_requested,
    reset_scan_progress,
    update_scan_progress,
)
from settings_store import apply_manual_verification
from vendor_ingestion import SUPPORTED_UPLOAD_EXTENSIONS, analyze_structured_file, legacy_result


# All config is injected at startup via configure_log_service(). Module-level
# globals keep the API simple so analyze_file() and collect_logs() don't need
# to thread configuration objects through every call.
logger = logging.getLogger(__name__)
DATA_DIR = Path(".")
ALLOWED_LOG_EXTENSIONS: set[str] = set()
TEXT_EXTENSIONS: set[str] = set()
PDF_EXTENSIONS: set[str] = set()
IMAGE_EXTENSIONS: set[str] = set()
MAX_TEXT_FILE_BYTES = 10 * 1024 * 1024
MAX_PDF_FILE_BYTES = 100 * 1024 * 1024
MAX_IMAGE_FILE_BYTES = 50 * 1024 * 1024
MAX_PDF_PAGES = 500
OCR_MAX_WORKERS = 1
month_sort_key: Callable[[str], tuple[int, int]]
get_cached_ocr_results: Callable
get_ai_result: Callable = lambda _path, _month, allow_inference=False: None
reconcile_ai_result: Callable

# Canonical system name lookup — everything goes through these abbreviations.
# classify_evidence_path() uses them to normalize folder names to system keys.
CANONICAL_SYSTEMS = {
    "radio": "RADIO",
    "cctv": "CCTV",
    "epm": "EPM",
    "info": "INFO",
    "net": "NET",
    "pbx": "PBX",
    "audio": "AUDIO",
    "voice": "VOICE",
    "fac": "FAC",
    "nvr": "NVR",
    "fw": "FW",
    "gw": "GW",
}


def configure_log_service(
    *,
    data_dir: Path,
    allowed_extensions: set[str],
    text_extensions: set[str],
    pdf_extensions: set[str],
    image_extensions: set[str],
    max_text_bytes: int,
    max_pdf_bytes: int,
    max_image_bytes: int,
    max_pdf_pages: int,
    ocr_workers: int,
    month_key: Callable[[str], tuple[int, int]],
    ocr_provider: Callable,
    ai_provider: Callable = lambda _path, _month, allow_inference=False: None,
    ai_reconciler: Callable = lambda *args, **kwargs: (args[0], args[1], args[2], args[3], args[4]),
) -> None:
    global DATA_DIR, ALLOWED_LOG_EXTENSIONS, TEXT_EXTENSIONS, PDF_EXTENSIONS
    global IMAGE_EXTENSIONS, MAX_TEXT_FILE_BYTES, MAX_PDF_FILE_BYTES
    global MAX_IMAGE_FILE_BYTES, MAX_PDF_PAGES, OCR_MAX_WORKERS
    global month_sort_key, get_cached_ocr_results, get_ai_result, reconcile_ai_result
    DATA_DIR = data_dir
    ALLOWED_LOG_EXTENSIONS = allowed_extensions
    TEXT_EXTENSIONS = text_extensions
    PDF_EXTENSIONS = pdf_extensions
    IMAGE_EXTENSIONS = image_extensions
    MAX_TEXT_FILE_BYTES = max_text_bytes
    MAX_PDF_FILE_BYTES = max_pdf_bytes
    MAX_IMAGE_FILE_BYTES = max_image_bytes
    MAX_PDF_PAGES = max_pdf_pages
    OCR_MAX_WORKERS = ocr_workers
    month_sort_key = month_key
    get_cached_ocr_results = ocr_provider
    get_ai_result = ai_provider
    reconcile_ai_result = ai_reconciler
    clear_document_cache()


def public_checklist_source(value: str):
    """Describe the checklist without exposing an absolute workstation path."""
    if not value:
        return ""
    try:
        return Path(value).resolve().relative_to(DATA_DIR.resolve()).as_posix()
    except (OSError, ValueError):
        return Path(value).name


def list_months():
    """Immediate sub-folders of DATA_DIR (the months), newest first."""
    if not DATA_DIR.exists():
        return []
    months = [d.name for d in DATA_DIR.iterdir() if d.is_dir() and not d.name.startswith(".")]
    months.sort(key=month_sort_key, reverse=True)
    return months


def validate_month(month: Optional[str], *, allow_empty: bool = True):
    """Return a known month name and reject traversal or stale UI values."""
    if not month:
        if allow_empty:
            return None
        raise HTTPException(status_code=400, detail="A month must be selected.")
    if month not in list_months():
        raise HTTPException(status_code=400, detail="Unknown month selection.")
    return month


def _compact_path_part(value: str):
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _canonical_system(value: str):
    return CANONICAL_SYSTEMS.get(_compact_path_part(value), "")


def classify_evidence_path(file_path: Path, month_dir: Optional[Path] = None):
    """Resolve current and legacy folder layouts to one canonical system.

    The evidence folder structure isn't perfectly uniform — historical data
    uses wrapper directories like DepotScreenshot, HQScreenshot, and
    ePOReportCombined. This function handles them all and returns a tuple of
    (system_name, subsystem, display_filename).
    """
    try:
        if month_dir is None:
            relative = file_path.resolve().relative_to(DATA_DIR.resolve())
            parts = relative.parts[1:]
        else:
            parts = file_path.resolve().relative_to(month_dir.resolve()).parts
    except (OSError, ValueError):
        parts = (file_path.name,)

    if not parts:
        return "Uncategorized", "Base System", file_path.name

    display_filename = (
        parts[-1]
        if len(parts) == 1
        else f"[{'/'.join(parts[:-1])}] {parts[-1]}"
    )
    first = _compact_path_part(parts[0])
    filename_key = _compact_path_part(parts[-1])
    direct_system = _canonical_system(parts[0])
    if direct_system:
        subsystem = parts[1] if len(parts) > 2 else "Base System"
        if direct_system == "RADIO" and _compact_path_part(subsystem) == "site":
            subsystem = "Site Radio"
        return direct_system, subsystem, display_filename

    if first == "eporeportcombined":
        scope = _compact_path_part(" ".join(parts[1:]))
        if "info" in scope:
            return "INFO", "Report", display_filename
        if "epm" in scope:
            return "EPM", "Report", display_filename
        return "Uncategorized", "Report", display_filename

    if first == "voicereport":
        return "VOICE", "Site U", display_filename
    if first.startswith("siteradio"):
        return "RADIO", "Site Radio", display_filename
    if first.startswith("depotradio") or first == "febscreenshot":
        return "RADIO", "Legacy mixed radio", display_filename

    wrapper_is_depot = first in {"depotscreenshot", "depothqscreenshot"}
    wrapper_is_iocc = first == "hqscreenshot"
    if wrapper_is_depot or wrapper_is_iocc:
        cursor = 1
        subsystem = "Depot" if wrapper_is_depot else "HQ"
        if cursor < len(parts) - 1 and _compact_path_part(parts[cursor]) == "hqscreenshot":
            subsystem = "HQ"
            cursor += 1
        if cursor < len(parts) - 1:
            child = _compact_path_part(parts[cursor])
            child_system = _canonical_system(parts[cursor])
            if child == "radio":
                return "RADIO", subsystem, display_filename
            if child == "hqcctv":
                return "CCTV", "HQ", display_filename
            if child_system:
                return child_system, subsystem, display_filename

    # A small number of historical reports were left in the month root. Use
    # only explicit system tokens; otherwise preserve them as Uncategorized.
    if "radio" in filename_key:
        return "RADIO", "Unspecified", display_filename
    for token, system_name in CANONICAL_SYSTEMS.items():
        if token in filename_key:
            return system_name, "Unspecified", display_filename
    return "Uncategorized", "Base System", display_filename


def infer_system_name(file_path: Path):
    return classify_evidence_path(file_path)[0]


def infer_evidence_month(file_path: Path):
    """Return the immediate month folder containing a validated evidence file."""
    try:
        relative_parts = file_path.resolve().relative_to(DATA_DIR.resolve()).parts
        if relative_parts:
            return relative_parts[0]
    except ValueError:
        pass
    return ""


@lru_cache(maxsize=64)
def _read_pdf_text_cached(path: str, mtime_ns: int, size: int, page_limit: int):
    """Cache extracted text by immutable file identity, never by path alone."""
    del mtime_ns, size
    pdf = pypdf.PdfReader(path)
    if len(pdf.pages) > page_limit:
        raise ValueError("PDF exceeds the configured page limit.")
    return "\n".join((page.extract_text() or "") for page in pdf.pages)


def clear_document_cache():
    _read_pdf_text_cached.cache_clear()


def read_pdf_text(file_path: Path):
    """Extract bounded PDF text and reuse it until path metadata changes."""
    enforce_file_size(file_path, MAX_PDF_FILE_BYTES, "PDF")
    file_stat = file_path.stat()
    return _read_pdf_text_cached(
        str(file_path.resolve()),
        file_stat.st_mtime_ns,
        file_stat.st_size,
        MAX_PDF_PAGES,
    )


def analyze_file(
    file_path: Path,
    scan_images: bool,
    system_name: str = "",
    evidence_month: str = "",
    *,
    persist_ocr: bool = True,
):
    """Analyze one supported evidence file and degrade safely on parser errors.

    The dispatch chain works like this:
      1. Images without cached OCR → "Not Scanned" (unless scan_images=True)
      2. Structured files (ePO, ClamWin, Symantec, etc.) → vendor_ingestion
      3. Plain text → analyze_text_content (regex-based threat extraction)
      4. PDF → pypdf extraction + analyze_text_content
      5. Images with OCR → spatial OCR analysis + optional AI fallback

    Any unhandled failure returns "Manual Verification Needed" — the dashboard
    will prompt the operator to look at the file manually.
    """
    ext = file_path.suffix.lower()
    evidence_month = evidence_month or infer_evidence_month(file_path)
    try:
        if ext in IMAGE_EXTENSIONS and not scan_images and not has_cached_ocr_results(file_path):
            return "Not Scanned", "Unknown", "Unknown", False, {}

        if ext in (SUPPORTED_UPLOAD_EXTENSIONS - IMAGE_EXTENSIONS):
            if ext in TEXT_EXTENSIONS:
                enforce_file_size(file_path, MAX_TEXT_FILE_BYTES, "Text")
            elif ext in PDF_EXTENSIONS:
                enforce_file_size(file_path, MAX_PDF_FILE_BYTES, "PDF")
            else:
                enforce_file_size(file_path, MAX_IMAGE_FILE_BYTES, "Image")

            structured = analyze_structured_file(
                file_path,
                evidence_month,
                ocr_provider=None,
            )
            mapped = legacy_result(structured)
            if mapped:
                status, dat_version, last_scan, review_details = mapped
                review_details.update({
                    "scan_runs": structured.get("scan_runs", []),
                    "vendor": structured.get("classification", {}).get("vendor", "unknown"),
                    "vendor_confidence": structured.get("classification", {}).get("confidence", 0),
                    "extraction_method": structured.get("extraction_method", "unknown"),
                    "source_file_id": structured.get("source_file_id", ""),
                    "document_role": structured.get("document_role", "unknown"),
                })
                return status, dat_version, last_scan, False, review_details

        if ext in TEXT_EXTENSIONS:
            result = analyze_text_content(read_text_content(file_path), system_name, evidence_month)
            return (*result, {})
        if ext in PDF_EXTENSIONS:
            result = analyze_text_content(read_pdf_text(file_path), system_name, evidence_month)
            return (*result, {})
        if ext in IMAGE_EXTENSIONS:
            enforce_file_size(file_path, MAX_IMAGE_FILE_BYTES, "Image")
            ocr_results = get_cached_ocr_results(
                file_path,
                persist=persist_ocr,
                system_name=system_name,
                evidence_month=evidence_month,
            )
            status, _summary, dat_version, last_scan, is_outdated, review_details = analyze_and_audit(
                ocr_results,
                system_name,
                evidence_month,
                image_path=str(file_path),
            )
            if status == "Manual Verification Needed":
                ai_result = get_ai_result(
                    file_path,
                    evidence_month,
                    allow_inference=scan_images,
                )
                if ai_result:
                    status, dat_version, last_scan, is_outdated, review_details = reconcile_ai_result(
                        status,
                        dat_version,
                        last_scan,
                        is_outdated,
                        review_details,
                        ai_result,
                        system_name,
                    )
            return status, dat_version, last_scan, is_outdated, review_details
    except Exception as exc:
        logger.warning("Unable to analyze %s: %s", public_log_path(file_path), exc)
        return (
            "Manual Verification Needed",
            "Unknown",
            "Unknown",
            False,
            {"verification_reasons": ["The file could not be parsed safely."], "parse_failed": True},
        )
    return "Manual Verification Needed", "Unknown", "Unknown", False, {
        "verification_reasons": ["The file type has no supported security parser."],
        "parse_failed": True,
    }


def _scan_status(status: str, is_outdated: bool, review_details: dict, verification=None):
    if review_details.get("parse_failed"):
        return "scan_failed"
    if status == "Not Scanned":
        return "not_scanned"
    if verification == "unsafe" or status == "Threats Found":
        return "finding_detected"
    if status == "Manual Verification Needed" or is_outdated:
        return "needs_review"
    if verification == "safe":
        return "verified_safe"
    return "healthy"


def _failed_log_entry(file_path: Path, month_dir: Path, month: str):
    system_name, subsystem_name, display_filename = classify_evidence_path(file_path, month_dir)
    return {
        "system": system_name,
        "subsystem": subsystem_name,
        "filename": display_filename,
        "status": "Manual Verification Needed",
        "scan_status": "scan_failed",
        "path": public_log_path(file_path),
        "type": file_path.suffix.upper().replace(".", "") or "UNKNOWN",
        "dat_version": "Unknown",
        "last_scan": "Unknown",
        "is_outdated": False,
        "verification": None,
        "month": month,
        "pdf_systems": [],
        "dat_version_candidate": "",
        "last_scan_candidate": "",
        "verification_reasons": ["An unexpected processing failure prevented analysis."],
        "date_evidence_count": 0,
        "parse_failed": True,
    }


def _empty_payload(checklist_data, month: str = ""):
    checklist_valid = bool(checklist_data.get("valid", False))
    checklist_source = public_checklist_source(checklist_data.get("path", ""))
    return {
        "month": month,
        "logs": {},
        "missing": [],
        "system_tree": checklist_data.get("system_tree", []) if checklist_valid else [],
        "checklist_source": checklist_source,
        "checklist": {
            "valid": checklist_valid,
            "source": checklist_source,
            "error": str(checklist_data.get("error", "")),
        },
        "coverage": {
            "complete": False,
            "expected_evidence": 0,
            "confirmed_evidence": 0,
            "missing_evidence": 0,
            "unknown_coverage": 0,
            "evidence_files": 0,
            "matched_files": 0,
            "unmatched_files": 0,
            "not_scanned_files": 0,
            "failed_files": 0,
            "review_files": 0,
            "finding_files": 0,
        },
        "reconciliation": [],
        "errors": [str(checklist_data.get("error", ""))] if not checklist_valid else [],
    }


def reconcile_epo_companion_reports(entries: list[dict]) -> None:
    """Join ePO DAT metadata with its required per-system threat report."""
    for dat_entry in (entry for entry in entries if entry.get("document_role") == "epo_dat_report"):
        companions = [
            entry for entry in entries
            if entry is not dat_entry
            and entry.get("system") == dat_entry.get("system")
            and entry.get("document_role") == "epo_threat_report"
        ]
        reasons = dat_entry.setdefault("verification_reasons", [])
        if not companions:
            reason = (
                "Required ePO threat-detection PDF is missing for this system; "
                "the DAT-properties PDF alone cannot prove a clean result."
            )
            if reason not in reasons:
                reasons.insert(0, reason)
            dat_entry["status"] = "Manual Verification Needed"
            dat_entry["companion_report_status"] = "missing"
            dat_entry["companion_report_paths"] = []
            dat_entry["scan_status"] = "needs_review"
            continue

        dat_entry["companion_report_paths"] = [entry.get("path", "") for entry in companions]
        reasons[:] = [
            reason for reason in reasons
            if "ePO properties report contains scan metadata" not in reason
        ]
        companion_statuses = {entry.get("status") for entry in companions}
        if "Threats Found" in companion_statuses:
            dat_entry["status"] = "Threats Found"
            dat_entry["companion_report_status"] = "threats_found"
        elif companion_statuses == {"Clean"}:
            dat_entry["status"] = "Clean"
            dat_entry["companion_report_status"] = "clean"
        else:
            reason = "The companion ePO threat-detection PDF also requires review."
            if reason not in reasons:
                reasons.append(reason)
            dat_entry["status"] = "Manual Verification Needed"
            dat_entry["companion_report_status"] = "needs_review"
        dat_entry["scan_status"] = _scan_status(dat_entry["status"], False, {})


def collect_logs(scan_images: bool = False, month: Optional[str] = None):
    """Build the full /api/logs payload — inventory, analysis, coverage, missing.

    This is the heart of the application. When scan_images=False (the default
    inventory request), it reads the evidence tree, parses everything that
    already has cached results, and returns the dashboard payload. No OCR runs.

    When scan_images=True (the operator clicked "Scan all"), it processes every
    supported file in parallel via ThreadPoolExecutor, runs OCR on images, and
    streams progress updates so the frontend can poll a progress bar.

    The result goes through several post-processing steps:
      - ePO companion report reconciliation (DAT PDF + threat PDF)
      - Checklist row matching (Hungarian-style one-to-one assignment)
      - Manual verification application (content-bound safe/unsafe verdicts)
      - Coverage calculation (per-location present/partial/missing/unknown)
      - Missing file alerts
    """
    if not DATA_DIR.exists():
        raise HTTPException(status_code=503, detail="The evidence directory is unavailable.")

    months = list_months()
    if not months:
        if month:
            raise HTTPException(status_code=400, detail="Unknown month selection.")
        return _empty_payload(get_month_checklist(), "")

    month = validate_month(month, allow_empty=False) if month else months[0]
    checklist_data = get_month_checklist(month)
    checklist_valid = bool(checklist_data.get("valid", False))
    checklist_rows = checklist_data.get("rows", []) if checklist_valid else []
    selected_system_tree = checklist_data.get("system_tree", []) if checklist_valid else []
    month_dir = DATA_DIR / month
    coverage_counts = {}
    unknown_coverage_systems = set()
    reconciliation = []
    errors = []

    valid_files = sorted(
        (
            file_path for file_path in month_dir.rglob("*")
            if file_path.is_file()
            and file_path.suffix.lower() in ALLOWED_LOG_EXTENSIONS
            and not file_path.name.startswith(".")
            and file_path.name.lower() != "thumbs.db"
        ),
        key=lambda path: str(path).lower(),
    )

    if scan_images:
        reset_scan_progress(month, len(valid_files))

    def process_single_file(file_path: Path):
        scan_this_file = scan_images and not is_scan_cancel_requested(month)
        system_name, subsystem_name, display_filename = classify_evidence_path(file_path, month_dir)
        pdf_systems = []
        review_details = {}

        if file_path.suffix.lower() in PDF_EXTENSIONS:
            try:
                pdf_content = read_pdf_text(file_path)
                status, dat_version, last_scan, is_outdated, review_details = analyze_file(
                    file_path,
                    scan_this_file,
                    system_name,
                    month,
                    persist_ocr=not scan_images,
                )
                pdf_systems = extract_pdf_systems(pdf_content, month)
            except Exception as exc:
                logger.warning("Unable to parse PDF %s: %s", public_log_path(file_path), exc)
                status, dat_version, last_scan, is_outdated = (
                    "Manual Verification Needed", "Unknown", "Unknown", False
                )
                review_details = {
                    "verification_reasons": ["The PDF could not be parsed safely."],
                    "parse_failed": True,
                }
        else:
            status, dat_version, last_scan, is_outdated, review_details = analyze_file(
                file_path,
                scan_this_file,
                system_name,
                month,
                persist_ocr=not scan_images,
            )

        log_entry = {
            "system": system_name,
            "subsystem": subsystem_name,
            "filename": display_filename,
            "status": status,
            "path": public_log_path(file_path),
            "type": file_path.suffix.upper().replace(".", "") or "UNKNOWN",
            "dat_version": dat_version,
            "last_scan": last_scan,
            "is_outdated": is_outdated,
            "verification": None,
            "month": month,
            "pdf_systems": pdf_systems,
            "dat_version_candidate": review_details.get("dat_version_candidate", ""),
            "last_scan_candidate": review_details.get("last_scan_candidate", ""),
            "verification_reasons": list(review_details.get("verification_reasons", [])),
            "date_evidence_count": int(review_details.get("date_evidence_count", 0)),
            "ai_fallback": review_details.get("ai_fallback"),
            "parse_failed": bool(review_details.get("parse_failed", False)),
            "scan_runs": review_details.get("scan_runs", []),
            "vendor": review_details.get("vendor", "unknown"),
            "vendor_confidence": review_details.get("vendor_confidence", 0),
            "extraction_method": review_details.get("extraction_method", "legacy"),
            "source_file_id": review_details.get("source_file_id", ""),
            "document_role": review_details.get("document_role", "unknown"),
        }
        log_entry["scan_status"] = _scan_status(status, is_outdated, review_details)
        return log_entry, scan_this_file

    processed_entries = []
    checkpoint_count = 0
    with ThreadPoolExecutor(max_workers=OCR_MAX_WORKERS) as executor:
        futures = {executor.submit(process_single_file, file_path): file_path for file_path in valid_files}
        for future in as_completed(futures):
            file_path = futures[future]
            scan_was_active = False
            failed = False
            try:
                log_entry, scan_was_active = future.result()
            except Exception as exc:
                failed = True
                logger.exception("Unexpected failure while processing %s: %s", public_log_path(file_path), exc)
                log_entry = _failed_log_entry(file_path, month_dir, month)
                errors.append(f"{public_log_path(file_path)} could not be processed.")
                scan_was_active = scan_images and not is_scan_cancel_requested(month)
            finally:
                if scan_images and scan_was_active:
                    update_scan_progress(file_path, failed=failed)
                    save_ocr_cache()
                    checkpoint_count += 1
            processed_entries.append(log_entry)

    if scan_images:
        save_ocr_cache()

    if scan_images:
        save_ocr_cache()

    processed_entries.sort(key=lambda entry: entry["path"].lower())
    reconcile_epo_companion_reports(processed_entries)
    assignments, match_metadata = match_checklist_rows(processed_entries, checklist_rows)
    logs_data = {}
    matched_files = 0
    ambiguous_files = 0

    for index, log_entry in enumerate(processed_entries):
        checklist_row = assignments[index]
        match_meta = match_metadata[index]
        status, checklist_fields = build_checklist_validation(
            log_entry,
            checklist_row,
            log_entry["status"],
        )
        checklist_fields["checklist_match_score"] = int(match_meta.get("score", 0))
        checklist_fields["checklist_match_ambiguous"] = bool(match_meta.get("ambiguous", False))
        if match_meta.get("ambiguous"):
            ambiguous_files += 1
            checklist_fields["checklist_match"] = "Ambiguous checklist match"
            reason = str(match_meta.get("reason", "Checklist match is ambiguous."))
            checklist_fields["checklist_mismatches"].append(
                f"Checklist matching discrepancy: {reason}"
            )
        elif not checklist_valid:
            checklist_fields["checklist_match"] = "Checklist unavailable"
        elif checklist_row:
            matched_files += 1

        log_entry.update(checklist_fields)
        log_entry["status"] = status
        file_path = DATA_DIR / log_entry["path"]
        status, is_outdated, verification = apply_manual_verification(file_path, status, log_entry["is_outdated"])
        log_entry["status"] = status
        log_entry["is_outdated"] = is_outdated
        log_entry["verification"] = verification
        log_entry["scan_status"] = _scan_status(
            status,
            is_outdated,
            {"parse_failed": log_entry.get("parse_failed", False)},
            verification,
        )

        # Coverage comes from the evidence path/content mapping, independently
        # of checklist metadata matching. A fuzzy or contested row must never
        # make valid evidence disappear from the missing-system calculation.
        add_file_coverage(
            coverage_counts,
            unknown_coverage_systems,
            log_entry,
            log_entry.get("subsystem", "Base System"),
            log_entry.get("pdf_systems", []),
        )
        if not checklist_row:
            reconciliation.append({
                "type": "unmapped_evidence",
                "system": log_entry["system"],
                "path": log_entry["path"],
                "reason": str(match_meta.get("reason", "No checklist row matched this evidence.")),
            })

        system_name = log_entry["system"]
        log_entry.pop("subsystem", None)
        log_entry.pop("pdf_systems", None)
        log_entry.pop("parse_failed", None)
        logs_data.setdefault(system_name, []).append(log_entry)

    system_tree_status = build_system_tree_status(
        coverage_counts,
        unknown_coverage_systems,
        selected_system_tree,
    )
    missing_alerts = []
    for system_entry in system_tree_status:
        for location in system_entry.get("locations", []):
            coverage_status = location.get("coverage_status")
            if coverage_status in {"missing", "partial"} and int(location.get("missing", 0)) > 0:
                missing_alerts.append({
                    "system": system_entry["system"],
                    "subsystem": location["name"],
                    "expected": int(location.get("expected", 0)),
                    "found": int(location.get("found", 0)),
                    "missing": int(location.get("missing", 0)),
                    "month": month,
                })
            elif coverage_status == "unknown":
                reconciliation.append({
                    "type": "unknown_coverage",
                    "system": system_entry["system"],
                    "subsystem": location["name"],
                    "expected": int(location.get("expected", 0)),
                    "found": int(location.get("found", 0)),
                    "unresolved": int(location.get("unresolved_count", 0)),
                    "reason": "Consolidated evidence exists, but endpoint coverage could not be mapped safely.",
                })

    all_logs = [log for system_logs in logs_data.values() for log in system_logs]
    all_locations = [
        location
        for system_entry in system_tree_status
        for location in system_entry.get("locations", [])
    ]
    expected_evidence = sum(int(location.get("expected", 0)) for location in all_locations)
    confirmed_evidence = sum(int(location.get("found", 0)) for location in all_locations)
    missing_evidence = sum(int(location.get("missing", 0)) for location in all_locations)
    unknown_coverage = sum(int(location.get("unresolved_count", 0)) for location in all_locations)
    failed_files = sum(log.get("scan_status") == "scan_failed" for log in all_logs)
    not_scanned_files = sum(log.get("scan_status") == "not_scanned" for log in all_logs)
    review_files = sum(log.get("scan_status") == "needs_review" for log in all_logs)
    finding_files = sum(log.get("scan_status") == "finding_detected" for log in all_logs)
    checklist_source = public_checklist_source(checklist_data.get("path", ""))
    if not checklist_valid:
        errors.append(str(checklist_data.get("error", "The monthly checklist is unavailable.")))

    coverage = {
        "complete": bool(
            checklist_valid
            and missing_evidence == 0
            and unknown_coverage == 0
            and failed_files == 0
            and not_scanned_files == 0
            and ambiguous_files == 0
        ),
        "expected_evidence": expected_evidence,
        "confirmed_evidence": confirmed_evidence,
        "missing_evidence": missing_evidence,
        "unknown_coverage": unknown_coverage,
        "evidence_files": len(valid_files),
        "matched_files": matched_files,
        "unmatched_files": len(valid_files) - matched_files,
        "ambiguous_files": ambiguous_files,
        "not_scanned_files": not_scanned_files,
        "failed_files": failed_files,
        "review_files": review_files,
        "finding_files": finding_files,
    }

    if scan_images:
        finish_scan_progress(month)

    try:
        return {
            "month": month,
            "logs": logs_data,
            "missing": missing_alerts,
            "system_tree": system_tree_status,
            "checklist_source": checklist_source,
            "checklist": {
                "valid": checklist_valid,
                "source": checklist_source,
                "error": str(checklist_data.get("error", "")),
            },
            "coverage": coverage,
            "reconciliation": reconciliation,
            "errors": errors,
        }
    finally:
        if scan_images:
            save_ocr_cache()
