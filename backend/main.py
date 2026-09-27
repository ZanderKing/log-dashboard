"""Security Center backend.

The service inventories monthly antivirus evidence, parses text/PDF logs, runs
EasyOCR only when requested, compares evidence with the monthly checklist, and
serves the statically exported Next.js dashboard.  Keep API routes above the UI
mount at the end of this file so ``/api`` is never shadowed by static files.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import logging
import os
import re
from typing import Optional
from pathlib import Path

from runtime_config import load_environment_file


APPLICATION_VERSION = "1.2.0"
BASE_DIR = Path(__file__).resolve().parent
RESOURCE_DIR = BASE_DIR

# .env files are loaded but never override already-set process variables.
# The project root .env is shared with the frontend, then backend-local.
load_environment_file(BASE_DIR.parent / ".env")
load_environment_file(BASE_DIR / ".env")

# Try the common spot first (beside the .exe or backend/), then one level up.
# This lets deployment layouts keep evidence outside the project folder.
local_2026 = (BASE_DIR / "2026").resolve()
parent_2026 = (BASE_DIR / ".." / "2026").resolve()
DATA_DIR = local_2026 if local_2026.exists() else parent_2026
UI_DIR = RESOURCE_DIR / "out"
logging.basicConfig(
    level=os.getenv("SECURITY_CENTER_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("security_center")

app = FastAPI(
    title="Security Center API",
    version=APPLICATION_VERSION,
    docs_url="/api/docs",
    redoc_url=None,
    openapi_url="/api/openapi.json",
)

# CORS is locked to exact-origin by default. Only the local dev server ports
# (Next.js on 3000, FastAPI self-reference on 8000) and any explicitly
# configured origins are allowed. No credentials — no session cookies, no tokens.
DEFAULT_ALLOWED_ORIGINS = {
    "http://127.0.0.1:3000",
    "http://localhost:3000",
    "http://127.0.0.1:8000",
    "http://localhost:8000",
}
CONFIGURED_ALLOWED_ORIGINS = {
    value.strip()
    for value in os.getenv("SECURITY_CENTER_ALLOWED_ORIGINS", "").split(",")
    if value.strip()
}
ALLOWED_ORIGINS = sorted(DEFAULT_ALLOWED_ORIGINS | CONFIGURED_ALLOWED_ORIGINS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)

@app.middleware("http")
async def add_security_headers(request, call_next):
    unsafe_method = request.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}
    origin = request.headers.get("origin", "")
    fetch_site = request.headers.get("sec-fetch-site", "").lower()
    browser_cross_origin = fetch_site in {"cross-site", "same-site"} and origin not in ALLOWED_ORIGINS
    if unsafe_method and ((origin and origin not in ALLOWED_ORIGINS) or browser_cross_origin):
        response = JSONResponse(
            status_code=403,
            content={"detail": "Cross-origin state changes are not allowed."},
        )
    else:
        response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
        "object-src 'none'; form-action 'self'; img-src 'self' data: blob:; "
        "script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "connect-src 'self'",
    )
    if request.url.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response

# Evidence file type whitelist and processing limits. Images get OCR,
# text and PDFs are parsed directly. All size limits are per-file.
IMAGE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.bmp'}
TEXT_EXTENSIONS = {'.txt', '.log', '.csv'}
PDF_EXTENSIONS = {'.pdf'}
ALLOWED_LOG_EXTENSIONS = IMAGE_EXTENSIONS | TEXT_EXTENSIONS | PDF_EXTENSIONS
MAX_SIGNATURE_THRESHOLD = 1_000_000.0
MAX_TEXT_FILE_BYTES = 10 * 1024 * 1024
MAX_PDF_FILE_BYTES = 100 * 1024 * 1024
MAX_IMAGE_FILE_BYTES = 50 * 1024 * 1024
MAX_PDF_PAGES = 500
MAX_SUMMARY_CHARS = 250_000
MAX_OCR_CACHE_ENTRIES = 2_000
# Screenshots are classified conservatively: low-confidence metadata is omitted
# and possible positive findings below the higher threshold go to manual review.
CONFIDENCE_THRESHOLD = 0.80
POSITIVE_DETECTION_CONFIDENCE_THRESHOLD = 0.90
# Explicit scan labels provide extra semantic evidence, so their immediate
# timestamp context may use a lower OCR score while still passing strict date,
# time, year, and evidence-month validation.
METADATA_CONTEXT_CONFIDENCE_THRESHOLD = 0.45
OCR_CONTEXT_GAP = "[OCR CONTEXT GAP]"
OCR_CACHE_FILE = BASE_DIR / "ocr_cache.json"
VERIFICATIONS_FILE = BASE_DIR / "verifications.json"

from ocr_runtime import (
    OCR_CANVAS_SIZE,
    OCR_FAST_MAG_RATIO,
    OCR_MAG_RATIO,
    OCR_MAX_WORKERS,
    OCR_TOTAL_MEMORY_BYTES,
    OCR_TORCH_THREADS,
    choose_ocr_magnification_plan,
    choose_ocr_worker_count,
    get_ocr_magnification_plan,
    get_ocr_reader,
    missing_ocr_models,
    ocr_models_available,
)

from checklist import (
    MONTH_ORDER,
    SYSTEM_TREE,
    configure_checklist,
    get_month_checklist,
)

# Checklist is loaded lazily on first request (not at startup). The static
# SYSTEM_TREE from checklist.py is the fallback when no month is selected.
configure_checklist(DATA_DIR)

# Keep server startup independent of Excel/OpenPyXL. The static SYSTEM_TREE
# above is the fallback; the selected month's exact checklist is loaded and
# cached on its first API request. This removes a minutes-long startup delay
# without weakening checklist validation or missing-file calculations.
CHECKLIST_ROWS = []
CHECKLIST_SYSTEM_TREE = SYSTEM_TREE

from scan_state import (
    finish_scan_progress,
    get_scan_progress_snapshot,
    increment_scan_metric,
    is_scan_cancel_requested,
    request_scan_cancel,
    reset_scan_progress,
    update_scan_progress,
)


def month_sort_key(folder_name: str):
    """'April 2026' -> (2026, 4) for newest-first sorting. Unknown -> (0, 0)."""
    year = 0
    month_num = 0
    for tok in re.findall(r'[A-Za-z]+|\d{4}', folder_name):
        low = tok.lower()
        if low in MONTH_ORDER:
            month_num = MONTH_ORDER[low]
        elif tok.isdigit() and len(tok) == 4:
            year = int(tok)
    return (year, month_num)



from ocr_cache_store import (
    configure_ocr_cache,
    has_cached_ocr_results,
    ocr_cache,
    ocr_cache_lock,
    ocr_content_inflight,
    ocr_content_inflight_lock,
    run_cached_ocr,
    clear_ocr_cache,
)

configure_ocr_cache(OCR_CACHE_FILE)

def get_cached_ocr_results(
    file_path: Path,
    *,
    persist: bool = True,
    system_name: str = "",
    evidence_month: str = "",
):
    """Use current runtime dependencies so tests and support overrides remain patchable."""
    return run_cached_ocr(
        file_path,
        reader_factory=get_ocr_reader,
        magnification_plan_factory=get_ocr_magnification_plan,
        extractor=extract_with_fail_safe,
        completeness_checker=fast_ocr_has_complete_evidence,
        metric_recorder=increment_scan_metric,
        persist=persist,
        system_name=system_name,
        evidence_month=evidence_month,
    )



from audit_store import configure_audit_store, OPERATOR_ANONYMOUS, record_audit_event

configure_audit_store(BASE_DIR)

from settings_store import (
    configure_settings_store,
    build_verification_record,
    current_thresholds,
    manual_verifications,
    save_thresholds,
    save_verifications,
    threshold_lock,
    verification_key,
    verification_lock,
)

configure_settings_store(BASE_DIR, DATA_DIR)

from ai_settings_store import (
    ai_settings_lock,
    configure_ai_settings_store,
    current_ai_settings,
    save_ai_settings,
    validate_ai_settings_update,
)

configure_ai_settings_store(BASE_DIR)

from models import AISettingsUpdate, MonthScanRequest, SingleFileScanRequest, Thresholds, VerificationDecision

@app.get("/api/settings/thresholds")
def get_thresholds():
    with threshold_lock:
        return current_thresholds.copy()

@app.post("/api/settings/thresholds")
def update_thresholds(t: Thresholds):
    updates = t.model_dump(exclude_unset=True)
    validated = {
        engine: validate_threshold_value(engine, value)
        for engine, value in updates.items()
        if value is not None
    }
    with threshold_lock:
        before = current_thresholds.copy()
        current_thresholds.update(validated)
        save_thresholds()
        saved = current_thresholds.copy()
    audit_recorded = True
    try:
        record_audit_event(
            "thresholds.updated",
            details={
                "changed_engines": sorted(validated),
                "before": {engine: before.get(engine) for engine in validated},
                "after": validated,
            },
        )
    except OSError:
        audit_recorded = False
        logger.exception("Unable to append the threshold audit event.")
    return {"status": "success", "thresholds": saved, "audit_recorded": audit_recorded}

@app.get("/api/settings/ai")
def get_ai_settings():
    with ai_settings_lock:
        settings = current_ai_settings.copy()
    return {"settings": settings, "status": local_vision_service.status()}


@app.post("/api/settings/ai")
def update_ai_settings(update: AISettingsUpdate):
    updates = update.model_dump(exclude_unset=True)
    try:
        validated = validate_ai_settings_update(updates)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    with ai_settings_lock:
        before = current_ai_settings.copy()
        current_ai_settings.update(validated)
        save_ai_settings()
        saved = current_ai_settings.copy()
    if saved.get("mode") == "off":
        local_vision_service.stop()
    try:
        record_audit_event(
            "local_ai.settings_updated",
            details={"before": before, "after": saved},
        )
    except OSError:
        logger.exception("Unable to append the local AI settings audit event.")
    return {"settings": saved, "status": local_vision_service.status()}


@app.post("/api/settings/ai/test")
def test_ai_runtime():
    try:
        local_vision_service.ensure_started()
    except (OSError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {"status": local_vision_service.status()}


@app.post("/api/logs/verification")
def update_log_verification(decision: VerificationDecision):
    verdict = decision.verdict.lower().strip()
    if verdict not in {"safe", "unsafe", "clear"}:
        raise HTTPException(status_code=400, detail="Verdict must be safe, unsafe, or clear.")

    file_path = resolve_log_path(decision.path)
    key = verification_key(file_path)
    try:
        record = None if verdict == "clear" else build_verification_record(
            file_path,
            verdict,
            decision.reviewer,
            decision.reason,
        )
    except OSError as exc:
        raise HTTPException(status_code=422, detail="Unable to bind the decision to the evidence file.") from exc

    with verification_lock:
        previous = manual_verifications.get(key)
        if verdict == "clear":
            manual_verifications.pop(key, None)
            saved_verdict = None
        else:
            manual_verifications[key] = record
            saved_verdict = verdict
        save_verifications()

    audit_recorded = True
    try:
        record_audit_event(
            "verification.updated",
            actor=decision.reviewer.strip() or OPERATOR_ANONYMOUS,
            details={
                "path": public_log_path(file_path),
                "previous_verdict": previous.get("verdict") if isinstance(previous, dict) else None,
                "verdict": saved_verdict,
                "reason": decision.reason.strip(),
                "content_sha256": record.get("content_sha256") if record else None,
            },
        )
    except OSError:
        audit_recorded = False
        logger.exception("Unable to append the verification audit event.")

    return {
        "status": "success",
        "path": public_log_path(file_path),
        "verification": saved_verdict,
        "audit_recorded": audit_recorded,
        "reviewed_at": record.get("reviewed_at") if record else None,
    }


from log_support import (
    configure_log_support,
    enforce_file_size,
    public_log_path,
    read_text_content,
    resolve_log_path,
    truncate_summary,
    validate_threshold_value,
)

configure_log_support(DATA_DIR, ALLOWED_LOG_EXTENSIONS)

from ocr_analysis import (
    analyze_and_audit,
    configure_ocr_analysis,
    extract_with_fail_safe,
    fast_ocr_has_complete_evidence,
    find_date_in_text,
)

configure_ocr_analysis(current_thresholds, month_sort_key)

from ai_vision import (
    analyze_with_qwen,
    clear_ai_cache,
    configure_ai_vision,
    local_vision_service,
    reconcile_ocr_and_ai,
)

configure_ai_vision(
    BASE_DIR,
    BASE_DIR.parent,
    current_ai_settings,
    increment_scan_metric,
)


from log_service import (
    analyze_file,
    collect_logs,
    configure_log_service,
    infer_evidence_month,
    infer_system_name,
    list_months,
    read_pdf_text,
    validate_month,
)

configure_log_service(
    data_dir=DATA_DIR,
    allowed_extensions=ALLOWED_LOG_EXTENSIONS,
    text_extensions=TEXT_EXTENSIONS,
    pdf_extensions=PDF_EXTENSIONS,
    image_extensions=IMAGE_EXTENSIONS,
    max_text_bytes=MAX_TEXT_FILE_BYTES,
    max_pdf_bytes=MAX_PDF_FILE_BYTES,
    max_image_bytes=MAX_IMAGE_FILE_BYTES,
    max_pdf_pages=MAX_PDF_PAGES,
    ocr_workers=OCR_MAX_WORKERS,
    month_key=month_sort_key,
    ocr_provider=get_cached_ocr_results,
    ai_provider=analyze_with_qwen,
    ai_reconciler=reconcile_ocr_and_ai,
)

from reporting import build_monthly_report


@app.get("/api/months")
def get_months():
    """List available month folders, newest first (for the dashboard dropdown)."""
    return list_months()

@app.get("/api/system-tree")
def get_system_tree(month: Optional[str] = None):
    selected_month = validate_month(month, allow_empty=False) if month else None
    if not selected_month:
        months = list_months()
        if not months:
            return []
        selected_month = months[0]
    checklist_data = get_month_checklist(selected_month)
    if not checklist_data.get("valid"):
        raise HTTPException(
            status_code=422,
            detail=checklist_data.get("error", "The monthly checklist is unavailable."),
        )
    return checklist_data.get("system_tree", [])

@app.get("/api/scan-progress")
def get_scan_progress():
    return get_scan_progress_snapshot()

@app.post("/api/scan/stop")
def stop_scan():
    """Cooperatively stop the active full or single-file OCR scan."""
    before = get_scan_progress_snapshot()
    requested = request_scan_cancel()
    if requested:
        try:
            record_audit_event(
                "scan.stop_requested",
                details={"job_id": before.get("job_id"), "month": before.get("month")},
            )
        except OSError:
            logger.exception("Unable to append the scan-stop audit event.")
    return {
        "status": "stopping" if requested else "idle",
        "message": (
            "Stop requested. OCR already in progress will finish safely."
            if requested
            else "No OCR scan is currently running."
        ),
    }

@app.post("/api/logs/scan")
def scan_log_file(request: SingleFileScanRequest):
    """Scan one validated evidence file without walking the selected month."""
    file_path = resolve_log_path(request.path)
    month = infer_evidence_month(file_path)
    if not month:
        raise HTTPException(status_code=400, detail="The log file is not inside a month folder.")

    reset_scan_progress(month, 1)
    job_id = get_scan_progress_snapshot().get("job_id")
    outcome = "failed"
    try:
        try:
            record_audit_event(
                "scan.single_started",
                details={"job_id": job_id, "month": month, "path": public_log_path(file_path)},
            )
        except OSError:
            logger.exception("Unable to append the single-scan start audit event.")

        status, dat_version, last_scan, is_outdated, review_details = analyze_file(
            file_path,
            True,
            infer_system_name(file_path),
            month,
            persist_ocr=True,
        )
        parse_failed = bool(review_details.get("parse_failed", False))
        update_scan_progress(file_path, failed=parse_failed)
        outcome = "completed_with_errors" if parse_failed else "completed"
        return {
            "status": "success",
            "path": public_log_path(file_path),
            "result": {
                "status": status,
                "scan_status": "scan_failed" if parse_failed else "complete",
                "dat_version": dat_version,
                "last_scan": last_scan,
                "is_outdated": is_outdated,
                "verification_reasons": review_details.get("verification_reasons", []),
            },
        }
    finally:
        finish_scan_progress(month)
        try:
            record_audit_event(
                "scan.single_finished",
                details={
                    "job_id": job_id,
                    "month": month,
                    "path": public_log_path(file_path),
                    "outcome": outcome,
                },
            )
        except OSError:
            logger.exception("Unable to append the single-scan completion audit event.")

@app.get("/api/health")
def get_health():
    """Readiness check covering evidence, UI, checklist, models, and state path."""
    months = list_months()
    checklist_data = get_month_checklist(months[0]) if months else {"valid": False, "error": "No month folders."}
    checks = {
        "data_directory": DATA_DIR.exists(),
        "ui_assets": (UI_DIR / "index.html").is_file(),
        "checklist_valid": bool(checklist_data.get("valid", False)),
        "ocr_models": ocr_models_available(),
        "local_ai": (
            local_vision_service.files_available()
            if current_ai_settings.get("mode") == "review_only"
            else True
        ),
        "state_directory_writable": os.access(BASE_DIR, os.W_OK),
    }
    return {
        "status": "ok" if all(checks.values()) else "degraded",
        **checks,
        "checklist_error": str(checklist_data.get("error", "")),
        "missing_ocr_models": missing_ocr_models(),
        "local_ai": local_vision_service.status(),
        "scan_active": get_scan_progress_snapshot().get("active", False),
        "ocr_workers": OCR_MAX_WORKERS,
        "ocr_torch_threads": OCR_TORCH_THREADS,
        "ocr_memory_gb": round(OCR_TOTAL_MEMORY_BYTES / 1024**3, 2),
        "ocr_primary_small_image_mag_ratio": OCR_MAG_RATIO,
        "ocr_large_image_mag_ratio": OCR_FAST_MAG_RATIO,
        "authentication": "not implemented; loopback is the secure default",
        "version": APPLICATION_VERSION,
    }


@app.get("/api/logs")
def get_logs(month: Optional[str] = None):
    """Read-only inventory; OCR can only be triggered through POST."""
    return collect_logs(scan_images=False, month=month)


@app.post("/api/logs/scan-all")
def scan_all_logs(request: MonthScanRequest):
    """Run the manually requested full OCR scan for one validated month."""
    month = validate_month(request.month, allow_empty=False)
    outcome = "failed"
    payload = None
    try:
        try:
            record_audit_event("scan.full_requested", details={"month": month})
        except OSError:
            logger.exception("Unable to append the full-scan request audit event.")
        payload = collect_logs(scan_images=True, month=month)
        outcome = "completed" if payload.get("coverage", {}).get("failed_files", 0) == 0 else "completed_with_errors"
        return payload
    finally:
        snapshot = get_scan_progress_snapshot()
        if snapshot.get("active") and snapshot.get("month") == month:
            finish_scan_progress(month)
            snapshot = get_scan_progress_snapshot()
        try:
            record_audit_event(
                "scan.full_finished",
                details={
                    "job_id": snapshot.get("job_id"),
                    "month": month,
                    "outcome": outcome,
                    "completed": snapshot.get("completed"),
                    "failed": snapshot.get("failed"),
                },
            )
        except OSError:
            logger.exception("Unable to append the full-scan completion audit event.")


@app.post("/api/logs/ai-review")
def run_ai_review(request: MonthScanRequest):
    """Run local Qwen only on files that OCR left in Manual Verification Needed."""
    month = validate_month(request.month, allow_empty=False)
    if current_ai_settings.get("mode", "off") != "review_only":
        raise HTTPException(status_code=400, detail="Local AI fallback is not enabled in Settings.")
    if not local_vision_service.files_available():
        raise HTTPException(status_code=503, detail="Local AI runtime or model files are missing.")

    payload = collect_logs(scan_images=False, month=month)
    all_logs = [log for logs in payload.get("logs", {}).values() for log in logs]
    review_logs = [
        log for log in all_logs
        if log.get("status") == "Manual Verification Needed"
        and log.get("type", "") in ("JPG", "JPEG", "PNG", "BMP", "GIF")
    ]

    if not review_logs:
        return {"status": "no_review_needed", "reviewed": 0, "month": month}

    reset_scan_progress(month, len(review_logs))
    job_id = get_scan_progress_snapshot().get("job_id")
    reviewed = 0
    try:
        for log_entry in review_logs:
            if is_scan_cancel_requested(month):
                break
            file_path = DATA_DIR / log_entry["path"]
            update_scan_progress(
                file_path,
                failed=False,
            )
            result = analyze_with_qwen(file_path, month, allow_inference=True)
            if result:
                reviewed += 1
                increment_scan_metric("ai_reviews")
    finally:
        finish_scan_progress(month)
        try:
            record_audit_event(
                "ai.review_finished",
                details={"job_id": job_id, "month": month, "reviewed": reviewed, "total": len(review_logs)},
            )
        except OSError:
            logger.exception("Unable to append the AI review audit event.")

    return {"status": "completed", "reviewed": reviewed, "total": len(review_logs), "month": month}


@app.post("/api/cache/clear")
def clear_cache_endpoint():
    """Clear in-memory and persistent OCR result cache."""
    clear_ocr_cache()
    clear_ai_cache()
    try:
        record_audit_event("cache.cleared", actor=OPERATOR_ANONYMOUS, details={"scope": "ocr_and_local_ai"})
    except OSError:
        pass
    return {"status": "success", "message": "OCR and local AI caches have been cleared."}


@app.get("/api/reports/monthly", response_class=HTMLResponse)
def get_monthly_report(month: str):
    """Download a printable report generated from the live dashboard payload."""
    month = validate_month(month, allow_empty=False)
    payload = collect_logs(scan_images=False, month=month)
    with threshold_lock:
        thresholds = current_thresholds.copy()
    report = build_monthly_report(
        payload,
        thresholds,
        application_version=APPLICATION_VERSION,
    )
    safe_month = re.sub(r"[^A-Za-z0-9_-]+", "-", month).strip("-") or "month"
    return HTMLResponse(
        content=report,
        headers={
            "Content-Disposition": f'attachment; filename="SecurityCenter-{safe_month}.html"',
            "X-Report-Coverage": "complete" if payload.get("coverage", {}).get("complete") else "incomplete",
        },
    )

@app.get("/api/logs/summary")
def get_log_summary(path: str, status: str = ""):
    file_path = resolve_log_path(path)
    ext = file_path.suffix.lower()
    try:
        if ext in TEXT_EXTENSIONS:
            return {"summary": truncate_summary(read_text_content(file_path))}
        if ext in PDF_EXTENSIONS:
            return {"summary": truncate_summary(read_pdf_text(file_path))}
        if ext in IMAGE_EXTENSIONS:
            enforce_file_size(file_path, MAX_IMAGE_FILE_BYTES, "Image")
            if not has_cached_ocr_results(file_path):
                return {"summary": "This image has not been scanned for threats yet. Click 'Scan'."}
            ocr_results = get_cached_ocr_results(file_path)
            _, summary_text, _, _, _, _review_details = analyze_and_audit(
                ocr_results,
                infer_system_name(file_path),
                infer_evidence_month(file_path),
            )
            return {"summary": truncate_summary(summary_text) if summary_text else "No text could be extracted."}
        return {"error": "Unsupported file type for summary."}
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Unable to read summary for %s: %s", public_log_path(file_path), exc)
        raise HTTPException(status_code=422, detail="Unable to read log summary.")

@app.get("/api/logs/file")
def get_log_image(path: str):
    """Serve only validated image evidence; never expose the data tree broadly."""
    file_path = resolve_log_path(path, allowed_extensions=IMAGE_EXTENSIONS)
    try:
        enforce_file_size(file_path, MAX_IMAGE_FILE_BYTES, "Image")
    except ValueError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    return FileResponse(
        file_path,
        filename=file_path.name,
        content_disposition_type="inline",
        headers={"Cache-Control": "private, max-age=60"},
    )

# ----- Final static UI mount --------
# Must be the absolute last route registration. Anything below this line will
# never be reached because StaticFiles catches all remaining paths.
# check_dir=False is intentional — it lets the API start even when the UI hasn't
# been built yet (health check will report the missing assets).
app.mount("/", StaticFiles(directory=str(UI_DIR), html=True, check_dir=False), name="ui")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host=os.getenv("SECURITY_CENTER_HOST", "127.0.0.1"),
        port=int(os.getenv("SECURITY_CENTER_PORT", "8000")),
        reload=False,
    )
