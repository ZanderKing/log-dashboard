"""Structured extraction, vendor classification, and normalized scan parsing."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import hashlib
import io
from pathlib import Path
import re
import tempfile
import time
from typing import Callable, Optional

import pypdf

from storage import sha256_file

from checklist import MONTH_ORDER


PARSER_VERSION = "structured-v2"
SUPPORTED_UPLOAD_EXTENSIONS = {".pdf", ".txt", ".log", ".csv", ".png", ".jpg", ".jpeg"}
VENDORS = {"trellix_mcafee", "symantec", "trend_micro", "clamwin", "generic_antivirus"}
PDF_MAGIC = b"%PDF-"
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
JPEG_MAGIC = b"\xff\xd8\xff"
MIN_NATIVE_PAGE_TEXT = 24
MAX_STRUCTURED_PDF_PAGES = 500

DATE_FORMATS = (
    "%m/%d/%Y %I:%M:%S %p", "%m/%d/%y %I:%M:%S %p",
    "%m/%d/%Y %I:%M %p", "%m/%d/%y %I:%M %p",
    "%Y/%m/%d %I:%M:%S %p", "%Y/%m/%d %I:%M %p",
    "%B %d, %Y %H:%M:%S", "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S", "%m/%d/%y %H:%M:%S",
)
DATE_RE = re.compile(
    r"\b(?:\d{1,2}/\d{1,2}/\d{2,4}\s+\d{1,2}:\d{2}(?::\d{2})?\s*(?:AM|PM)|"
    r"[A-Za-z]+\s+\d{1,2},\s+\d{4}\s+\d{1,2}:\d{2}:\d{2}|"
    r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\b",
    re.IGNORECASE,
)


def decode_text(data: bytes) -> tuple[str, str, list[str]]:
    warnings: list[str] = []
    for encoding in ("utf-8-sig", "utf-16", "cp1252"):
        try:
            text = data.decode(encoding)
            if encoding != "utf-8-sig":
                warnings.append(f"Decoded using {encoding} fallback.")
            return text, encoding, warnings
        except UnicodeDecodeError:
            continue
    warnings.append("Undecodable bytes were replaced.")
    return data.decode("utf-8", errors="replace"), "utf-8-replace", warnings


def validate_file_content(path: Path) -> str:
    """Return detected type after checking magic/text structure, not extension alone."""
    extension = path.suffix.lower()
    with path.open("rb") as handle:
        head = handle.read(8192)
    if not head:
        raise ValueError("The uploaded file is empty.")
    if extension == ".pdf":
        if not head.startswith(PDF_MAGIC):
            raise ValueError("The file extension is PDF but the content is not a PDF.")
        return "application/pdf"
    if extension == ".png":
        if not head.startswith(PNG_MAGIC):
            raise ValueError("The file extension is PNG but the content is not a PNG image.")
        return "image/png"
    if extension in {".jpg", ".jpeg"}:
        if not head.startswith(JPEG_MAGIC):
            raise ValueError("The file extension is JPEG but the content is not a JPEG image.")
        return "image/jpeg"
    if extension not in {".txt", ".log", ".csv"}:
        raise ValueError("Unsupported structured log type.")
    if b"\x00" in head and not (head.startswith(b"\xff\xfe") or head.startswith(b"\xfe\xff")):
        raise ValueError("The text log contains unexpected binary data.")
    text, _encoding, _warnings = decode_text(head)
    if not text.strip():
        raise ValueError("The text log is empty.")
    if extension == ".csv":
        try:
            csv.Sniffer().sniff(text, delimiters=",;\t|")
        except csv.Error as exc:
            raise ValueError("The CSV delimiter or row structure could not be identified.") from exc
        return "text/csv"
    return "text/plain"


def _parse_datetime(value: str) -> Optional[datetime]:
    cleaned = " ".join(value.replace("\u00a0", " ").split())
    for fmt in DATE_FORMATS:
        try:
            return datetime.strptime(cleaned, fmt)
        except ValueError:
            continue
    return None


def _iso(value: str) -> Optional[str]:
    parsed = _parse_datetime(value)
    return parsed.isoformat(sep=" ") if parsed else None


def _duration_seconds(value: str) -> Optional[int]:
    value = value.strip().replace(",", "")
    if value.isdigit():
        return int(value)
    parts = value.split(":")
    if 2 <= len(parts) <= 3 and all(part.isdigit() for part in parts):
        parts = [int(part) for part in parts]
        if len(parts) == 2:
            return parts[0] * 60 + parts[1]
        return parts[0] * 3600 + parts[1] * 60 + parts[2]
    return None


def _stable_run_id(source_id: str, vendor: str, endpoint: str, completed: str, index: int) -> str:
    seed = f"{source_id}:{PARSER_VERSION}:{vendor}:{endpoint}:{completed}:{index}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:24]


def _base_run(source_id: str, vendor: str, index: int, **values) -> dict:
    endpoint = values.get("endpoint") or "Unknown"
    completed = values.get("scan_completion_time") or values.get("scan_start_time") or ""
    run = {
        "scan_run_id": _stable_run_id(source_id, vendor, endpoint, completed, index),
        "source_file_id": source_id,
        "vendor": vendor,
        "endpoint": endpoint,
        "system_id": None,
        "scan_type": values.get("scan_type"),
        "scan_start_time": values.get("scan_start_time"),
        "scan_completion_time": values.get("scan_completion_time"),
        "scan_duration_seconds": values.get("scan_duration_seconds"),
        "timestamp_source": values.get("timestamp_source", "log_content"),
        "normalized_status": values.get("normalized_status", "Requires review"),
        "original_status": values.get("original_status"),
        "files_scanned": values.get("files_scanned"),
        "files_skipped": values.get("files_skipped"),
        "threats_detected": values.get("threats_detected"),
        "threats_remediated": values.get("threats_remediated"),
        "threat_names": values.get("threat_names", []),
        "detection_actions": values.get("detection_actions", []),
        "definition_version": values.get("definition_version"),
        "engine_version": values.get("engine_version"),
        "source_event_id": values.get("source_event_id"),
        "source_level": values.get("source_level"),
        "source_event_origin": values.get("source_event_origin"),
        "description_summary": values.get("description_summary"),
        "result_basis": values.get("result_basis"),
        "warnings": list(dict.fromkeys(values.get("warnings", []))),
        "parser_version": PARSER_VERSION,
    }
    return run


CLASSIFIER_RULES = {
    "trellix_mcafee": (
        (r"\b(?:mcafee|trellix)\b", 5, "McAfee/Trellix product name"),
        (r"\bamcore content version\b", 4, "AMCore field"),
        (r"\bendpoint security threat prevention custom properties\b", 4, "ePO Threat Prevention report"),
        (r"\bnumber of threat events\b", 6, "ePO threat-event total"),
        (r"\bods(?:b1)?\.ods\.activity\b|\bmfetp\b", 5, "OnDemandScan activity syntax"),
        (r"\bvirus\s*scan enterprise\b|\bantivirus dat version\b", 4, "VirusScan Enterprise fields"),
        (r"\bfiles with detections\b|\bfile detections\b", 3, "McAfee scan-summary fields"),
    ),
    "trend_micro": (
        (r"\btrend micro\b|\bdeep security\b", 6, "Trend Micro/Deep Security product name"),
        (r"\bagent/appliance event", 4, "Deep Security event structure"),
        (r"\bmanual malware scan (?:started|completed)\b", 4, "Trend Micro scan event"),
        (r"\bevent id\b.*\b900[12]\b", 3, "Trend Micro scan event ID"),
    ),
    "clamwin": (
        (r"\bclamwin\b", 6, "ClamWin product name"),
        (r"\bknown viruses\b", 4, "ClamWin signature field"),
        (r"\binfected files\s*:", 5, "ClamWin result field"),
        (r"\bvirus db version\b", 3, "ClamWin definition field"),
    ),
    "symantec": (
        (r"\bsymantec\b|\bendpoint protection\b", 6, "Symantec product name"),
        (r"\btotal risks? detected\b|\brisks? found\b", 4, "Symantec result field"),
        (r"\bvirus definitions?\b", 3, "Symantec definition field"),
    ),
    "generic_antivirus": (),
}


def classify_vendor(text: str, *, csv_headers: Optional[list[str]] = None) -> dict:
    evidence_text = text[:2_000_000]
    if csv_headers:
        evidence_text = " ".join(csv_headers) + "\n" + evidence_text
    scores: dict[str, int] = {}
    indicators: dict[str, list[str]] = {}
    for vendor, rules in CLASSIFIER_RULES.items():
        score = 0
        found: list[str] = []
        for pattern, weight, reason in rules:
            if re.search(pattern, evidence_text, re.IGNORECASE | re.DOTALL):
                score += weight
                found.append(reason)
        scores[vendor] = score
        indicators[vendor] = found
    if csv_headers:
        normalized = {header.strip().lower() for header in csv_headers}
        expected = {"time", "level", "event id", "event", "event origin", "target", "description"}
        if expected.issubset(normalized):
            scores["trend_micro"] += 6
            indicators["trend_micro"].append("Deep Security System Events CSV columns")
        generic_scan_headers = {
            "started on", "completed", "computer", "status", "total files", "infected",
        }
        if generic_scan_headers.issubset(normalized):
            scores["generic_antivirus"] += 6
            indicators["generic_antivirus"].append("Completed-scan CSV columns")
    ranked = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
    top_vendor, top_score = ranked[0]
    second_vendor, second_score = ranked[1]
    if top_score < 5:
        return {"vendor": "unknown", "confidence": 0.0, "scores": scores, "indicators": [],
                "conflicts": [], "reason": "No supported vendor signature reached the minimum score.",
                "requires_review": True}
    if second_score >= 5 and top_score - second_score <= 2:
        return {"vendor": "ambiguous", "confidence": round(top_score / max(1, sum(scores.values())), 3),
                "scores": scores, "indicators": indicators[top_vendor],
                "conflicts": [top_vendor, second_vendor],
                "reason": "Two vendor signatures scored similarly.", "requires_review": True}
    return {"vendor": top_vendor, "confidence": round(min(1.0, top_score / 12), 3),
            "scores": scores, "indicators": indicators[top_vendor],
            "conflicts": [vendor for vendor, score in ranked[1:] if score >= 5],
            "reason": "; ".join(indicators[top_vendor]), "requires_review": False}


def _csv_rows(text: str) -> tuple[list[dict], list[str], str]:
    try:
        dialect = csv.Sniffer().sniff(text[:8192], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    headers = [str(value or "").strip() for value in (reader.fieldnames or [])]
    rows = [{str(k or "").strip(): str(v or "").strip() for k, v in row.items()} for row in reader]
    return rows, headers, dialect.delimiter


def _parse_epo_report(text: str, source_id: str) -> list[dict]:
    if not all(label in text.lower() for label in ("on-demand full scan date", "amcore content version", "system name")):
        return []
    row_re = re.compile(
        r"^(?P<date>\d{1,2}/\d{1,2}/\d{2,4}\s+\d{1,2}:\d{2}(?::\d{2})?\s+[AP]M)\s+"
        r"(?P<dat>\d+(?:\.\d+)?)\s+(?P<duration><\s*1|\d+(?:\.\d+)?\+?)\s+"
        r"(?P<endpoint>[A-Z0-9][A-Z0-9_-]{1,})$", re.IGNORECASE,
    )
    runs = []
    for line in text.splitlines():
        match = row_re.match(" ".join(line.split()))
        if not match:
            continue
        completed = _iso(match.group("date"))
        duration = match.group("duration").replace(" ", "").rstrip("+")
        duration_seconds = 1800 if duration.startswith("<") else int(float(duration) * 3600)
        dat_value = match.group("dat")
        if not 1000 <= float(dat_value) <= 100000:
            dat_value = None
        runs.append(_base_run(
            source_id, "trellix_mcafee", len(runs), endpoint=match.group("endpoint").upper(),
            scan_type="On-Demand Full Scan", scan_completion_time=completed,
            scan_duration_seconds=duration_seconds, timestamp_source="report_scan_date",
            normalized_status="Requires review", original_status="Listed in completed-scan report",
            threats_detected=None, definition_version=dat_value,
            warnings=["The ePO properties report contains scan metadata but no detection-result field."],
        ))
    return runs


def _parse_epo_threat_report(text: str, source_id: str) -> list[dict]:
    """Parse the ePO threat-event summary, where an explicit total is decisive."""
    if not re.search(r"\bnumber of threat events\b", text, re.IGNORECASE):
        return []
    total_match = re.search(r"\btotal\s+([0-9][0-9,]*)\b", text, re.IGNORECASE)
    if not total_match:
        return []
    threats = int(total_match.group(1).replace(",", ""))
    dates = list(DATE_RE.finditer(text))
    generated = _iso(dates[-1].group(0)) if dates else None
    warnings = [] if generated else ["The ePO threat-event total had no report timestamp."]
    return [_base_run(
        source_id, "trellix_mcafee", 0, scan_type="ePO threat-event report",
        scan_completion_time=generated, timestamp_source="report_generated_time" if generated else "unknown",
        normalized_status="Completed with detections" if threats else "Completed clean",
        original_status="ePO threat event total", threats_detected=threats,
        result_basis="epo_threat_event_total", warnings=warnings,
    )]


def _parse_generic_scan_csv(rows: list[dict], source_id: str) -> list[dict]:
    """Parse completed-scan exports with explicit file and infection counts."""
    runs = []
    for row in rows:
        fields = {str(key).strip().casefold(): value for key, value in row.items()}
        status = fields.get("status", "")
        if not re.search(r"\b(?:scan )?complete(?:d)?\b", status, re.IGNORECASE):
            continue
        infected = _labelled_int(f"Infected: {fields.get('infected', '')}", ("infected",))
        files_scanned = _labelled_int(f"Total Files: {fields.get('total files', '')}", ("total files",))
        completed = _iso(fields.get("completed", ""))
        started = _iso(fields.get("started on", ""))
        if infected is None:
            continue
        warnings = [] if completed else ["Completed-scan CSV row had no valid completion timestamp."]
        runs.append(_base_run(
            source_id, "generic_antivirus", len(runs),
            endpoint=fields.get("computer", "") or "Unknown",
            scan_type=fields.get("logged by", "") or "Antivirus scan",
            scan_start_time=started, scan_completion_time=completed,
            timestamp_source="csv_completed_time" if completed else "unknown",
            normalized_status="Completed with detections" if infected else "Completed clean",
            original_status=status, files_scanned=files_scanned, threats_detected=infected,
            result_basis="generic_csv_infected_count", warnings=warnings,
        ))
    return runs


def _labelled_int(text: str, labels: tuple[str, ...]) -> Optional[int]:
    for label in labels:
        match = re.search(rf"\b{label}\b\s*(?::|=|-)?\s*([0-9][0-9,]*)", text, re.IGNORECASE)
        if match:
            return int(match.group(1).replace(",", ""))
    return None


def _parse_mcafee_activity(text: str, source_id: str) -> list[dict]:
    has_activity_log = re.search(r"ods\.activity|scan summary|virus\s*scan enterprise", text, re.IGNORECASE)
    has_product_completion = (
        re.search(r"\b(?:mcafee|trellix)\b", text, re.IGNORECASE)
        and re.search(r"\bscan complete(?:d)?\b", text, re.IGNORECASE)
    )
    if not (has_activity_log or has_product_completion):
        return []
    lines = [" ".join(line.split()) for line in text.splitlines() if line.strip()]
    completed_indexes = [
        i for i, line in enumerate(lines)
        if re.search(r"\bscan complete(?:d)?\b", line, re.IGNORECASE) and DATE_RE.search(line)
    ]
    runs = []
    start_index = 0
    dat_match = re.search(r"(?:anti[- ]?virus\s+dat|dat|amcore\s+content)\s+version\s*[:=]\s*([0-9]+(?:\.[0-9]+)*)", text, re.IGNORECASE)
    engine_match = re.search(r"(?:scan\s+)?engine\s+version(?:\s*\([^)]*\))?\s*[:=]\s*([0-9]+(?:\.[0-9]+)+)", text, re.IGNORECASE)
    threat_labels = (
        "files? with detections", "file detections", "processes detected", "boot sectors detected",
        "registry detections", "keys detected", "memory detections", "cookies detected",
        "threats? detected", "infected files?", "detections",
    )
    for end_index in completed_indexes:
        chunk = "\n".join(lines[start_index:end_index + 1])
        completion_line = lines[end_index]
        timestamp_match = DATE_RE.search(completion_line)
        completion = _iso(timestamp_match.group(0)) if timestamp_match else None
        tail = re.split(r"scan complete(?:d)?", completion_line, flags=re.IGNORECASE, maxsplit=1)[-1].strip()
        machine = re.search(r"(?:[A-Za-z0-9_.-]+\\)?(?P<host>[A-Za-z0-9_-]+)\$(?:\s|$)", tail)
        if not machine:
            machine = re.search(r"(?P<host>[A-Za-z0-9_-]+)\\(?:Administrator|SYSTEM|[^\\\s]+)", tail, re.IGNORECASE)
        endpoint = machine.group("host") if machine else "Unknown"
        kind = re.search(r"\b(full scan|quick scan|targeted scan)\b", tail, re.IGNORECASE)
        scan_type = kind.group(1).title() if kind else "On-Demand Scan"
        duration_match = re.search(r"\((\d{1,3}:\d{2}(?::\d{2})?)\)\s*$", tail)
        duration_seconds = _duration_seconds(duration_match.group(1)) if duration_match else None
        counts = []
        for label in threat_labels:
            counts.extend(int(value.replace(",", "")) for value in re.findall(
                rf"\b{label}\b\s*(?::|=|-)?\s*([0-9][0-9,]*)", chunk, re.IGNORECASE,
            ))
        explicit_nothing = bool(re.search(
            r"\bnothing found\b|\bno (?:threats?|viruses|infected files?) (?:were )?(?:detected|found)\b|"
            r"\bdetections\s*(?::|=|-)?\s*0\b",
            chunk, re.IGNORECASE,
        ))
        threats = max(counts) if counts else (0 if explicit_nothing else None)
        skipped = _labelled_int(chunk, ("files? not scanned", "objects? skipped"))
        files_scanned = _labelled_int(chunk, ("files? scanned", "items? scanned"))
        warnings = []
        if skipped:
            warnings.append(f"{skipped} files or objects were not scanned.")
        if threats is None:
            warnings.append("No contextual numeric detection result was found in the completed summary.")
        status = "Completed with detections" if threats and threats > 0 else "Completed with warnings" if warnings else "Completed clean"
        runs.append(_base_run(
            source_id, "trellix_mcafee", len(runs), endpoint=endpoint.upper(), scan_type=scan_type,
            scan_completion_time=completion, scan_duration_seconds=duration_seconds,
            normalized_status=status, original_status="Scan Complete", files_scanned=files_scanned,
            files_skipped=skipped, threats_detected=threats,
            definition_version=dat_match.group(1) if dat_match else None,
            engine_version=engine_match.group(1) if engine_match else None, warnings=warnings,
        ))
        start_index = end_index + 1
    return runs


def _parse_clamwin(text: str, source_id: str, file_mtime: float) -> list[dict]:
    """Parse all individual ClamWin scan blocks from a concatenated log."""
    if not re.search(r"\bscan summary\b", text, re.IGNORECASE):
        return []

    # ClamWin logs concatenate multiple scans.  Split on "Scan Started"
    # headers and extract each completed scan independently.
    scan_start_re = re.compile(
        r"Scan\s+Started\s+"
        r"(\w+\s+\w+\s+\d{1,2}\s+\d{1,2}:\d{2}:\d{2}\s+\d{4})",
        re.IGNORECASE,
    )
    summary_re = re.compile(r"-+\s*SCAN SUMMARY\s*-+")

    starts = list(scan_start_re.finditer(text))
    if not starts:
        # Fallback: file has a summary but no parseable "Scan Started" header.
        infected = _labelled_int(text, ("infected files?",))
        if infected is None:
            return []
        completed = datetime.fromtimestamp(file_mtime).isoformat(sep=" ")
        known = _labelled_int(text, ("known viruses",))
        engine = re.search(r"\bengine version\s*:\s*([0-9.]+)", text, re.IGNORECASE)
        scanned = _labelled_int(text, ("scanned files",))
        return [_base_run(
            source_id, "clamwin", 0, scan_type="ClamWin scan",
            scan_completion_time=completed, timestamp_source="file_mtime_fallback",
            normalized_status="Completed with detections" if infected > 0 else "Completed clean",
            original_status="Completed", files_scanned=scanned, threats_detected=infected,
            definition_version=str(known) if known is not None else None,
            engine_version=engine.group(1) if engine else None,
            warnings=["No scan timestamp was present; file modification time was used as a fallback."],
        )]

    runs: list[dict] = []
    for idx, start_match in enumerate(starts):
        end_pos = starts[idx + 1].start() if idx + 1 < len(starts) else len(text)
        block = text[start_match.start():end_pos]

        # Only completed scans have a SCAN SUMMARY.
        if not summary_re.search(block):
            continue

        infected = _labelled_int(block, ("infected files?",))
        if infected is None:
            continue

        # Parse the ClamWin ctime date: "Tue Dec 19 10:23:33 2023"
        date_str = start_match.group(1).strip()
        try:
            scan_dt = datetime.strptime(date_str, "%a %b %d %H:%M:%S %Y")
            completed = scan_dt.isoformat(sep=" ")
            timestamp_source = "log_content"
        except ValueError:
            completed = datetime.fromtimestamp(file_mtime).isoformat(sep=" ")
            timestamp_source = "file_mtime_fallback"

        known = _labelled_int(block, ("known viruses",))
        engine = re.search(r"\bengine version\s*:\s*([0-9.]+)", block, re.IGNORECASE)
        scanned = _labelled_int(block, ("scanned files",))

        scan_warnings: list[str] = []
        if timestamp_source == "file_mtime_fallback":
            scan_warnings.append(
                "No scan timestamp was present; file modification time was used as a fallback."
            )

        runs.append(_base_run(
            source_id, "clamwin", len(runs), scan_type="ClamWin scan",
            scan_completion_time=completed, timestamp_source=timestamp_source,
            normalized_status="Completed with detections" if infected > 0 else "Completed clean",
            original_status="Completed", files_scanned=scanned, threats_detected=infected,
            definition_version=str(known) if known is not None else None,
            engine_version=engine.group(1) if engine else None, warnings=scan_warnings,
        ))

    return runs


def _description_field(description: str, label: str) -> Optional[str]:
    matches = re.findall(rf"(?im)^\s*{re.escape(label)}\s*:\s*(.+?)\s*$", description)
    return matches[-1].strip().rstrip(".") if matches else None


def _parse_trend_csv(rows: list[dict], source_id: str) -> list[dict]:
    completed_rows = [row for row in rows if row.get("Event", "").strip().lower() in {
        "manual malware scan completed", "anti-malware scan completed", "scheduled malware scan completed"
    }]
    # Only narrowly named detection events are findings. Descriptions of rules,
    # configurations and product features often contain words such as malware,
    # detect and infection but are not evidence that a scan found a threat.
    positive_event = re.compile(
        r"^(?:anti-)?(?:malware|virus|threat)(?:/spyware)?\s+(?:detected|found)$|"
        r"^(?:infected file|malware detection)$", re.IGNORECASE,
    )
    positive_rows = [row for row in rows if positive_event.fullmatch(row.get("Event", "").strip())]

    def target_key(row: dict) -> str:
        return re.sub(r"\s*\([^)]*\)\s*$", "", row.get("Target", "")).strip().casefold()

    runs = []
    for row in completed_rows:
        description = row.get("Description", "")
        embedded_time = _description_field(description, "Time")
        completed = _iso(embedded_time or row.get("Time", ""))
        endpoint = re.sub(r"\s*\([^)]*\)\s*$", "", row.get("Target", "") or row.get("Manager", "")).strip()
        files_scanned = _labelled_int(description, ("number of files scanned", "files scanned"))
        duration = _labelled_int(description, ("scan time",))
        explicit_count = _labelled_int(description, (
            "threats? detected", "malware detected", "malware found", "infected files?",
            "virus(?:es)? detected", "detections",
        ))
        findings = [
            candidate.get("Event", "") for candidate in positive_rows
            if target_key(candidate) == target_key(row)
        ]
        threats = explicit_count if explicit_count is not None else len(findings)
        warnings = []
        status = "Completed with detections" if threats > 0 else "Completed clean"
        runs.append(_base_run(
            source_id, "trend_micro", len(runs), endpoint=endpoint or "Unknown",
            scan_type=_description_field(description, "Scan Type") or "Manual Malware Scan",
            scan_completion_time=completed, scan_duration_seconds=duration,
            normalized_status=status, original_status=row.get("Event"), files_scanned=files_scanned,
            threats_detected=threats, threat_names=findings, warnings=warnings,
            source_event_id=row.get("Event ID") or _description_field(description, "Event ID"),
            source_level=row.get("Level") or _description_field(description, "Level"),
            source_event_origin=row.get("Event Origin"),
            description_summary=" ".join(description.split())[:1000],
            result_basis=(
                "explicit_detection_count"
                if explicit_count is not None
                else "trend_csv_detection_events" if findings
                else "trend_csv_no_detection_events"
            ),
        ))
    return runs


def _parse_symantec(text: str, source_id: str, file_mtime: float) -> list[dict]:
    if not re.search(r"symantec|endpoint protection", text, re.IGNORECASE):
        return []
    threats = _labelled_int(text, ("total risks? detected", "risks? found", "infected files?"))
    if threats is None:
        return []
    dates = list(DATE_RE.finditer(text))
    completed = _iso(dates[-1].group(0)) if dates else datetime.fromtimestamp(file_mtime).isoformat(sep=" ")
    definition = re.search(r"(?:virus definitions?|definitions?)\s*[:=]\s*([0-9./-]+)", text, re.IGNORECASE)
    return [_base_run(
        source_id, "symantec", 0, scan_completion_time=completed,
        timestamp_source="log_content" if dates else "file_mtime_fallback", scan_type="Symantec scan",
        normalized_status="Completed with detections" if threats > 0 else "Completed clean",
        threats_detected=threats, definition_version=definition.group(1) if definition else None,
        warnings=[] if dates else ["File modification time was used because no scan timestamp was present."],
    )]


def _parse_evidence_month(evidence_month: str) -> Optional[tuple[int, int]]:
    """Parse 'May 2026' into (2026, 5).  Returns None if unparseable."""
    year = 0
    month_num = 0
    for token in re.findall(r"[A-Za-z]+|\d{4}", evidence_month):
        low = token.lower()
        if low in MONTH_ORDER:
            month_num = MONTH_ORDER[low]
        elif token.isdigit() and len(token) == 4:
            year = int(token)
    return (year, month_num) if year and month_num else None


def _filter_runs_to_month(
    runs: list[dict], evidence_month: str,
) -> tuple[list[dict], list[str]]:
    """Keep only scan runs whose completion date falls within *evidence_month*.

    If every run would be dropped the full list is returned with a warning so
    the dashboard never silently hides all evidence.
    """
    parsed = _parse_evidence_month(evidence_month)
    if not parsed:
        return runs, []
    target_year, target_month = parsed

    def _matches(run: dict) -> bool:
        ts = run.get("scan_completion_time") or run.get("scan_start_time") or ""
        if not ts:
            return True          # keep runs without a timestamp
        try:
            dt = datetime.fromisoformat(ts)
            return dt.year == target_year and dt.month == target_month
        except (ValueError, TypeError):
            return True          # keep unparseable dates

    filtered = [r for r in runs if _matches(r)]
    warnings: list[str] = []
    if not filtered and runs:
        warnings.append(
            f"None of the {len(runs)} parsed scan run(s) fell within "
            f"{evidence_month}; showing all runs."
        )
        return runs, warnings

    dropped = len(runs) - len(filtered)
    if dropped:
        warnings.append(
            f"{dropped} scan run(s) outside {evidence_month} were excluded."
        )
    return filtered, warnings


def _extract_pdf(path: Path, ocr_provider: Optional[Callable]) -> tuple[str, str, list[str]]:
    reader = pypdf.PdfReader(str(path))
    if len(reader.pages) > MAX_STRUCTURED_PDF_PAGES:
        raise ValueError(f"PDF exceeds the {MAX_STRUCTURED_PDF_PAGES}-page processing limit.")
    texts: list[str] = []
    warnings: list[str] = []
    used_ocr = False
    for page_number, page in enumerate(reader.pages, 1):
        native = page.extract_text() or ""
        if len(native.strip()) >= MIN_NATIVE_PAGE_TEXT:
            texts.append(native)
            continue
        if ocr_provider is None:
            warnings.append(f"PDF page {page_number} has insufficient native text and was not OCR-scanned.")
            continue
        images = list(page.images)
        if not images:
            warnings.append(f"PDF page {page_number} has no extractable text or embedded image.")
            continue
        largest = max(images, key=lambda image: image.image.width * image.image.height)
        with tempfile.TemporaryDirectory(prefix="security-center-pdf-") as temp_dir:
            image_path = Path(temp_dir) / f"page-{page_number}.png"
            largest.image.convert("RGB").save(image_path, format="PNG")
            results = ocr_provider(image_path, persist=False)
        texts.append("\n".join(str(item[1]) for item in results if len(item) >= 2))
        used_ocr = True
    return "\n".join(texts), "pdf_mixed" if used_ocr else "pdf_native_text", warnings


def analyze_structured_file(
    path: Path,
    evidence_month: str = "",
    *,
    ocr_provider: Optional[Callable] = None,
) -> dict:
    started = time.perf_counter()
    source_id = sha256_file(path)
    mime = validate_file_content(path)
    warnings: list[str] = []
    csv_rows: list[dict] = []
    csv_headers: list[str] = []
    extension = path.suffix.lower()
    if extension == ".pdf":
        text, extraction_method, extraction_warnings = _extract_pdf(path, ocr_provider)
        warnings.extend(extraction_warnings)
    elif extension in {".png", ".jpg", ".jpeg"}:
        if ocr_provider is None:
            text, extraction_method = "", "ocr_pending"
            warnings.append("PNG OCR has not been requested.")
        else:
            results = ocr_provider(path, persist=True)
            text = "\n".join(str(item[1]) for item in results if len(item) >= 2)
            extraction_method = "ocr"
    else:
        text, encoding, decode_warnings = decode_text(path.read_bytes())
        warnings.extend(decode_warnings)
        extraction_method = "csv" if extension == ".csv" else f"text:{encoding}"
        if extension == ".csv":
            csv_rows, csv_headers, delimiter = _csv_rows(text)
            if not csv_headers:
                warnings.append("CSV has no header row.")
            extraction_method = f"csv:{repr(delimiter)}"
    classification = classify_vendor(text, csv_headers=csv_headers)
    vendor = classification["vendor"]
    document_role = "unknown"
    if vendor == "trellix_mcafee":
        epo_runs = _parse_epo_report(text, source_id)
        if epo_runs:
            document_role = "epo_dat_report"
            runs = epo_runs
        else:
            threat_report_runs = _parse_epo_threat_report(text, source_id) if extension == ".pdf" else []
            runs = threat_report_runs or _parse_mcafee_activity(text, source_id)
            document_role = "epo_threat_report" if threat_report_runs or (
                extension == ".pdf" and re.search(
                    r"\b(?:threat (?:events?|detection|name|report)|detected threats?|infected systems?)\b",
                    text, re.IGNORECASE,
                )
            ) else "mcafee_scan_log"
    elif vendor == "trend_micro":
        document_role = "trend_system_events"
        runs = _parse_trend_csv(csv_rows, source_id) if csv_rows else []
    elif vendor == "clamwin":
        document_role = "clamwin_scan_log"
        runs = _parse_clamwin(text, source_id, path.stat().st_mtime)
    elif vendor == "symantec":
        document_role = "symantec_scan_log"
        runs = _parse_symantec(text, source_id, path.stat().st_mtime)
    elif vendor == "generic_antivirus":
        document_role = "generic_scan_csv"
        runs = _parse_generic_scan_csv(csv_rows, source_id) if csv_rows else []
    else:
        runs = []
    if extension == ".pdf" and document_role == "unknown" and re.search(
        r"\b(?:threat|detect(?:ion|ed)?|virus|malware)\b", path.stem, re.IGNORECASE,
    ):
        document_role = "epo_threat_report"
    # Filter runs to the evidence month when a month context is available.
    if evidence_month and runs:
        runs, month_warnings = _filter_runs_to_month(runs, evidence_month)
        warnings.extend(month_warnings)
    if not runs:
        warnings.append("No supported completed scan run could be parsed from this file.")
    for run in runs:
        run["extraction_method"] = extraction_method
        run["raw_evidence"] = path.name
        run["import_timestamp"] = datetime.now(timezone.utc).isoformat()
        run["warnings"] = list(dict.fromkeys(run.get("warnings", []) + warnings))
    return {
        "source_file_id": source_id,
        "filename": path.name,
        "size_bytes": path.stat().st_size,
        "mime_type": mime,
        "extraction_method": extraction_method,
        "classification": classification,
        "document_role": document_role,
        "processing_status": (
            "Completed"
            if runs
            and not classification["requires_review"]
            and all(run.get("normalized_status") != "Requires review" for run in runs)
            else "Requires review"
        ),
        "warnings": list(dict.fromkeys(warnings)),
        "scan_runs": runs,
        "parser_version": PARSER_VERSION,
        "timing_ms": round((time.perf_counter() - started) * 1000, 3),
    }


def legacy_result(result: dict) -> Optional[tuple[str, str, str, dict]]:
    """Map normalized runs into the existing dashboard fields without hiding uncertainty."""
    runs = result.get("scan_runs") or []
    if not runs:
        return None
    latest = max(runs, key=lambda run: run.get("scan_completion_time") or run.get("scan_start_time") or "")
    positive = any((run.get("threats_detected") or 0) > 0 for run in runs)
    explicit_zero = any(run.get("threats_detected") == 0 for run in runs)
    unresolved = any(run.get("threats_detected") is None for run in runs)
    status = "Threats Found" if positive else "Clean" if explicit_zero and not unresolved else "Manual Verification Needed"
    reasons = list(dict.fromkeys(
        warning for run in runs for warning in run.get("warnings", [])
        if run.get("threats_detected") is None or run.get("normalized_status") == "Requires review"
    ))
    details = {
        "verification_reasons": reasons,
        "structured": result,
        "parse_failed": False,
    }
    return (
        status,
        latest.get("definition_version") or "Unknown",
        latest.get("scan_completion_time") or latest.get("scan_start_time") or "Unknown",
        details,
    )
