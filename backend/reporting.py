"""Deterministic, printable monthly security report generation."""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape


REPORT_SCHEMA_VERSION = "1.0"


def _cell(value):
    return escape(str(value if value not in (None, "") else "Not available"))


def _table(headers, rows):
    if not rows:
        return '<p class="empty">No entries.</p>'
    head = "".join(f"<th>{_cell(header)}</th>" for header in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{_cell(value)}</td>" for value in row) + "</tr>"
        for row in rows
    )
    return f"<div class=\"table-wrap\"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"


def build_monthly_report(payload: dict, thresholds: dict, *, application_version: str):
    """Build standalone HTML from the same payload used by the dashboard."""
    generated_at = datetime.now(timezone.utc).isoformat()
    month = str(payload.get("month", ""))
    coverage = payload.get("coverage", {}) if isinstance(payload.get("coverage"), dict) else {}
    checklist = payload.get("checklist", {}) if isinstance(payload.get("checklist"), dict) else {}
    logs = [
        log
        for system_logs in (payload.get("logs", {}) or {}).values()
        for log in (system_logs if isinstance(system_logs, list) else [])
    ]
    findings = [log for log in logs if log.get("scan_status") == "finding_detected"]
    reviews = [log for log in logs if log.get("scan_status") in {"needs_review", "scan_failed"}]
    missing = payload.get("missing", []) if isinstance(payload.get("missing"), list) else []
    reconciliation = payload.get("reconciliation", []) if isinstance(payload.get("reconciliation"), list) else []

    summary_fields = [
        ("Evidence files", coverage.get("evidence_files", 0)),
        ("Checklist expected", coverage.get("expected_evidence", 0)),
        ("Confirmed coverage", coverage.get("confirmed_evidence", 0)),
        ("Missing", coverage.get("missing_evidence", 0)),
        ("Coverage unknown", coverage.get("unknown_coverage", 0)),
        ("Findings", coverage.get("finding_files", 0)),
        ("Needs review", coverage.get("review_files", 0)),
        ("Scan failures", coverage.get("failed_files", 0)),
        ("Not OCR-scanned", coverage.get("not_scanned_files", 0)),
    ]
    cards = "".join(
        f'<div class="card"><span>{_cell(label)}</span><strong>{_cell(value)}</strong></div>'
        for label, value in summary_fields
    )
    threshold_rows = [
        (engine.title(), value) for engine, value in sorted(thresholds.items())
        if engine != "zero_threat_confidence"
    ]
    zero_confidence = float(thresholds.get("zero_threat_confidence", 0.90))
    finding_rows = [
        (
            log.get("system"), log.get("filename"), log.get("status"),
            log.get("dat_version"), log.get("last_scan"), log.get("path"),
        )
        for log in findings
    ]
    review_rows = [
        (
            log.get("system"), log.get("filename"), log.get("scan_status"),
            "; ".join(log.get("verification_reasons", []) or []), log.get("path"),
        )
        for log in reviews
    ]
    missing_rows = [
        (item.get("system"), item.get("subsystem"), item.get("expected"), item.get("found"), item.get("missing"))
        for item in missing
    ]
    reconciliation_rows = [
        (
            item.get("type"), item.get("system"), item.get("subsystem", item.get("path", "")),
            item.get("expected", ""), item.get("found", ""), item.get("unresolved", ""), item.get("reason", ""),
        )
        for item in reconciliation
    ]
    limitations = []
    if not checklist.get("valid"):
        limitations.append(f"Checklist unavailable or invalid: {checklist.get('error', 'unknown error')}")
    if coverage.get("unknown_coverage"):
        limitations.append("Consolidated evidence could not be mapped to every expected endpoint.")
    if coverage.get("not_scanned_files"):
        limitations.append("Some image evidence has not completed OCR; this report is not a complete detection review.")
    if coverage.get("failed_files"):
        limitations.append("One or more evidence files failed safe parsing and require manual review.")
    if not limitations:
        limitations.append("No automated parser can replace review of original evidence and endpoint security tooling.")
    limitation_items = "".join(f"<li>{_cell(value)}</li>" for value in limitations)

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Center - {_cell(month)} report</title>
<style>
:root{{--ink:#17171b;--muted:#62626b;--line:#dedee5;--accent:#6d28d9;--warn:#b45309;--danger:#be123c}}
*{{box-sizing:border-box}}body{{font:14px/1.45 Arial,sans-serif;color:var(--ink);margin:0;background:#f6f6f8}}
main{{max-width:1120px;margin:24px auto;background:white;padding:36px;border:1px solid var(--line);border-radius:16px}}
h1{{margin:0;font-size:28px}}h2{{font-size:17px;margin:30px 0 10px}}p.meta,.empty{{color:var(--muted)}}
.badge{{display:inline-block;margin-top:10px;padding:5px 9px;border-radius:999px;background:#f3e8ff;color:var(--accent);font-weight:700}}
.summary{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:22px 0}}.card{{border:1px solid var(--line);border-radius:10px;padding:12px}}
.card span{{display:block;color:var(--muted);font-size:11px;text-transform:uppercase}}.card strong{{display:block;font-size:22px;margin-top:4px}}
.notice{{border-left:4px solid var(--warn);background:#fffbeb;padding:12px 16px}}.table-wrap{{overflow:auto}}
table{{width:100%;border-collapse:collapse;font-size:12px}}th,td{{border-bottom:1px solid var(--line);padding:8px;text-align:left;vertical-align:top}}th{{background:#f7f7f9}}
footer{{margin-top:32px;padding-top:12px;border-top:1px solid var(--line);color:var(--muted);font-size:11px}}
@media print{{body{{background:white}}main{{margin:0;max-width:none;border:0;padding:16px}}.summary{{grid-template-columns:repeat(3,1fr)}}h2{{break-after:avoid}}tr{{break-inside:avoid}}}}
</style></head><body><main>
<h1>Monthly Security Evidence Report</h1>
<p class="meta">Evidence month: <strong>{_cell(month)}</strong><br>Generated UTC: {_cell(generated_at)}<br>Application: {_cell(application_version)} | Report schema: {_cell(REPORT_SCHEMA_VERSION)}<br>Checklist: {_cell(checklist.get('source') or payload.get('checklist_source'))}</p>
<span class="badge">{'Coverage complete' if coverage.get('complete') else 'Coverage incomplete - review required'}</span>
<div class="summary">{cards}</div>
<div class="notice"><strong>Scope and limitations</strong><ul>{limitation_items}</ul></div>
<h2>Configured signature thresholds</h2>{_table(['Engine','Minimum version'], threshold_rows)}
<p class="meta">Explicit zero-threat OCR confidence: <strong>{zero_confidence:.0%}</strong>. Positive-threat confidence remains fixed at 90%.</p>
<h2>Detected findings</h2>{_table(['System','Evidence','Verdict','DAT','Scan date','Trace path'], finding_rows)}
<h2>Manual review and parser failures</h2>{_table(['System','Evidence','State','Reason','Trace path'], review_rows)}
<h2>Missing evidence</h2>{_table(['System','Location','Expected','Found','Missing'], missing_rows)}
<h2>Unresolved reconciliation</h2>{_table(['Type','System','Location or path','Expected','Found','Unresolved','Reason'], reconciliation_rows)}
<footer>This report is generated from the local evidence inventory and checklist at request time. Retain the original evidence and audit trail as the source of record.</footer>
</main></body></html>"""
