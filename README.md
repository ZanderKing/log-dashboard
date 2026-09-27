# Security Center Dashboard

Local antivirus evidence and compliance dashboard. It reads monthly log files from a `2026/` folder, extracts scan info from text/PDF evidence, runs OCR on screenshots when an operator clicks **Scan**, and compares findings against an Excel checklist.

## Quick Start

```bash
cd backend && pip install -r requirements.txt
cd ../frontend && npm ci && cd ..
python start.py
```

Open `http://127.0.0.1:8000`. Both services bind to loopback only. OCR is manual — no background watcher.

**Requirements:** Python 3.11 or 3.12, Node.js/npm.

## Architecture

- **Frontend:** Next.js/React with static export (`output: "export"`). Production never runs Node.js.
- **Backend:** FastAPI on Python. Serves both `/api` routes and the static UI at `/`.
- **Data:** `2026/` directory adjacent to the backend — each subfolder is a selectable month.

The FastAPI UI mount (`app.mount("/", StaticFiles(...))`) must be the **last line** in `main.py` so it never shadows `/api` routes.

## Project Map

| File | Purpose |
|------|---------|
| `backend/main.py` | FastAPI entry point — CORS, security middleware, all API routes, UI mount |
| `backend/log_service.py` | Month discovery, file analysis, checklist matching, coverage calculations, logs/missing payload |
| `backend/log_support.py` | Path traversal protection, safe file reading, PDF system extraction, coverage helpers |
| `backend/ocr_analysis.py` | Conservative OCR interpretation — spatial row reconstruction, DAT/threat/date extraction, confidence gates |
| `backend/ocr_runtime.py` | EasyOCR loader with RAM-aware worker policy (1 worker <12GB, 2 workers ≥12GB) |
| `backend/ocr_cache_store.py` | Content-addressed OCR cache (SHA-256), duplicate inference suppression |
| `backend/checklist.py` | Excel parsing, system tree, one-to-one checklist matching |
| `backend/vendor_ingestion.py` | Structured file parsers — ePO, McAfee, ClamWin, Symantec, Trend Micro, CSV |
| `backend/ai_vision.py` | Optional local Qwen3-VL 2B fallback via llama.cpp subprocess |
| `backend/settings_store.py` | Threshold/verification persistence with content-bound verdicts |
| `backend/scan_state.py` | Thread-safe scan progress, single-job gating, cooperative cancellation |
| `backend/audit_store.py` | Append-only JSONL audit trail |
| `backend/reporting.py` | Monthly HTML report generator |
| `backend/runtime_config.py` | .env file loader (never overrides process vars) |
| `backend/models.py` | Pydantic request/response models |
| `backend/storage.py` | Atomic JSON writes (tmp + fsync + replace) |
| `frontend/src/app/page.tsx` | Single-page dashboard — Home/Logs/Settings tabs, Chart.js, image viewer, verification workflow |

## Models and Runtime

Large OCR weights and the optional local LLM runtime are **not** committed. On first run `start.py` downloads the EasyOCR models automatically. To use the optional AI fallback, drop a llama.cpp `llama-server` binary and a Qwen3-VL GGUF model into `runtime/` and `models/` (or point the `SECURITY_CENTER_AI_*` variables at them).

```text
backend/easyocr_models/   # EasyOCR weights (auto-downloaded)
runtime/                  # llama.cpp binaries (optional)
models/                   # GGUF model weights (optional)
```

## Antivirus Parsing Rules (Default Mappings)

- **RADIO** → ClamWin only
- **CCTV, EPM, INFO** → McAfee only
- **Other systems** → keyword guessing (McAfee, Trellix, Symantec, ClamWin)

Adjust these mappings to match your own antivirus deployment.

## State Files (Back Up Before Upgrades)

| File | What it holds |
|------|---------------|
| `backend/thresholds.json` | Minimum AV version thresholds per engine |
| `backend/verifications.json` | Operator safe/unsafe verdicts (bound to file content SHA-256) |
| `backend/ocr_cache.json` | OCR results keyed by file identity and content hash |
| `backend/audit.jsonl` | Append-only audit trail |

All writes are atomic (tmp file → fsync → os.replace).

## Status Rules

- **Clean** — no positive detection, no blocking mismatch
- **Threats Found** — positive detection count or operator "unsafe" verdict
- **Manual Verification Needed** — ambiguous OCR, checklist mismatch, outdated signature, parser failure
- **Not Scanned** — image has no OCR yet

Manual safe/unsafe verdicts override the automated status. Content-bound verdicts expire when the file bytes change.

## Monthly Workflow

1. Copy the new month folder + checklist into `2026/`
2. Open dashboard, select the month
3. Review **Missing Files** alerts (based on physical evidence, not OCR)
4. Click **Scan all** — OCR is CPU intensive, works on demand only
5. Review Threats Found first, then Needs Verification, then outdated signatures
6. Open the actual evidence before marking **Safe** or **Unsafe**
7. Export the monthly HTML report, archive with audit log snapshot

**Unknown never means clean.** Consolidated EPM/CCTV reports cannot prove per-endpoint coverage.

## Scan Controls

- **Scan all** — processes the selected month's supported files
- **Stop scan** — cooperative cancel (waits for current OCR to finish, saves that cache entry)
- **Scan file** — scans a single validated file

Only one scan job runs at a time. Stop never alters manual verdicts.

## Settings

Thresholds are editable in the Settings page, persisted in `thresholds.json`:
- **McAfee** (default 6127), **ClamWin** (default 1), **Trellix** (default 1), **Symantec** (default 1)
- **Zero-threat OCR confidence** (0.50–0.99, default 0.90) — controls acceptance of explicit zero results
- **OCR strictness** — high/medium/low, affects confidence thresholds for DAT and threat extraction

Lowering zero-threat confidence reduces manual review but increases false-clean risk.

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `SECURITY_CENTER_HOST` | `127.0.0.1` | Server bind address |
| `SECURITY_CENTER_PORT` | `8000` | Server port |
| `SECURITY_CENTER_LOG_LEVEL` | `INFO` | Logging verbosity |
| `SECURITY_CENTER_ALLOWED_ORIGINS` | `127.0.0.1:3000, localhost:8000` | Additional CORS origins (comma-separated) |
| `SECURITY_CENTER_OCR_WORKERS` | auto (1-2) | OCR worker count override |
| `SECURITY_CENTER_TORCH_THREADS` | auto (1-8) | PyTorch thread count |
| `SECURITY_CENTER_OCR_MODEL_DIR` | `backend/easyocr_models` | Custom EasyOCR model path |
| `SECURITY_CENTER_AI_PORT` | `8091` | llama.cpp server port |
| `SECURITY_CENTER_AI_RUNTIME` | — | Path to llama-server binary |
| `SECURITY_CENTER_AI_MODEL` | — | Path to Qwen GGUF model |
| `SECURITY_CENTER_AI_MMPROJ` | — | Path to mmproj GGUF file |
| `SECURITY_CENTER_AI_THREADS` | auto | AI inference thread count |

Source loads `.env` from the project root then `backend/.env`. Process environment variables always take precedence.

## Security

- Default listener is loopback only. No authentication or RBAC.
- Do not expose to the internet. LAN access requires firewall rules and an authenticated reverse proxy.
- All API responses include CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy headers.
- Cross-origin state changes rejected with 403.
- `/api/` responses use `Cache-Control: no-store`.
- File serving enforces path containment within `DATA_DIR`, rejects traversal and hidden files.
- Audit records are integrity evidence, not tamper-proof — forward to managed storage if required.

## Known Limitations

- OCR is probabilistic — ambiguous results require human review
- 14 DOCX files are retained but not parsed
- EPM/CCTV consolidated reports cannot establish per-endpoint coverage
- Scan cancellation is cooperative (waits for active OCR to finish)
- No authentication or RBAC; loopback is the safe default
- Local audit files are not tamper-proof
- OCR peak ~3.47 GB RAM (single image measurement); validate on the actual target machine
- Legacy path-only verification entries are ignored for safety

## Verification

```bash
cd frontend && npm run check
python -m py_compile backend/main.py start.py
```
