"use client";

import { useEffect, useRef, useState } from "react";
import { Doughnut } from "react-chartjs-2";
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
  Title,
} from "chart.js";

ChartJS.register(ArcElement, Tooltip, Legend, Title);

// ----- Types ------
// Every interface here mirrors what the FastAPI backend returns. Keep these
// in sync with backend/models.py and the JSON shapes in the API routes.
interface LogFile {
  system: string;
  filename: string;
  status: string;
  path: string;
  type: string;
  dat_version: string;
  last_scan: string;
  dat_version_candidate?: string;
  last_scan_candidate?: string;
  verification_reasons?: string[];
  date_evidence_count?: number;
  is_outdated: boolean;
  verification?: "safe" | "unsafe" | null;
  scan_status?: "healthy" | "verified_safe" | "finding_detected" | "needs_review" | "not_scanned" | "scan_failed";
  month?: string;
  pdf_systems?: PdfSystem[];
  checklist_remarks?: string;
  checklist_dat_version?: string;
  checklist_date_scan?: string;
  checklist_virus_found?: string;
  checklist_av_software?: string;
  checklist_match?: string;
  checklist_mismatches?: string[];
  ai_fallback?: {
    used: boolean;
    model?: string;
    prompt_version?: string;
    elapsed_ms?: number;
    agreements: string[];
    conflicts: string[];
    threat_count: number | null;
    threat_evidence?: string;
  } | null;
}

interface LogsData {
  [system: string]: LogFile[];
}

interface PdfSystem {
  name: string;
  dat_version: string;
  last_scan: string;
}

interface MissingAlert {
  system: string;
  subsystem: string;
  expected: number;
  found: number;
  missing: number;
  month?: string;
}

interface SystemTreeLocation {
  extra?: number;
  coverage_status?: "present" | "partial" | "missing" | "unknown";
  unresolved_count?: number;
  name: string;
  expected: number;
  antivirus: string;
  found?: number;
  missing?: number;
}

interface SystemTreeSystem {
  system: string;
  locations: SystemTreeLocation[];
}

interface ScanProgress {
  active: boolean;
  job_id?: string;
  outcome?: "running" | "completed" | "completed_with_errors" | "stopped";
  month: string;
  total: number;
  completed: number;
  current_file: string;
  percent: number;
  succeeded?: number;
  failed?: number;
  failed_files?: string[];
  cancel_requested?: boolean;
  stopped?: boolean;
  cache_hits?: number;
  content_cache_hits?: number;
  fast_passes?: number;
  full_quality_passes?: number;
  full_quality_fallbacks?: number;
}

interface CoverageSummary {
  complete: boolean;
  expected_evidence: number;
  confirmed_evidence: number;
  missing_evidence: number;
  unknown_coverage: number;
  evidence_files: number;
  matched_files: number;
  unmatched_files: number;
  ambiguous_files?: number;
  not_scanned_files: number;
  failed_files: number;
  review_files: number;
  finding_files: number;
}

interface LogsResponse {
  logs: LogsData;
  missing: MissingAlert[];
  system_tree: SystemTreeSystem[];
  checklist_source?: string;
  coverage?: CoverageSummary;
  checklist?: { valid: boolean; source: string; error: string };
  reconciliation?: Array<Record<string, unknown>>;
  errors?: string[];
}

type Tab = "home" | "logs" | "settings";
type ThemeKey = "purple" | "indigo" | "blue";
type LogTypeFilter = "all" | "images" | "text" | "pdf";

interface ViewingImage { url: string; name: string; retry: number; log: LogFile; }
type StatusFilter = "all" | "clean" | "verification" | "threats" | "not-scanned";
type SignatureThresholdKey = "mcafee" | "clamwin" | "trellix" | "symantec";
type ThresholdKey = SignatureThresholdKey | "zero_threat_confidence" | "ocr_strictness";
type ThresholdValues = Record<SignatureThresholdKey | "zero_threat_confidence", number> & { ocr_strictness?: string };
type AIFallbackMode = "off" | "review_only";
interface AISettings { mode: AIFallbackMode; max_image_dimension: number; timeout_seconds: number; }
interface AIStatus { available: boolean; running: boolean; last_error: string; }
interface AISettingsResponse { settings: AISettings; status: AIStatus; }

// Dynamic host resolution — never hardcode IPs. Resolves to the host the
// dashboard is being viewed from (localhost, LAN IP, mobile hotspot, etc.).
const API_PORT = 8000;
// When running as `npm run dev`, Next.js is on port 3000 and FastAPI is on 8000
// — so we need to rewrite the origin. In production, both are served from the
// same FastAPI process, so the current page origin is the right API base.
const getApiBase = () => {
  if (typeof window === "undefined") return "";
  const { protocol, hostname, port, origin } = window.location;
  // FastAPI serves the static export in production. Only Next.js development
  // uses a separate port, which keeps HTTPS/reverse-proxy deployments same-origin.
  if (port === "3000") return `${protocol}//${hostname || "127.0.0.1"}:${API_PORT}`;
  return origin;
};

// Centralized request handling prevents indefinite spinners and consistently
// surfaces backend validation errors to callers.
// Every API call goes through this wrapper. It handles timeouts (default 60s,
// 2h for full scans), AbortController integration for cancellation, and surfaces
// backend validation errors from the "detail" field in FastAPI error responses.
const fetchJson = async <T,>(path: string, init: RequestInit = {}, timeoutMs = 60_000, callerSignal?: AbortSignal): Promise<T> => {
  const controller = new AbortController();
  const timeoutId = window.setTimeout(() => controller.abort(), timeoutMs);
  const abortFromCaller = () => controller.abort();
  callerSignal?.addEventListener("abort", abortFromCaller, { once: true });
  try {
    const response = await fetch(`${getApiBase()}${path}`, {
      ...init,
      cache: "no-store",
      signal: controller.signal,
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(typeof data?.detail === "string" ? data.detail : `Request failed (${response.status})`);
    }
    return data as T;
  } finally {
    window.clearTimeout(timeoutId);
    callerSignal?.removeEventListener("abort", abortFromCaller);
  }
};
const themes = {
  purple: { hex: "#5D1E79", name: "Corporate Purple" },
  indigo: { hex: "#4F46E5", name: "Indigo" },
  blue: { hex: "#2563EB", name: "Ocean Blue" }
};

const Icons = {
  Dashboard: () => <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" className="w-[18px] h-[18px]"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" /></svg>,
  Logs: () => <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" className="w-[18px] h-[18px]"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>,
  Settings: () => <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" className="w-[18px] h-[18px]"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>,
  Search: () => <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" className="w-4 h-4"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>,
  Spinner: () => <svg className="animate-spin h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
};

const Home = () => {
  const [activeTab, setActiveTab] = useState<Tab>("home");
  // Deterministic initial values match the static HTML. Stored browser
  // preferences are applied after hydration below.
  const [theme, setTheme] = useState<ThemeKey>("purple");
  const [darkMode, setDarkMode] = useState<boolean>(false);
  const [preferencesLoaded, setPreferencesLoaded] = useState(false);
  const [thresholdInputs, setThresholdInputs] = useState<Record<ThresholdKey, string>>({
    mcafee: "6127",
    clamwin: "1",
    trellix: "1",
    zero_threat_confidence: "0.90",
    symantec: "1",
    ocr_strictness: "high",
  });
  const [thresholdSaveStatus, setThresholdSaveStatus] = useState<string>("");
  const [aiSettings, setAiSettings] = useState<AISettings>({ mode: "off", max_image_dimension: 1600, timeout_seconds: 120 });
  const [aiStatus, setAiStatus] = useState<AIStatus | null>(null);
  const [aiSaveStatus, setAiSaveStatus] = useState<string>("");
  const [aiTesting, setAiTesting] = useState(false);

  const [logs, setLogs] = useState<LogsData>({});
  const [missing, setMissing] = useState<MissingAlert[]>([]);
  const [systemTree, setSystemTree] = useState<SystemTreeSystem[]>([]);
  const [coverage, setCoverage] = useState<CoverageSummary | null>(null);
  const [logsError, setLogsError] = useState<string>("");
  const [months, setMonths] = useState<string[]>([]);
  const [selectedMonth, setSelectedMonth] = useState<string>("");
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [isAiScanning, setIsAiScanning] = useState<boolean>(false);
  const [isStoppingScan, setIsStoppingScan] = useState<boolean>(false);
  const [scanningFilePath, setScanningFilePath] = useState<string | null>(null);
  const [scanProgressState, setScanProgressState] = useState<ScanProgress | null>(null);
  const [statusMessage, setStatusMessage] = useState<string>("");
  const [selectedLog, setSelectedLog] = useState<LogFile | null>(null);
  const [logSummary, setLogSummary] = useState<string>("");
  const [viewingImage, setViewingImage] = useState<ViewingImage | null>(null);
  const [imageLoadState, setImageLoadState] = useState<"loading" | "loaded" | "error">("loading");
  const [verificationPending, setVerificationPending] = useState<string | null>(null);
  const [logTypeFilter, setLogTypeFilter] = useState<LogTypeFilter>("all");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [systemFilter, setSystemFilter] = useState<string>("all");
  const [selectedPdfSystems, setSelectedPdfSystems] = useState<Record<string, string>>({});
  const [expandedSystems, setExpandedSystems] = useState<Record<string, boolean>>({});
  const [showMissingDetails, setShowMissingDetails] = useState<boolean>(false);
  const logsRequestGeneration = useRef(0);
  const logsAbortController = useRef<AbortController | null>(null);
  const selectedMonthRef = useRef("");
  const lastFinishedJob = useRef("");
  const lastCompletedCount = useRef(-1);

  const activeColor = themes[theme].hex;
  const isDarkTheme = darkMode;

  const t = {
    secCenter: "Logs Dashboard", dashboard: "Dashboard", logDir: "Log Directory", settings: "Settings",
    overview: "Overview", sysLogs: "System Logs", sysSettings: "Settings",
    status: "Status", online: "Online", totalFiles: "Total Files", threatsFound: "Threats Found",
    needsVerification: "Needs Review", cleanFiles: "Clean Files", notScanned: "Not Scanned",
    outdatedSigs: "Outdated Antivirus Versions",
    overallStatus: "Overall Security Status", threatsBySystem: "Threats by System", allSysLogs: "Logs",
    runScan: "Scan", scanning: "Scanning", system: "System", filename: "Filename",
    type: "Type", audit: "Details", viewLog: "View", appPrefs: "Application Preferences",
    datVersion: "Antivirus Version", lastScan: "Last Scan Date", remarks: "Remarks", month: "Month",
    markSafe: "Verified", markUnsafe: "Dangerous", verifiedSafe: "Approved as Verified", verifiedUnsafe: "Flagged as Dangerous",
    themeLabel: "Color Theme", themeDesc: "Customize the visual appearance of the application.",
    darkModeLabel: "Dark Mode", darkModeDesc: "Switch between light and dark surfaces.",
    thresholdsLabel: "Required Antivirus Versions",
    thresholdsDesc: "Antivirus versions below these numbers will be marked as outdated.",
    auditReport: "File Details & Review", closeWindow: "Close", noLogs: "No log files detected in the directory.",
    loading: "Loading log files", fetchError: "Error loading logs. Please ensure the backend server is running.",
    complianceAlerts: "Missing Log Files", systemTree: "System Checklist & Status", expectedLabel: "Expected",
    foundLabel: "Found", missingLabel: "Missing", allPresent: "All expected files are present."
  };
  const scanText = {
    scanAll: "Scan all", scanFile: "Scan file", stopScan: "Stop scan",
    stopping: "Stopping scan", stopRequested: "Stop requested. Finishing active OCR safely",
    scanComplete: "File scan complete.",
  };

  const pageBgClass = isDarkTheme ? "bg-[#0A0A0C] text-slate-100" : "bg-white text-zinc-900";
  const surfaceClass = isDarkTheme ? "bg-[#111114] border-white/[0.06]" : "bg-white border-zinc-200/70";
  const mutedTextClass = isDarkTheme ? "text-slate-400" : "text-zinc-500";
  const headingClass = isDarkTheme ? "text-slate-100" : "text-zinc-900";
  const inputClass = isDarkTheme
    ? "bg-white/[0.04] border-white/[0.08] text-slate-100 placeholder:text-slate-500"
    : "bg-white border-zinc-200 text-zinc-800";
  const dividerClass = isDarkTheme ? "border-white/[0.06]" : "border-zinc-100";
  const imageTypes = new Set(["JPG", "JPEG", "PNG", "BMP", "GIF"]);
  const textTypes = new Set(["TXT", "LOG", "CSV"]);

  // Derived values are calculated before request callbacks so React always
  // closes over the current snapshot and the render stays side-effect free.
  const allLogRows = Object.values(logs).flatMap((systemLogs) => Array.isArray(systemLogs) ? systemLogs : []);
  const logCounts = allLogRows.reduce((counts, log) => ({
    totalLogs: counts.totalLogs + 1,
    cleanCount: counts.cleanCount + Number(log.status === "Clean"),
    threatsCount: counts.threatsCount + Number(log.status === "Threats Found"),
    manualCount: counts.manualCount + Number(log.status === "Manual Verification Needed"),
    notScannedCount: counts.notScannedCount + Number(log.status === "Not Scanned"),
    outdatedCount: counts.outdatedCount + Number(log.is_outdated),
  }), {
    totalLogs: 0,
    cleanCount: 0,
    threatsCount: 0,
    manualCount: 0,
    notScannedCount: 0,
    outdatedCount: 0,
  });
  const { totalLogs, cleanCount, threatsCount, manualCount, notScannedCount, outdatedCount } = logCounts;

  // Central log loader — used for both inventory (GET /api/logs) and full OCR
  // scans (POST /api/logs/scan-all). Generation-based deduplication prevents
  // stale responses from overwriting fresh data when the user changes months
  // rapidly or a scan completes while a poll is in flight.
  const fetchLogs = (scanImages: boolean = false, month: string = selectedMonth, showLoading: boolean = true) => {
    const requestedMonth = month;
    if (scanImages && !requestedMonth) {
      setLogsError("Select an evidence month before starting OCR.");
      return;
    }
    const requestGeneration = ++logsRequestGeneration.current;
    logsAbortController.current?.abort();
    const requestController = new AbortController();
    logsAbortController.current = requestController;

    if (scanImages) {
      setIsScanning(true);
      setIsStoppingScan(false);
      setScanningFilePath(null);
      setScanProgressState({
        active: true,
        month: requestedMonth,
        total: totalLogs,
        completed: 0,
        current_file: "",
        percent: 0,
      });
    }
    setLogsError("");
    if (showLoading) setStatusMessage(scanImages ? t.scanning : t.loading);
    if (!scanImages && showLoading) setIsLoading(true);

    const path = scanImages
      ? "/api/logs/scan-all"
      : `/api/logs${requestedMonth ? `?month=${encodeURIComponent(requestedMonth)}` : ""}`;
    const requestInit: RequestInit = scanImages
      ? {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ month: requestedMonth }),
      }
      : {};

    fetchJson<LogsResponse>(
      path,
      requestInit,
      scanImages ? 2 * 60 * 60_000 : 60_000,
      requestController.signal,
    )
      .then((data) => {
        if (
          requestGeneration !== logsRequestGeneration.current
          || (requestedMonth && selectedMonthRef.current !== requestedMonth)
        ) return;
        setLogs(data.logs || {});
        setMissing(Array.isArray(data.missing) ? data.missing : []);
        setSystemTree(Array.isArray(data.system_tree) ? data.system_tree : []);
        setCoverage(data.coverage || null);
        setLogsError((data.errors || []).filter(Boolean).join(" "));
        setStatusMessage("");
      })
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") return;
        if (requestGeneration !== logsRequestGeneration.current) return;
        const message = error instanceof Error ? error.message : t.fetchError;
        setLogsError(message);
        setStatusMessage(message);
      })
      .finally(() => {
        if (requestGeneration !== logsRequestGeneration.current) return;
        if (scanImages) {
          setIsScanning(false);
          setIsStoppingScan(false);
          setScanningFilePath(null);
        }
        setIsLoading(false);
      });
  };

  const handleStopScan = () => {
    if (!isScanning || isStoppingScan) return;
    setIsStoppingScan(true);
    setStatusMessage(scanText.stopping);
    fetchJson<{ status: "stopping" | "idle"; message?: string }>("/api/scan/stop", {
      method: "POST",
    }, 10_000)
      .then((data) => {
        setStatusMessage(data.status === "stopping" ? scanText.stopRequested : (data.message || scanText.stopRequested));
      })
      .catch((error: unknown) => {
        setIsStoppingScan(false);
        setStatusMessage(error instanceof Error ? error.message : "Failed to stop scan.");
      });
  };

  const handleAiScan = () => {
    if (isScanning || isAiScanning || !selectedMonth) return;
    setIsAiScanning(true);
    setStatusMessage("Running AI review on unresolved files...");
    fetchJson<{ status: string; reviewed: number; total: number }>("/api/logs/ai-review", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ month: selectedMonth }),
    }, 10 * 60_000)
      .then((data) => {
        setStatusMessage(`AI reviewed ${data.reviewed}/${data.total} files.`);
        fetchLogs(false, selectedMonth, false);
      })
      .catch((error: unknown) => {
        setStatusMessage(error instanceof Error ? error.message : "AI review failed.");
      })
      .finally(() => setIsAiScanning(false));
  };

  const handleScanFile = (log: LogFile) => {
    if (isScanning) return;
    setIsScanning(true);
    setIsStoppingScan(false);
    setScanningFilePath(log.path);
    setStatusMessage(`${t.scanning} ${log.filename}`);
    setScanProgressState({
      active: true,
      month: log.month || selectedMonth,
      total: 1,
      completed: 0,
      current_file: log.filename,
      percent: 0,
    });

    fetchJson<{ status: string }>("/api/logs/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path: log.path }),
    }, 30 * 60_000)
      .then(() => {
        setStatusMessage(scanText.scanComplete);
        // Refresh from cache so checklist fields, manual verdicts, and all
        // status counters are rebuilt by the backend's canonical log route.
        fetchLogs(false, selectedMonth, false);
      })
      .catch((error: unknown) => {
        setStatusMessage(error instanceof Error ? error.message : t.fetchError);
      })
      .finally(() => {
        setIsScanning(false);
        setIsStoppingScan(false);
        setScanningFilePath(null);
      });
  };

  // ---- Scan progress polling ----
  // 750ms interval while isScanning=true. Polls /api/scan-progress, updates
  // progress bar. When scan completes, refreshes the full log table.
  useEffect(() => {
    if (!isScanning) return;

    let cancelled = false;
    const pollProgress = () => {
      fetchJson<ScanProgress>("/api/scan-progress", {}, 10_000)
        .then((progress: ScanProgress) => {
          if (cancelled || !progress) return;
          setScanProgressState(progress);
          if (!progress.active) {
            setIsScanning(false);
            setIsStoppingScan(false);
            setScanningFilePath(null);
            if (progress.month === selectedMonthRef.current) {
              const completedJob = progress.job_id || `${progress.month}:${progress.completed}:${progress.outcome}`;
              if (lastFinishedJob.current !== completedJob) {
                lastFinishedJob.current = completedJob;
                fetchLogs(false, progress.month, false);
              }
            }
          } else if (progress.month === selectedMonthRef.current) {
            setScanProgressState(progress);
            if (lastCompletedCount.current !== progress.completed) {
              lastCompletedCount.current = progress.completed;
              fetchLogs(false, progress.month, false);
            }
          }
        })
        .catch(() => undefined);
    };

    pollProgress();
    const intervalId = window.setInterval(pollProgress, 750);
    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- polling is keyed to the backend scan lifecycle, not callback identity.
  }, [isScanning, selectedMonth]);

  // ---- Initial bootstrap ----
  // On mount: fetch available months, check if a scan is already running on the
  // backend (important after a page refresh), load the latest month, and pull
  // saved settings (thresholds, AI config). Runs once.
  useEffect(() => {
    // Restore a backend-owned scan after refresh; otherwise load the newest month.
    fetchJson<string[]>("/api/months")
      .then((data: string[]) => {
        const availableMonths = Array.isArray(data) ? data : [];
        setMonths(availableMonths);
        return fetchJson<ScanProgress>("/api/scan-progress", {}, 10_000)
          .catch(() => null)
          .then((progress) => {
            const targetMonth = progress?.active && availableMonths.includes(progress.month)
              ? progress.month
              : (availableMonths[0] || "");
            selectedMonthRef.current = targetMonth;
            setSelectedMonth(targetMonth);
            if (progress?.active && progress.month === targetMonth) {
              setScanProgressState(progress);
              setIsScanning(true);
            }
            if (targetMonth) {
              fetchLogs(false, targetMonth);
            } else {
              setLogsError("No evidence month folders were found.");
              setIsLoading(false);
            }
          });
      })
      .catch((error: unknown) => {
        setLogsError(error instanceof Error ? error.message : "Unable to load evidence months.");
        setIsLoading(false);
      });

    fetchJson<ThresholdValues>("/api/settings/thresholds")
      .then((data) => {
        if (data && data.mcafee !== undefined) {
          setThresholdInputs({ mcafee: String(data.mcafee ?? 0), clamwin: String(data.clamwin ?? 0), trellix: String(data.trellix ?? 0), symantec: String(data.symantec ?? 0), zero_threat_confidence: String(data.zero_threat_confidence ?? 0.90), ocr_strictness: data.ocr_strictness ?? "high" });
        }
      })
      .catch(() => setThresholdSaveStatus("Unable to load thresholds."));

    fetchJson<AISettingsResponse>("/api/settings/ai")
      .then((data) => { setAiSettings(data.settings); setAiStatus(data.status); })
      .catch(() => setAiSaveStatus("Unable to load local AI settings."));
    // Initial bootstrap is intentionally mount-only; request callbacks use the
    // initial language and explicitly pass the selected month.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const frameId = window.requestAnimationFrame(() => {
      const storedTheme = window.localStorage.getItem("securityCenterTheme") || window.localStorage.getItem("theme");
      if (storedTheme === "purple" || storedTheme === "indigo" || storedTheme === "blue") {
        setTheme(storedTheme);
      } else if (storedTheme === "dark") {
        setTheme("indigo");
      }
      const storedDarkMode = window.localStorage.getItem("securityCenterDarkMode");
      setDarkMode(storedDarkMode === "true" || (storedDarkMode === null && storedTheme === "dark"));
      setPreferencesLoaded(true);
    });
    return () => window.cancelAnimationFrame(frameId);
  }, []);

  useEffect(() => {
    if (!preferencesLoaded) return;
    window.localStorage.setItem("securityCenterTheme", theme);
window.localStorage.setItem("securityCenterDarkMode", darkMode ? "true" : "false");
  }, [theme, darkMode, preferencesLoaded]);

  useEffect(() => () => logsAbortController.current?.abort(), []);

  useEffect(() => () => logsAbortController.current?.abort(), []);

  const handleMonthChange = (month: string) => {
    if (isScanning) return;
    selectedMonthRef.current = month;
    setSelectedMonth(month);
    fetchLogs(false, month);
  };

  const handleThresholdChange = (engine: ThresholdKey, value: string) => {
    setThresholdInputs((current) => ({ ...current, [engine]: value }));
    setThresholdSaveStatus("");
  };

  const saveThreshold = (engine: ThresholdKey) => {
    const rawValue = thresholdInputs[engine];
    if (rawValue.trim() === "") return;

    let finalValue: string | number = rawValue;
    if (engine !== "ocr_strictness") {
      finalValue = Number(rawValue);
      if (!Number.isFinite(finalValue)) {
        setThresholdSaveStatus("Enter a valid number.");
        return;
      }
      if (engine === "zero_threat_confidence" && (finalValue < 0.00 || finalValue > 0.99)) {
        setThresholdSaveStatus("OCR confidence must be between 0.00 and 0.99.");
        return;
      }
    }

    setThresholdSaveStatus("Saving setting...");

    fetchJson<{ thresholds: ThresholdValues }>("/api/settings/thresholds", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      // Send only the edited field so two open dashboards cannot overwrite
      // unrelated engine values with stale state.
      body: JSON.stringify({ [engine]: finalValue }),
    })
      .then((data) => {
        if (data?.thresholds) setThresholdInputs({ mcafee: String(data.thresholds.mcafee ?? 0), clamwin: String(data.thresholds.clamwin ?? 0), trellix: String(data.thresholds.trellix ?? 0), symantec: String(data.thresholds.symantec ?? 0), zero_threat_confidence: String(data.thresholds.zero_threat_confidence ?? 0.90), ocr_strictness: data.thresholds.ocr_strictness ?? "high" });
        setThresholdSaveStatus("Setting saved. Cached OCR results have been reclassified.");
        fetchLogs(false, selectedMonth, false);
      })
      .catch(() => {
        setThresholdSaveStatus("Unable to save setting.");
      });
  };

  const saveAISettings = (updates: Partial<AISettings>) => {
    setAiSaveStatus("Saving...");
    fetchJson<AISettingsResponse>("/api/settings/ai", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(updates),
    }).then((data) => {
      setAiSettings(data.settings); setAiStatus(data.status);
      setAiSaveStatus(data.settings.mode === "off" ? "Local AI is off." : "Local AI will check unresolved images.");
    }).catch((error: unknown) => setAiSaveStatus(error instanceof Error ? error.message : "Unable to save."));
  };

  const testLocalAI = () => {
    setAiTesting(true); setAiSaveStatus("Checking local Qwen...");
    fetchJson<{ status: AIStatus }>("/api/settings/ai/test", { method: "POST" }, 75_000)
      .then((data) => { setAiStatus(data.status); setAiSaveStatus("Local Qwen is ready."); })
      .catch((error: unknown) => setAiSaveStatus(error instanceof Error ? error.message : "Local Qwen is unavailable."))
      .finally(() => setAiTesting(false));
  };
  const handleVerification = (log: LogFile, verdict: "safe" | "unsafe" | "clear") => {
    if (verificationPending) return;
    setVerificationPending(log.path);
    setStatusMessage("Saving verification...");
    fetchJson<{ status: string }>("/api/logs/verification", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path: log.path, verdict }),
    })
      .then(() => {
        setStatusMessage(verdict === "clear" ? "Verification cleared." : verdict === "safe" ? "Marked as safe." : "Marked as unsafe.");
        fetchLogs(false, selectedMonth, false);
      })
      .catch((error: unknown) => setStatusMessage(error instanceof Error ? error.message : t.fetchError))
      .finally(() => setVerificationPending(null));
  };

  const systemFilters = Array.from(new Set(allLogRows.map((log) => log.system))).sort();
  const systemFilteredRows = systemFilter === "all" ? allLogRows : allLogRows.filter((log) => log.system === systemFilter);
  const logTypeFilters: { key: LogTypeFilter; label: string; count: number }[] = [
    { key: "all", label: "All", count: systemFilteredRows.length },
    { key: "images", label: "Images", count: systemFilteredRows.filter((log) => imageTypes.has(log.type)).length },
    { key: "text", label: "Text/Log", count: systemFilteredRows.filter((log) => textTypes.has(log.type)).length },
    { key: "pdf", label: "PDF", count: systemFilteredRows.filter((log) => log.type === "PDF").length },
  ];
  const normalizedSearch = searchQuery.trim().toLowerCase();
  const filteredLogRows = systemFilteredRows
    .filter((log) => {
      if (logTypeFilter === "images") return imageTypes.has(log.type);
      if (logTypeFilter === "text") return textTypes.has(log.type);
      if (logTypeFilter === "pdf") return log.type === "PDF";
      return true;
    })
    .filter((log) => {
      if (statusFilter === "clean") return log.status === "Clean";
      if (statusFilter === "verification") return log.status === "Manual Verification Needed";
      if (statusFilter === "threats") return log.status === "Threats Found";
      if (statusFilter === "not-scanned") return log.status === "Not Scanned";
      return true;
    })
    .filter((log) => {
      if (!normalizedSearch) return true;
      return [
        log.system,
        log.filename,
        log.dat_version,
        log.last_scan,
        log.dat_version_candidate,
        log.last_scan_candidate,
        ...(log.verification_reasons || []),
      ].some((value) => String(value || "").toLowerCase().includes(normalizedSearch));
    });

  const getSelectedPdfSystem = (log: LogFile) => {
    const systems = log.pdf_systems || [];
    if (systems.length === 0) return null;
    const selectedName = selectedPdfSystems[log.path];
    return systems.find((system) => system.name === selectedName) || systems[0];
  };
  // --- NEW WIDGET DATA LOGIC ---

  const scannedCount = totalLogs - notScannedCount;
  const scanProgress = totalLogs > 0 ? Math.round((scannedCount / totalLogs) * 100) : 0;
  const liveScanTotal = isScanning && scanProgressState?.total ? scanProgressState.total : totalLogs;
  const liveScannedCount = isScanning && scanProgressState ? scanProgressState.completed : scannedCount;
  const liveNotScannedCount = Math.max(liveScanTotal - liveScannedCount, 0);
  const liveScanProgress = liveScanTotal > 0 ? Math.round((liveScannedCount / liveScanTotal) * 100) : scanProgress;

  const toggleSystemExpanded = (systemName: string) => {
    setExpandedSystems((current) => ({ ...current, [systemName]: !current[systemName] }));
  };

  const isActionRequiredLog = (log: LogFile) =>
    log.is_outdated || log.status === "Manual Verification Needed" || log.status === "Threats Found";
  const actionRequiredLogs = allLogRows.filter(isActionRequiredLog);

  // Quick verification buttons (Safe/Unsafe/Clear) rendered inline in log rows.
  // Uses verificationPending to lock out double-clicks on the same file.
  const renderVerificationActions = (log: LogFile) => (
    <div className="flex items-center gap-1 whitespace-nowrap">
      <button
        onClick={() => handleVerification(log, "safe")}
        disabled={verificationPending === log.path}
        className={`rounded-none px-2 py-1 text-[11px] font-semibold transition-colors cursor-pointer ${isDarkTheme ? "bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/20" : "bg-emerald-50 text-emerald-700 hover:bg-emerald-100"}`}
      >
        {t.markSafe}
      </button>
      <button
        onClick={() => handleVerification(log, "unsafe")}
        disabled={verificationPending === log.path}
        className={`rounded-none px-2 py-1 text-[11px] font-semibold transition-colors cursor-pointer ${isDarkTheme ? "bg-rose-500/10 text-rose-300 hover:bg-rose-500/20" : "bg-rose-50 text-rose-700 hover:bg-rose-100"}`}
      >
        {t.markUnsafe}
      </button>
      {log.verification && (
        <button
          onClick={() => handleVerification(log, "clear")}
          disabled={verificationPending === log.path}
          className={`rounded-none px-2 py-1 text-[11px] font-semibold transition-colors disabled:opacity-50 ${isDarkTheme ? "bg-white/[0.06] text-slate-300 hover:bg-white/[0.1]" : "bg-zinc-100 text-zinc-700 hover:bg-zinc-200"}`}
        >
          Clear
        </button>
      )}
    </div>
  );

  // 3. System tree status overlays. The tree itself comes from the checklist;
  // found/missing badges are only applied when names match the current logs.
  const foundLocationMap: Record<string, Set<string>> = {};
  const missingLocationMap: Record<string, Set<string>> = {};
  const normalizeLocationName = (value: string) => value.toLowerCase().replace(/[^a-z0-9]/g, "");

  Object.keys(logs).forEach(system => {
    foundLocationMap[system] = new Set();

    if (Array.isArray(logs[system])) {
      logs[system].forEach(log => {
        const match = log.filename.match(/^\[(.*?)\]/);
        const location = match ? match[1].split('/')[0].trim() : "Base System";
        foundLocationMap[system].add(normalizeLocationName(location));
      });
    }
  });

  missing.forEach(alert => {
    if (!missingLocationMap[alert.system]) missingLocationMap[alert.system] = new Set();
    missingLocationMap[alert.system].add(normalizeLocationName(alert.subsystem));
  });

  const groupedMissing = Object.values(missing.reduce((groups, alert) => {
    const systemKey = alert.system;
    const locationKey = `${alert.system}::${alert.subsystem}`;
    if (!groups[systemKey]) {
      groups[systemKey] = {
        system: alert.system,
        expected: 0,
        found: 0,
        missing: 0,
        seen: new Set<string>(),
        locations: [] as MissingAlert[],
      };
    }

    if (!groups[systemKey].seen.has(locationKey)) {
      groups[systemKey].seen.add(locationKey);
      groups[systemKey].expected += alert.expected;
      groups[systemKey].found += alert.found;
      groups[systemKey].missing += alert.missing;
      groups[systemKey].locations.push(alert);
    }

    return groups;
  }, {} as Record<string, {
    system: string;
    expected: number;
    found: number;
    missing: number;
    seen: Set<string>;
    locations: MissingAlert[];
  }>)).map((group) => ({
    system: group.system,
    expected: group.expected,
    found: group.found,
    missing: group.missing,
    locations: group.locations,
  }));

  const missingTotals = groupedMissing.reduce((totals, group) => ({
    systems: totals.systems + 1,
    locations: totals.locations + group.locations.length,
    expected: totals.expected + group.expected,
    found: totals.found + group.found,
    missing: totals.missing + group.missing,
  }), { systems: 0, locations: 0, expected: 0, found: 0, missing: 0 });

  const chartTextColor = isDarkTheme ? "#94a3b8" : "#71717a";
  const doughnutOptions = {
    maintainAspectRatio: false,
    cutout: "68%",
    plugins: {
      legend: {
        position: "bottom" as const,
        labels: { boxWidth: 8, boxHeight: 8, usePointStyle: true, padding: 16, color: chartTextColor, font: { size: 11 } },
      },
    },
  };

  const getOverallStatusData = () => ({
    labels: [t.cleanFiles, t.threatsFound, t.needsVerification, t.notScanned],
    datasets: [
      {
        data: [cleanCount, threatsCount, manualCount, notScannedCount],
        backgroundColor: ["#10b981", "#f43f5e", "#f59e0b", isDarkTheme ? "#3f3f46" : "#d4d4d8"],
        borderWidth: 0,
      },
    ],
  });

  const getThreatsBySystemData = () => {
    const labels = Object.keys(logs);
    const threatsData = labels.map((system) =>
      Array.isArray(logs[system]) ? logs[system].filter((log) => log.status === "Threats Found").length : 0
    );
    const backgroundColors = labels.map((_, index) => `hsl(${index * (360 / Math.max(labels.length, 1))}, 65%, 58%)`);

    return {
      labels,
      datasets: [{ data: threatsData, backgroundColor: backgroundColors, borderWidth: 0 }],
    };
  };

  const getStatusMeta = (status: string) => {
    if (status === "Threats Found") return { dot: "bg-rose-500", pill: isDarkTheme ? "text-rose-300 bg-rose-500/10" : "text-rose-700 bg-rose-50", display: t.threatsFound };
    if (status === "Manual Verification Needed") return { dot: "bg-amber-500", pill: isDarkTheme ? "text-amber-300 bg-amber-500/10" : "text-amber-700 bg-amber-50", display: t.needsVerification };
    if (status === "Clean") return { dot: "bg-emerald-500", pill: isDarkTheme ? "text-emerald-300 bg-emerald-500/10" : "text-emerald-700 bg-emerald-50", display: t.cleanFiles };
    return { dot: "bg-zinc-400", pill: isDarkTheme ? "text-slate-300 bg-white/[0.06]" : "text-zinc-600 bg-zinc-100", display: t.notScanned };
  };

  // Evidence viewer — images are served through the validated /api/logs/file
  // route (never exposed directly from the filesystem). Text/PDF summaries come
  // from /api/logs/summary which returns the raw extracted content.
  const openLogSummary = (log: LogFile) => {
    // Images are served through a validated API route, not a broad static mount.
    if (imageTypes.has(log.type)) {
      setImageLoadState("loading");
      setViewingImage({
        url: `${getApiBase()}/api/logs/file?path=${encodeURIComponent(log.path)}`,
        name: log.filename,
        retry: 0,
        log,
      });
      return;
    }

    // Otherwise, fetch the text summary for PDF/TXT as usual
    setSelectedLog(log);
    setLogSummary(t.loading);
    fetchJson<{ summary: string }>(
      `/api/logs/summary?path=${encodeURIComponent(log.path)}&status=${encodeURIComponent(log.status)}`,
    )
      .then((data) => setLogSummary(data.summary || "No content was extracted."))
      .catch(() => setLogSummary("Failed to fetch summary."));
  };

  const closeLogSummary = () => {
    setSelectedLog(null);
    setLogSummary("");
    setViewingImage(null);
    setImageLoadState("loading");
  };

  const retryViewingImage = () => {
    setImageLoadState("loading");
    setViewingImage((current) => current ? { ...current, retry: current.retry + 1 } : current);
  };

  useEffect(() => {
    if (!selectedLog && !viewingImage) return;
    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setSelectedLog(null);
        setLogSummary("");
        setViewingImage(null);
        setImageLoadState("loading");
      }
    };
    document.addEventListener("keydown", handleEscape);
    return () => document.removeEventListener("keydown", handleEscape);
  }, [selectedLog, viewingImage]);

  const navItems: { key: Tab; label: string; icon: () => React.ReactElement }[] = [
    { key: "home", label: t.dashboard, icon: Icons.Dashboard },
    { key: "logs", label: t.logDir, icon: Icons.Logs },
    { key: "settings", label: t.settings, icon: Icons.Settings },
  ];

  const statCards = [
    { label: t.totalFiles, value: totalLogs, dot: "", accent: true },
    { label: t.threatsFound, value: threatsCount, dot: "bg-rose-500", valueClass: "text-rose-500" },
    { label: t.needsVerification, value: manualCount, dot: "bg-amber-500", valueClass: "text-amber-500" },
    { label: t.outdatedSigs, value: outdatedCount, dot: "bg-orange-500", valueClass: "text-orange-500" },
  ];

  if (isLoading) {
    return (
      <div className={`min-h-screen flex flex-col justify-center items-center gap-4 ${pageBgClass}`}>
        <div style={{ color: activeColor }}>
          <Icons.Spinner />
        </div>
        <p className={`text-sm ${mutedTextClass}`}>{statusMessage || t.loading}</p>
      </div>
    );
  }

  return (
    <div className={`flex h-screen font-sans overflow-hidden ${pageBgClass}`}>

      {/* Sidebar */}
      <aside
        style={{ backgroundColor: activeColor }}
        className="w-60 shrink-0 flex flex-col shadow-xl z-10 text-white transition-colors duration-500"
      >
        <div className="bg-white px-4 h-24 flex flex-col items-center justify-center gap-0.5 border-b border-zinc-200 text-center shrink-0">
          <svg viewBox="0 0 24 24" className="h-10 w-10 text-emerald-600" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
            <path d="M12 3l7 3v5c0 4.5-3 7.6-7 9-4-1.4-7-4.5-7-9V6l7-3z" />
            <path d="M9 12l2 2 4-4" />
          </svg>
          <div className="leading-tight">
            <div className="text-xs font-bold tracking-tight text-zinc-900">{t.secCenter}</div>
          </div>
        </div>

        <nav className="flex-1 p-3 space-y-1">
          {navItems.map(({ key, label, icon: Icon }) => {
            const active = activeTab === key;
            return (
              <button
                key={key}
                onClick={() => setActiveTab(key)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-none text-sm font-medium transition-colors cursor-pointer ${active
                  ? "bg-white/20 text-white font-bold shadow-inner"
                  : "text-white/70 hover:text-white hover:bg-white/10"
                  }`}
              >
                <Icon />
                <span>{label}</span>
              </button>
            );
          })}
        </nav>

      </aside>

      {/* Main */}
      <main className="flex-1 flex flex-col h-full overflow-y-auto">
        <header className={`h-24 shrink-0 px-8 flex items-center justify-between border-b sticky top-0 z-10 backdrop-blur ${isDarkTheme ? "bg-[#0A0A0C]/80 border-white/[0.06]" : "bg-white/80 border-zinc-200/70"}`}>
          <h2 className={`text-3xl font-bold tracking-tight ${headingClass}`}>
            {activeTab === "home" ? t.overview : activeTab === "logs" ? t.sysLogs : t.sysSettings}
          </h2>
          <div className="flex items-center gap-3">
            {months.length > 0 && (
              <label className="flex items-center gap-2">
                <span className={`text-xs font-medium ${mutedTextClass}`}>{t.month}</span>
                <select
                  value={selectedMonth}
                  disabled={isScanning}
                  aria-label="Evidence month"
                  onChange={(e) => handleMonthChange(e.target.value)}
                  className={`text-xs font-medium rounded-none px-2.5 py-1.5 outline-none border cursor-pointer ${inputClass}`}
                >
                  {months.map((m) => (
                    <option key={m} value={m}>{m}</option>
                  ))}
                </select>
              </label>
            )}
          </div>
        </header>

        <div className={activeTab === "logs" ? "p-6 w-full max-w-none" : "p-8 max-w-7xl w-full mx-auto"}>
          {logsError && (
            <div
              role="alert"
              className={`mb-4 flex items-center justify-between gap-4 rounded-none border px-4 py-3 text-xs ${isDarkTheme ? "border-rose-500/20 bg-rose-500/10 text-rose-200" : "border-rose-200 bg-rose-50 text-rose-800"}`}
            >
              <span>{logsError}</span>
              {selectedMonth && (
                <button
                  type="button"
                  onClick={() => fetchLogs(false, selectedMonth)}
                  className="shrink-0 rounded-none border border-current/20 px-3 py-1.5 font-semibold hover:bg-white/10"
                >
                  Retry
                </button>
              )}
            </div>
          )}

          {activeTab === "home" && (
            <div className="space-y-4">
              {/* Stat cards */}
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                {statCards.map((card) => (
                  <div key={card.label} className={`p-5 rounded-none border ${surfaceClass}`}>
                    <div className={`flex items-center gap-2 text-xs font-medium ${mutedTextClass}`}>
                      {card.dot && <span className={`w-1.5 h-1.5 rounded-full ${card.dot}`}></span>}
                      {card.accent && <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: activeColor }}></span>}
                      {card.label}
                    </div>
                    <div
                      className={`text-3xl font-semibold tracking-tight mt-3 ${card.valueClass ?? headingClass}`}
                      style={card.accent ? { color: activeColor } : undefined}
                    >
                      {card.value}
                    </div>
                  </div>
                ))}
              </div>

              {/* Charts */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className={`p-6 rounded-none border ${surfaceClass}`}>
                  <h3 className={`text-sm font-semibold mb-5 tracking-tight ${headingClass}`}>{t.overallStatus}</h3>
                  <div style={{ height: "260px" }} className="flex justify-center">
                    <Doughnut data={getOverallStatusData()} options={doughnutOptions} />
                  </div>
                </div>
                <div className={`p-6 rounded-none border ${surfaceClass}`}>
                  <h3 className={`text-sm font-semibold mb-5 tracking-tight ${headingClass}`}>{t.threatsBySystem}</h3>
                  <div style={{ height: "260px" }} className="flex justify-center">
                    <Doughnut data={getThreatsBySystemData()} options={doughnutOptions} />
                  </div>
                </div>
              </div>
              {/* --- NEW OVERVIEW WIDGETS --- */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mt-4">

                {/* Files scanned */}
                <div className={`lg:col-span-3 p-6 rounded-none border flex flex-col justify-center ${surfaceClass}`}>
                  <div className="flex justify-between items-end mb-3">
                    <div>
                      <h3 className={`text-sm font-semibold tracking-tight ${headingClass}`}>No. of files scanned</h3>
                      <p className={`text-xs mt-1 ${mutedTextClass}`}>
                        {isScanning && scanProgressState?.current_file
                          ? `Scanning ${scanProgressState.current_file}`
                          : `${liveNotScannedCount} files not scanned.`}
                      </p>
                    </div>
                    <div className="text-right">
                      <div className="text-3xl font-semibold tracking-tight" style={{ color: activeColor }}>
                        {liveScannedCount}
                        <span className={`text-base font-medium ${mutedTextClass}`}>/{liveScanTotal}</span>
                      </div>
                      <div className={`text-xs mt-1 ${mutedTextClass}`}>{liveScanProgress}% scanned</div>
                      {isScanning && scanProgressState && (
                        <div className={`text-[11px] mt-1 ${mutedTextClass}`}>
                          Cached {scanProgressState.cache_hits || 0}
                        </div>
                      )}
                    </div>
                  </div>
                  <div className={`w-full h-3 rounded-none overflow-hidden ${isDarkTheme ? 'bg-white/5' : 'bg-zinc-100'}`}>
                    <div
                      className="h-full transition-all duration-300 ease-out"
                      style={{ width: `${liveScanProgress}%`, backgroundColor: activeColor }}
                    ></div>
                  </div>
                </div>

                {/* Action Required */}
                <div className={`lg:col-span-1 p-6 rounded-none border flex flex-col ${surfaceClass}`}>
                  <h3 className={`text-sm font-semibold mb-4 tracking-tight ${headingClass}`}>Action Required</h3>
                  {actionRequiredLogs.length > 0 ? (
                    <div className={`flex-1 overflow-y-auto pr-2 space-y-3`}>
                      {actionRequiredLogs.map((log, i) => (
                        <div key={`${log.path}-${i}`} className={`p-3 rounded-none border ${isDarkTheme ? 'bg-amber-500/5 border-amber-500/10' : 'bg-amber-50 border-amber-100'}`}>
                          <div className="flex justify-between items-start gap-3">
                            <div className="min-w-0">
                              <div className={`text-xs font-bold truncate ${isDarkTheme ? "text-amber-300" : "text-amber-700"}`}>{log.system}</div>
                              <div className={`text-[10px] truncate mt-0.5 ${isDarkTheme ? "text-amber-200/70" : "text-amber-700/70"}`} title={log.filename}>{log.filename}</div>
                            </div>
                            <div className="text-right shrink-0">
                              <div className={`text-[10px] uppercase font-bold ${isDarkTheme ? "text-amber-300/70" : "text-amber-600/70"}`}>
                                {log.is_outdated ? "Version" : "Review"}
                              </div>
                              <div className={`text-xs font-mono font-medium ${isDarkTheme ? "text-amber-200" : "text-amber-700"}`}>
                                {log.is_outdated ? log.dat_version : log.type}
                              </div>
                            </div>
                          </div>
                          <div className="mt-3 flex items-center justify-between gap-2">
                            <span className={`text-[10px] font-semibold uppercase tracking-wide ${isDarkTheme ? "text-amber-300/70" : "text-amber-700/70"}`}>
                              {log.status === "Manual Verification Needed" ? t.needsVerification : t.outdatedSigs}
                            </span>
                            <div className="flex items-center gap-1.5">
                              {imageTypes.has(log.type) && (
                                <button
                                  type="button"
                                  onClick={() => openLogSummary(log)}
                                  className={`px-2 py-1 rounded-none text-[11px] font-semibold transition-colors cursor-pointer ${isDarkTheme ? "bg-white/[0.06] text-slate-200 hover:bg-white/[0.1]" : "bg-white text-zinc-700 hover:bg-zinc-100 border border-zinc-200"}`}
                                >
                                  View Image
                                </button>
                              )}
                              {renderVerificationActions(log)}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className={`flex-1 flex flex-col items-center justify-center py-8 text-xs ${mutedTextClass} bg-emerald-500/5 rounded-none border border-emerald-500/10`}>
                      <span className="text-emerald-500 text-2xl mb-2">✓</span>
                      No manual action required.
                    </div>
                  )}
                </div>

                {/* System Tree */}
                <div className={`lg:col-span-2 p-6 rounded-none border ${surfaceClass}`}>
                  <h3 className={`text-sm font-semibold mb-4 tracking-tight ${headingClass}`}>{t.systemTree}</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {systemTree.length > 0 ? (
                      systemTree.map(system => {
                        const totals = system.locations.reduce((acc, location) => {
                          const locationKey = normalizeLocationName(location.name);
                          const foundCount = location.found ?? (foundLocationMap[system.system]?.has(locationKey) ? location.expected : 0);
                          const missingCount = location.missing ?? Math.max(location.expected - foundCount, 0);
                          const unknownCount = location.coverage_status === "unknown" ? (location.unresolved_count ?? Math.max(location.expected - foundCount, 0)) : 0;
                          acc.expected += location.expected;
                          acc.found += foundCount;
                          acc.missing += missingCount;
                          acc.unknown += unknownCount;
                          return acc;
                        }, { expected: 0, found: 0, missing: 0, unknown: 0 });
                        const isExpanded = Boolean(expandedSystems[system.system]);

                        return (
                          <div key={system.system} className={`p-3 rounded-none border ${isDarkTheme ? 'bg-white/[0.02] border-white/5' : 'bg-white border-zinc-200/70'}`}>
                            <button
                              type="button"
                              onClick={() => toggleSystemExpanded(system.system)}
                              className="w-full flex items-center justify-between gap-3 text-left cursor-pointer"
                            >
                              <div className="min-w-0">
                                <div className={`text-xs font-bold ${headingClass}`}>{system.system}</div>
                                <div className={`text-[10px] mt-1 ${mutedTextClass}`}>
                                  {totals.found}/{totals.expected} found
                                  {totals.missing > 0 && (
                                    <span className={isDarkTheme ? "text-rose-300" : "text-rose-600"}> · {totals.missing} missing</span>
                                  )}
                                  {totals.unknown > 0 && (
                                    <span className={isDarkTheme ? "text-amber-300" : "text-amber-700"}> / {totals.unknown} unresolved</span>
                                  )}
                                </div>
                              </div>
                              <span className={`shrink-0 text-[10px] uppercase tracking-wider font-semibold px-2 py-1 rounded-none ${isDarkTheme ? "bg-white/[0.05] text-slate-300" : "bg-white text-zinc-600 border border-zinc-200"}`}>
                                {isExpanded ? "Hide" : "Show"}
                              </span>
                            </button>

                            {isExpanded && (
                              <div className="flex flex-wrap gap-1.5 mt-3">
                                {system.locations.map(location => {
                                  const locationKey = normalizeLocationName(location.name);
                                  const foundCount = location.found ?? (foundLocationMap[system.system]?.has(locationKey) ? location.expected : 0);
                                  const missingCount = location.missing ?? Math.max(location.expected - foundCount, 0);
                                  const isUnknown = location.coverage_status === "unknown";
                                  const isFound = foundCount >= location.expected;
                                  const isPartial = foundCount > 0 && missingCount > 0;
                                  const isMissing = missingCount > 0 && !isPartial;
                                  const locationClass = isUnknown
                                    ? isDarkTheme
                                      ? 'bg-amber-500/10 text-amber-300 border border-amber-500/20'
                                      : 'bg-amber-50 text-amber-800 border border-amber-200'
                                    : isMissing
                                      ? isDarkTheme
                                        ? 'bg-rose-500/10 text-rose-300 border border-rose-500/20'
                                        : 'bg-rose-50 text-rose-700 border border-rose-200'
                                      : isPartial
                                        ? isDarkTheme
                                          ? 'bg-amber-500/10 text-amber-300 border border-amber-500/20'
                                          : 'bg-amber-50 text-amber-700 border border-amber-200'
                                        : isFound
                                          ? isDarkTheme
                                            ? 'bg-emerald-500/10 text-emerald-300'
                                            : 'bg-emerald-50 text-emerald-700'
                                          : isDarkTheme
                                            ? 'bg-white/[0.04] text-slate-300 border border-white/[0.05]'
                                            : 'bg-white text-zinc-600 border border-zinc-200';

                                  return (
                                    <span
                                      key={`${system.system}-${location.name}`}
                                      className={`text-[9px] uppercase tracking-wider font-semibold px-2 py-1 rounded-none ${locationClass}`}
                                      title={`${foundCount} found / ${location.expected} expected • ${location.antivirus}`}
                                    >
                                      {isUnknown && '? '}
                                      {isMissing ? '!' : isPartial ? '!' : isFound ? '✓' : ''} {location.name} · {foundCount}/{location.expected} · {location.antivirus}
                                    </span>
                                  );
                                })}
                              </div>
                            )}
                          </div>
                        );
                      })
                    ) : (
                      <div className={`md:col-span-2 text-center py-8 text-xs ${mutedTextClass}`}>
                        No subsystem data available.
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === "logs" && (
            <div className="space-y-6">
              {(coverage?.unknown_coverage || 0) > 0 && (
                <div className={`rounded-none border px-4 py-3 text-xs ${isDarkTheme ? "border-amber-500/20 bg-amber-500/10 text-amber-200" : "border-amber-200 bg-amber-50 text-amber-900"}`}>
                  <strong>{coverage?.unknown_coverage} computer records are grouped in a summary report.</strong>{" "}
                  Summary reports are saved as valid evidence, but individual computers within them cannot be listed separately. These are not counted as missing files.
                </div>
              )}
              {/* Compliance alerts — missing files, shown separately from present logs */}
              {groupedMissing.length > 0 && (
                <div className={`rounded-none border overflow-hidden ${isDarkTheme ? "border-rose-500/20 bg-rose-500/[0.04]" : "border-rose-200 bg-rose-50/60"}`}>
                  <div className={`px-5 py-3.5 flex flex-wrap items-center gap-x-4 gap-y-2 ${showMissingDetails ? `border-b ${isDarkTheme ? "border-rose-500/20" : "border-rose-100"}` : ""}`}>
                    <div className="flex min-w-0 items-center gap-2.5">
                      <span className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-none ${isDarkTheme ? "bg-rose-500/15 text-rose-300" : "bg-rose-100 text-rose-700"}`}>
                        <span className="h-2 w-2 bg-rose-500"></span>
                      </span>
                      <div className="min-w-0">
                        <h3 className={`text-sm font-semibold tracking-tight ${isDarkTheme ? "text-rose-200" : "text-rose-900"}`}>
                          {t.complianceAlerts}
                        </h3>
                        <p className={`mt-0.5 text-[11px] ${isDarkTheme ? "text-rose-200/60" : "text-rose-700/70"}`}>
                          {missingTotals.missing} files missing across {missingTotals.systems} systems and {missingTotals.locations} locations
                        </p>
                      </div>
                    </div>
                    <div className={`ml-auto hidden items-center gap-4 text-[11px] sm:flex ${isDarkTheme ? "text-rose-200/70" : "text-rose-800/70"}`}>
                      <span>Expected <strong className={headingClass}>{missingTotals.expected}</strong></span>
                      <span>Found <strong className={headingClass}>{missingTotals.found}</strong></span>
                    </div>
                    <button
                      type="button"
                      onClick={() => setShowMissingDetails((current) => !current)}
                      aria-expanded={showMissingDetails}
                      className={`rounded-none border px-3 py-1.5 text-xs font-semibold transition-colors ${isDarkTheme ? "border-rose-400/20 text-rose-200 hover:bg-rose-500/10" : "border-rose-200 bg-white/70 text-rose-800 hover:bg-white"}`}
                    >
                      {showMissingDetails ? "Hide details" : "View details"}
                    </button>
                  </div>
                  {showMissingDetails && (
                    <div className="grid grid-cols-1 gap-3 p-4 sm:grid-cols-2 xl:grid-cols-3">
                      {groupedMissing.map((group) => (
                        <div key={group.system} className={`p-3.5 rounded-none border ${isDarkTheme ? "bg-white/[0.02] border-rose-500/15" : "bg-white border-rose-100"}`}>
                          <div className="flex items-center justify-between gap-2">
                            <span className={`text-sm font-semibold ${headingClass}`}>{group.system}</span>
                            <span className={`text-[10px] uppercase tracking-wider font-semibold px-2 py-0.5 rounded-none ${isDarkTheme ? "bg-rose-500/15 text-rose-300" : "bg-rose-100 text-rose-700"}`}>
                              {group.locations.length} locations
                            </span>
                          </div>
                          <div className={`mt-2 flex items-center gap-3 text-xs ${mutedTextClass}`}>
                            <span>{t.expectedLabel}: <span className={`font-semibold ${headingClass}`}>{group.expected}</span></span>
                            <span>{t.foundLabel}: <span className={`font-semibold ${headingClass}`}>{group.found}</span></span>
                            <span className={`ml-auto font-bold ${isDarkTheme ? "text-rose-300" : "text-rose-600"}`}>{t.missingLabel}: {group.missing}</span>
                          </div>
                          <div className="mt-3 flex flex-wrap gap-1.5 max-h-24 overflow-y-auto pr-1">
                            {group.locations.map((alert) => (
                              <span
                                key={`${group.system}-${alert.subsystem}`}
                                className={`text-[10px] uppercase tracking-wider font-semibold px-2 py-1 rounded-none ${isDarkTheme ? "bg-white/[0.04] text-slate-300" : "bg-zinc-100 text-zinc-600"}`}
                                title={`${alert.found} found / ${alert.expected} expected`}
                              >
                                {alert.subsystem} · {alert.missing}
                              </span>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              <div className={`rounded-none border overflow-hidden ${surfaceClass}`}>
                <div className={`flex flex-col gap-3 border-b px-5 py-4 lg:flex-row lg:items-center lg:justify-between ${dividerClass}`}>
                  <div className="flex min-w-0 flex-1 flex-wrap items-center gap-2">
                    <h3 className={`mr-1 text-sm font-semibold tracking-tight ${headingClass}`}>{t.allSysLogs}</h3>
                    <select
                      value={systemFilter}
                      onChange={(event) => setSystemFilter(event.target.value)}
                      className={`h-9 min-w-[150px] rounded-none border px-2.5 text-xs font-semibold outline-none cursor-pointer ${inputClass}`}
                      title="Filter by system"
                    >
                      <option value="all">All Systems</option>
                      {systemFilters.map((system) => (
                        <option key={system} value={system}>{system}</option>
                      ))}
                    </select>
                    <div className={`flex h-9 items-center gap-0.5 rounded-none border p-1 ${isDarkTheme ? "border-white/[0.06] bg-white/[0.03]" : "border-zinc-200 bg-white"}`}>
                      {logTypeFilters.map((filter) => {
                        const active = logTypeFilter === filter.key;
                        return (
                          <button
                            key={filter.key}
                            onClick={() => setLogTypeFilter(filter.key)}
                            className={`whitespace-nowrap rounded-none px-2.5 py-1 text-[11px] font-semibold transition-colors cursor-pointer ${active
                              ? "text-white"
                              : isDarkTheme
                                ? "text-slate-300 hover:bg-white/[0.06]"
                                : "text-zinc-600 hover:bg-zinc-100"
                              }`}
                            style={active ? { backgroundColor: activeColor } : undefined}
                          >
                            {filter.label} {filter.count}
                          </button>
                        );
                      })}
                    </div>
                    <select
                      value={statusFilter}
                      onChange={(event) => setStatusFilter(event.target.value as StatusFilter)}
                      className={`h-9 min-w-[135px] rounded-none border px-2.5 text-xs font-semibold outline-none cursor-pointer ${inputClass}`}
                      title="Filter by review status"
                    >
                      <option value="all">All statuses</option>
                      <option value="clean">Clean</option>
                      <option value="verification">Needs verification</option>
                      <option value="threats">Threats found</option>
                      <option value="not-scanned">Not scanned</option>
                    </select>
                    <div className="relative min-w-[220px] flex-1 xl:max-w-sm">
                      <span className={`absolute left-2.5 top-1/2 -translate-y-1/2 ${mutedTextClass}`}>
                        <Icons.Search />
                      </span>
                      <input
                        value={searchQuery}
                        onChange={(event) => setSearchQuery(event.target.value)}
                        placeholder="Search system, file, DAT or date"
                        className={`h-9 w-full rounded-none border pl-8 pr-3 text-xs outline-none ${inputClass}`}
                      />
                    </div>
                  </div>
                  <div className="flex shrink-0 items-center gap-2 self-end lg:self-auto">
                    {selectedMonth && (
                      <a
                        href={`${getApiBase()}/api/reports/monthly?month=${encodeURIComponent(selectedMonth)}`}
                        className={`flex h-9 items-center rounded-none border px-3 text-xs font-semibold transition-colors ${isDarkTheme ? "border-white/[0.1] text-slate-200 hover:bg-white/[0.06]" : "border-zinc-200 text-zinc-700 hover:bg-zinc-100"}`}
                      >
                        Export report
                      </a>
                    )}
                    <button
                      onClick={() => fetchLogs(true, selectedMonth)}
                      disabled={isScanning || !selectedMonth}
                      style={{ backgroundColor: activeColor }}
                      className="flex h-9 items-center justify-center gap-2 whitespace-nowrap rounded-none px-3.5 text-xs font-semibold text-white transition-opacity hover:opacity-90 disabled:opacity-50 cursor-pointer"
                    >
                      {isScanning ? <><Icons.Spinner /> {t.scanning}</> : <><Icons.Search /> {scanText.scanAll}</>}
                    </button>
                    <button
                      onClick={handleAiScan}
                      disabled={isScanning || isAiScanning || !selectedMonth}
                      className={`flex h-9 items-center justify-center gap-2 whitespace-nowrap rounded-none border px-3.5 text-xs font-semibold transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${isDarkTheme ? "border-violet-400/30 text-violet-300 hover:bg-violet-500/10" : "border-violet-200 text-violet-700 hover:bg-violet-50"}`}
                      title="Run local Qwen only on files that need review"
                    >
                      {isAiScanning ? <><Icons.Spinner /> AI reviewing...</> : "AI review"}
                    </button>
                    <button
                      onClick={handleStopScan}
                      disabled={!isScanning || isStoppingScan}
                      className={`flex h-9 items-center justify-center gap-2 whitespace-nowrap rounded-none border px-3.5 text-xs font-semibold transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${isDarkTheme ? "border-rose-400/30 text-rose-300 hover:bg-rose-500/10" : "border-rose-200 text-rose-700 hover:bg-rose-50"}`}
                      title="Safely stop queued OCR work after active files finish"
                    >
                      {isStoppingScan ? <><Icons.Spinner /> {scanText.stopping}</> : scanText.stopScan}
                    </button>
                  </div>
                </div>

                {statusMessage && (
                  <div className={`text-xs px-6 py-2.5 border-b font-medium text-center ${isDarkTheme ? "bg-white/[0.03] text-slate-300 border-white/[0.06]" : "bg-amber-50/60 text-amber-800 border-amber-100"}`}>
                    {statusMessage}
                  </div>
                )}

                <div className={`px-6 py-2 text-[11px] border-b ${dividerClass} ${mutedTextClass}`}>
                  Showing <span className={`font-semibold ${headingClass}`}>{filteredLogRows.length}</span> of {allLogRows.length} logs.
                  {allLogRows.some((log) => log.dat_version_candidate || log.last_scan_candidate) && (
                    <span className="ml-2 text-amber-600 dark:text-amber-300">
                      Amber text needs confirmation against the original file.
                    </span>
                  )}
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full min-w-[1260px] table-fixed border-collapse text-left text-[13px]">
                    <colgroup>
                      <col className="w-[6%]" />
                      <col className="w-[15%]" />
                      <col className="w-[4%]" />
                      <col className="w-[18%]" />
                      <col className="w-[11%]" />
                      <col className="w-[14%]" />
                      <col className="w-[10%]" />
                      <col className="w-[22%]" />
                    </colgroup>
                    <thead>
                      <tr className={`text-[11px] font-medium uppercase tracking-wider ${mutedTextClass} border-b ${dividerClass}`}>
                        <th className="px-4 py-3 font-medium">{t.system}</th>
                        <th className="px-4 py-3 font-medium">{t.filename}</th>
                        <th className="px-3 py-3 font-medium">{t.type}</th>
                        <th className="px-4 py-3 font-medium">{t.status}</th>
                        <th className="px-4 py-3 font-medium">{t.datVersion}</th>
                        <th className="px-4 py-3 font-medium">{t.lastScan}</th>
                        <th className="px-4 py-3 font-medium">{t.remarks}</th>
                        <th className="px-4 py-3 font-medium text-right">{t.audit}</th>
                      </tr>
                    </thead>
                    <tbody className={`divide-y text-sm ${isDarkTheme ? "divide-white/[0.06]" : "divide-zinc-100"}`}>
                      {filteredLogRows.length > 0 ? (
                        filteredLogRows.map((log, idx) => {
                          const selectedPdfSystem = getSelectedPdfSystem(log);
                          return (
                            <tr key={`${log.system}-${idx}-${log.path}`} className={`transition-colors ${isDarkTheme ? "hover:bg-white/[0.025]" : "hover:bg-zinc-50/80"}`}>
                              <td className={`px-4 py-3 font-semibold align-top ${headingClass}`}>{log.system}</td>

                              {/* Added Filename Data Cell */}
                              <td className={`px-4 py-3 font-mono text-xs align-top ${headingClass}`}>
                                <div className="truncate leading-5" title={log.filename}>{log.filename}</div>
                                {log.type === "PDF" && (log.pdf_systems?.length || 0) > 0 && (
                                  <div className="mt-2 max-w-xs" onClick={(event) => event.stopPropagation()}>
                                    <select
                                      value={selectedPdfSystem?.name || ""}
                                      onChange={(event) => setSelectedPdfSystems((current) => ({ ...current, [log.path]: event.target.value }))}
                                      className={`w-full text-[11px] rounded-none px-2 py-1 outline-none border font-sans ${inputClass}`}
                                      title="Detected systems inside this PDF"
                                    >
                                      {log.pdf_systems?.map((system) => (
                                        <option key={`${log.path}-${system.name}`} value={system.name}>
                                          {system.name}
                                        </option>
                                      ))}
                                    </select>
                                    {selectedPdfSystem && (
                                      <div className={`mt-1 text-[10px] font-sans ${mutedTextClass}`}>
                                        DAT {selectedPdfSystem.dat_version} · {selectedPdfSystem.last_scan}
                                      </div>
                                    )}
                                  </div>
                                )}
                              </td>

                              <td className={`px-3 py-3 align-top ${mutedTextClass}`}>
                                <span className="text-[11px] font-medium uppercase tracking-wide">{log.type}</span>
                              </td>
                              <td className="px-4 py-3 align-top">
                                <span className={`inline-flex items-center gap-1.5 rounded-none px-2.5 py-1 text-[11px] font-semibold ${getStatusMeta(log.status).pill}`}>
                                  <span className={`w-1.5 h-1.5 rounded-full ${getStatusMeta(log.status).dot}`}></span>
                                  {getStatusMeta(log.status).display}
                                </span>
                                {log.verification && (
                                  <div className={`mt-1 text-[10px] font-medium ${log.verification === "safe" ? "text-emerald-500" : "text-rose-500"}`}>
                                    {log.verification === "safe" ? t.verifiedSafe : t.verifiedUnsafe}
                                  </div>
                                )}
                                {(log.verification_reasons?.length || 0) > 0 && (
                                  <div
                                    className={`mt-1.5 max-h-8 overflow-hidden text-[10px] leading-4 ${isDarkTheme ? "text-amber-300/80" : "text-amber-700"}`}
                                    title={log.verification_reasons?.join("\n")}
                                  >
                                    {log.verification_reasons?.[0]}
                                    {(log.verification_reasons?.length || 0) > 1 && ` +${(log.verification_reasons?.length || 1) - 1} more`}
                                  </div>
                                )}
                                {log.ai_fallback?.used && (
                                  <div
                                    className={`mt-1 text-[10px] font-semibold ${isDarkTheme ? "text-violet-300" : "text-violet-700"}`}
                                    title="Open View to inspect the local Qwen evidence."
                                  >
                                    Qwen checked
                                    {" | "}
                                    {log.ai_fallback.threat_count === null
                                      ? "no threat count resolved"
                                      : `threat count ${log.ai_fallback.threat_count}`}
                                    {Number(log.ai_fallback.elapsed_ms) > 0
                                      ? ` | ${(Number(log.ai_fallback.elapsed_ms) / 1000).toFixed(1)}s`
                                      : ""}
                                  </div>
                                )}
                              </td>
                              <td className="px-4 py-3 text-sm align-top">
                                {log.dat_version !== "Unknown" ? (
                                  <span className={`block truncate font-mono text-xs font-semibold leading-5 ${log.is_outdated ? "text-rose-500" : "text-emerald-500"}`} title={log.dat_version}>
                                    {log.dat_version} {log.is_outdated && "⚠"}
                                  </span>
                                ) : log.dat_version_candidate ? (
                                  <div title="Unconfirmed version; check against the image">
                                    <span className={`block font-mono text-xs font-medium break-words leading-5 ${isDarkTheme ? "text-amber-300" : "text-amber-700"}`}>
                                      {log.dat_version_candidate}
                                    </span>
                                    <span className={`text-[10px] font-semibold uppercase tracking-wide ${mutedTextClass}`}>Needs confirmation</span>
                                  </div>
                                ) : (
                                  <span className={mutedTextClass}>—</span>
                                )}
                              </td>
                              <td className={`px-4 py-3 text-xs font-mono align-top ${mutedTextClass}`}>
                                {log.last_scan !== "Unknown" ? (
                                  <div>
                                    <span className={`block break-words leading-5 ${headingClass}`}>{log.last_scan}</span>
                                    {(log.date_evidence_count || 0) >= 3 && (
                                      <span className="text-[10px] font-sans text-emerald-500">Repeated {log.date_evidence_count} times</span>
                                    )}
                                  </div>
                                ) : log.last_scan_candidate ? (
                                  <div title="Valid date found, but not confirmed as the completed scan timestamp">
                                    <span className={`block break-words leading-5 ${isDarkTheme ? "text-amber-300" : "text-amber-700"}`}>
                                      {log.last_scan_candidate}
                                    </span>
                                    <span className={`text-[10px] font-sans font-semibold uppercase tracking-wide ${mutedTextClass}`}>Unconfirmed date</span>
                                  </div>
                                ) : "—"}
                              </td>
                              <td className={`px-4 py-3 text-xs align-top ${mutedTextClass}`}>
                                {log.checklist_remarks ? (
                                  <div className={`truncate ${headingClass}`} title={log.checklist_remarks}>{log.checklist_remarks}</div>
                                ) : (
                                  <span>—</span>
                                )}
                                {(log.checklist_mismatches?.length || 0) > 0 && (
                                  <div className="mt-1 space-y-1">
                                    {log.checklist_mismatches?.map((mismatch) => (
                                      <div key={`${log.path}-${mismatch}`} className="text-[10px] font-semibold text-rose-500">
                                        {mismatch}
                                      </div>
                                    ))}
                                  </div>
                                )}
                              </td>
                              <td className="px-4 py-3 align-top">
                                <div className="flex flex-wrap items-center justify-end gap-1 whitespace-nowrap">
                                  {(isActionRequiredLog(log) || Boolean(log.verification)) && renderVerificationActions(log)}
                                  <button
                                    onClick={
                                      // eslint-disable-next-line react-hooks/refs -- this callback is invoked only by the click event, never during render.
                                      () => handleScanFile(log)
                                    }
                                    disabled={isScanning}
                                    className={`flex items-center gap-1 rounded-none px-2 py-1.5 text-[11px] font-semibold transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${isDarkTheme ? "text-indigo-300 hover:bg-indigo-400/10" : "text-indigo-700 hover:bg-indigo-50"}`}
                                    title={`Scan only ${log.filename}`}
                                  >
                                    {scanningFilePath === log.path ? <><Icons.Spinner /> {t.scanning}</> : <><Icons.Search /> {scanText.scanFile}</>}
                                  </button>
                                  <button
                                    onClick={() => openLogSummary(log)}
                                    className={`rounded-none px-2 py-1.5 text-[11px] font-semibold transition-colors cursor-pointer ${isDarkTheme ? "text-slate-300 hover:bg-white/[0.06]" : "text-zinc-600 hover:bg-zinc-100"}`}
                                  >
                                    {t.viewLog}
                                  </button>
                                </div>
                              </td>
                            </tr>
                          );
                        })
                      ) : (
                        <tr>
                          <td colSpan={8} className={`text-center py-16 text-xs ${mutedTextClass}`}>
                            {Object.keys(logs).length > 0 ? "No logs match this filter." : t.noLogs}
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {activeTab === "settings" && (
            <div className={`max-w-2xl p-8 rounded-none border ${surfaceClass}`}>
              <h3 className={`text-sm font-semibold mb-6 tracking-tight pb-4 border-b ${dividerClass} ${headingClass}`}>{t.appPrefs}</h3>

              <div className="space-y-8">
                <div>
                  <label className={`block text-sm font-medium mb-1 ${headingClass}`}>{t.themeLabel}</label>
                  <p className={`text-xs mb-3 ${mutedTextClass}`}>{t.themeDesc}</p>
                  <div className="flex gap-3">
                    {(Object.keys(themes) as ThemeKey[]).map((key) => (
                      <button
                        key={key}
                        onClick={() => setTheme(key)}
                        style={{ backgroundColor: themes[key].hex }}
                        className={`h-8 w-8 rounded-full cursor-pointer transition-all ${theme === key ? "ring-2 ring-offset-2 scale-105 " + (isDarkTheme ? "ring-white/40 ring-offset-[#111114]" : "ring-zinc-300 ring-offset-white") : "opacity-40 hover:opacity-90"}`}
                        title={themes[key].name}
                      ></button>
                    ))}
                  </div>
                </div>

                <div className={`h-px ${isDarkTheme ? "bg-white/[0.06]" : "bg-zinc-100"}`} />

                <div className={`flex items-center justify-between gap-4 rounded-none border p-4 ${isDarkTheme ? "bg-white/[0.02] border-white/[0.06]" : "bg-white border-zinc-200/70"}`}>
                  <div>
                    <label className={`block text-sm font-medium mb-1 ${headingClass}`}>{t.darkModeLabel}</label>
                    <p className={`text-xs ${mutedTextClass}`}>{t.darkModeDesc}</p>
                  </div>
                  <button
                    type="button"
                    role="switch"
                    aria-checked={darkMode}
                    onClick={() => setDarkMode((value) => !value)}
                    className={`relative h-7 w-12 shrink-0 rounded-full border transition-colors cursor-pointer ${darkMode ? "border-transparent" : "border-zinc-200 bg-zinc-200"}`}
                    style={darkMode ? { backgroundColor: activeColor } : undefined}
                  >
                    <span
                      className={`absolute top-1 left-0 h-5 w-5 rounded-full bg-white shadow-sm transition-transform ${darkMode ? "translate-x-5" : "translate-x-1"}`}
                    ></span>
                  </button>
                </div>

                <div className={`h-px ${isDarkTheme ? "bg-white/[0.06]" : "bg-zinc-100"}`} />

                <div>
                  <label className={`block text-sm font-medium mb-1 ${headingClass}`}>{t.thresholdsLabel}</label>
                  <p className={`text-xs mb-4 ${mutedTextClass}`}>{t.thresholdsDesc}</p>

                  {thresholdSaveStatus && <p className={`text-xs mb-3 ${mutedTextClass}`}>{thresholdSaveStatus}</p>}

                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                    {([
                      { key: "mcafee" as const, label: "McAfee (AMCore)" },
                      { key: "clamwin" as const, label: "ClamWin" },
                      { key: "trellix" as const, label: "Trellix" },
                      { key: "symantec" as const, label: "Symantec" },
                    ]).map(({ key, label }) => (
                      <div key={key}>
                        <label className={`block text-xs font-medium mb-1.5 ${mutedTextClass}`}>{label}</label>
                        <input
                          type="number"
                          value={thresholdInputs[key] ?? ""}
                          onChange={(e) => handleThresholdChange(key, e.target.value)}
                          onBlur={() => saveThreshold(key)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") {
                              e.currentTarget.blur();
                            }
                          }}
                          className={`w-full text-sm rounded-none outline-none p-2.5 font-mono border focus:ring-2 focus:ring-offset-0 ${inputClass}`}
                          style={{ ["--tw-ring-color" as string]: activeColor }}
                        />
                      </div>
                    ))}
                  </div>

                  <div className={`mt-5 rounded-none border p-4 ${isDarkTheme ? "border-white/[0.08] bg-white/[0.03]" : "border-zinc-200 bg-white"}`}>
                    <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                      <div className="max-w-2xl">
                        <label htmlFor="ai-fallback-mode" className={`block text-sm font-medium mb-1 ${headingClass}`}>Local Qwen fallback</label>
                        <p className={`text-xs leading-5 ${mutedTextClass}`}>
                          Runs only when OCR cannot resolve an image. An AI-only zero still remains Needs Review.
                        </p>
                        <p className={`mt-1 text-[11px] ${aiStatus?.available ? "text-emerald-500" : "text-amber-600"}`}>
                          {aiStatus?.running ? "Qwen is running" : aiStatus?.available ? "Qwen files detected" : "Runtime/model files not installed"}
                        </p>
                        {aiSaveStatus && <p className={`mt-1 text-[11px] ${mutedTextClass}`}>{aiSaveStatus}</p>}
                      </div>
                      <div className="flex w-full flex-col gap-2 sm:w-auto sm:flex-row">
                        <select
                          id="ai-fallback-mode"
                          value={aiSettings.mode}
                          onChange={(event) => saveAISettings({ mode: event.target.value as AIFallbackMode })}
                          className={`min-w-48 text-sm rounded-none outline-none p-2.5 border ${inputClass}`}
                        >
                          <option value="off">Off</option>
                          <option value="review_only">Unresolved images only</option>
                        </select>
                        <button
                          type="button"
                          onClick={testLocalAI}
                          disabled={aiTesting}
                          className={`px-4 py-2.5 text-xs font-semibold border disabled:opacity-50 ${isDarkTheme ? "border-white/10 hover:bg-white/5" : "border-zinc-200 hover:bg-zinc-50"}`}
                        >
                          {aiTesting ? "Checking..." : "Test Qwen"}
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

        </div>
      </main>

      {/* Audit modal */}
      {selectedLog && (
        <div className="fixed inset-0 bg-black/40 backdrop-blur-sm flex justify-center items-center z-50 p-6" onClick={closeLogSummary}>
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="audit-dialog-title"
            onClick={(e) => e.stopPropagation()}
            className={`rounded-none shadow-2xl w-full max-w-4xl h-5/6 flex flex-col overflow-hidden border ${isDarkTheme ? "bg-[#111114] border-white/[0.08]" : "bg-white border-zinc-200"}`}
          >
            <div className={`px-6 h-14 flex justify-between items-center border-b ${dividerClass}`}>
              <h2 id="audit-dialog-title" className="text-sm font-semibold tracking-tight flex items-center gap-2">
                <span style={{ color: activeColor }}>{t.auditReport}</span>
                <span className={`font-mono font-normal text-xs px-2 py-0.5 rounded-none ${isDarkTheme ? "bg-white/[0.06] text-slate-300" : "bg-zinc-100 text-zinc-600"}`}>
                  {selectedLog.filename}
                </span>
              </h2>
              <button autoFocus aria-label="Close audit report" onClick={closeLogSummary} className={`text-xl leading-none cursor-pointer ${mutedTextClass} hover:${headingClass}`}>
                &times;
              </button>
            </div>

            <div className="p-5 flex-1 overflow-hidden flex flex-col">
              <div className={`rounded-none flex-1 overflow-y-auto p-5 font-mono text-xs leading-relaxed ${isDarkTheme ? "bg-black/40 border border-white/[0.06] text-slate-300" : "bg-zinc-950 text-zinc-300"}`}>
                <pre className="whitespace-pre-wrap">{logSummary}</pre>
              </div>
            </div>

            <div className={`px-6 py-3.5 flex justify-end border-t ${dividerClass}`}>
              <button
                onClick={closeLogSummary}
                className={`px-4 py-2 rounded-none text-xs font-medium transition-colors cursor-pointer ${isDarkTheme ? "bg-white/[0.06] text-slate-200 hover:bg-white/[0.1]" : "bg-zinc-100 hover:bg-zinc-200 text-zinc-700"}`}
              >
                {t.closeWindow}
              </button>
            </div>
          </div>
        </div>
      )}
      {viewingImage && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex justify-center items-center z-50 p-6" onClick={closeLogSummary}>
          <div role="dialog" aria-modal="true" aria-label={`Evidence image: ${viewingImage.name}`} className="relative w-full max-w-6xl max-h-full flex flex-col items-center">

            <button
              onClick={closeLogSummary}
              autoFocus
              aria-label="Close evidence image"
              className="absolute -top-12 right-0 text-white hover:text-rose-400 text-3xl font-bold transition-colors z-50"
            >
              &times;
            </button>

            <div
              className="bg-black rounded-none overflow-hidden shadow-2xl border border-white/20"
              onClick={(e) => e.stopPropagation()} // Prevent clicking the image from closing it
            >
              {imageLoadState === "loading" && (
                <div className="flex min-h-48 min-w-80 items-center justify-center gap-2 p-8 text-sm text-white/80">
                  <Icons.Spinner /> Loading original evidence...
                </div>
              )}
              {imageLoadState === "error" && (
                <div role="alert" className="flex min-h-48 min-w-80 flex-col items-center justify-center gap-3 p-8 text-center text-sm text-white/80">
                  <span>The evidence image could not be loaded.</span>
                  <button
                    type="button"
                    onClick={retryViewingImage}
                    className="rounded-none bg-white/10 px-4 py-2 font-semibold text-white hover:bg-white/20"
                  >Retry</button>
                </div>
              )}
              {/* Raw evidence has unknown dimensions and is intentionally not optimized or transformed. */}
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                key={viewingImage.retry}
                src={`${viewingImage.url}${viewingImage.retry ? `&retry=${viewingImage.retry}` : ""}`}
                alt={viewingImage.name}
                onLoad={() => setImageLoadState("loaded")}
                onError={() => setImageLoadState("error")}
                className={`max-w-full ${viewingImage.log.ai_fallback?.used ? "max-h-[62vh]" : "max-h-[85vh]"} object-contain ${imageLoadState === "error" ? "hidden" : ""}`}
              />
            </div>
            {viewingImage.log.ai_fallback?.used && (
              <section
                aria-label="Qwen analysis"
                className="mt-3 w-full border border-violet-300/30 bg-zinc-950/95 px-4 py-3 text-zinc-200 shadow-xl"
                onClick={(e) => e.stopPropagation()}
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <h3 className="text-sm font-semibold text-violet-300">Qwen analysis</h3>
                  <span className="text-[10px] text-zinc-400">
                    {viewingImage.log.ai_fallback.model || "Local Qwen"}
                    {Number(viewingImage.log.ai_fallback.elapsed_ms) > 0
                      ? ` | ${(Number(viewingImage.log.ai_fallback.elapsed_ms) / 1000).toFixed(1)} seconds`
                      : ""}
                  </span>
                </div>
                <div className="mt-2 grid gap-2 text-xs sm:grid-cols-3">
                  <div>
                    <div className="text-[10px] uppercase tracking-wide text-zinc-500">Threat count</div>
                    <div className="mt-0.5 font-mono">
                      {viewingImage.log.ai_fallback.threat_count === null
                        ? "Not resolved"
                        : viewingImage.log.ai_fallback.threat_count}
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] uppercase tracking-wide text-zinc-500">OCR agreement</div>
                    <div className="mt-0.5">
                      {viewingImage.log.ai_fallback.agreements?.length
                        ? viewingImage.log.ai_fallback.agreements.join(", ")
                        : "None"}
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] uppercase tracking-wide text-zinc-500">Conflicts</div>
                    <div className="mt-0.5">
                      {viewingImage.log.ai_fallback.conflicts?.length
                        ? viewingImage.log.ai_fallback.conflicts.join(", ")
                        : "None"}
                    </div>
                  </div>
                </div>
                <div className="mt-2 border-t border-white/10 pt-2 text-xs">
                  <span className="text-zinc-500">Threat evidence: </span>
                  <span className="font-mono">
                    {viewingImage.log.ai_fallback.threat_evidence || "No labelled numeric evidence returned."}
                  </span>
                </div>
                {viewingImage.log.ai_fallback.threat_count === null && (
                  <p className="mt-2 text-[10px] leading-4 text-amber-300">
                    Qwen did not return a validated number beside a threat label, so this file remains Needs Review.
                  </p>
                )}
              </section>
            )}

            <a
              href={viewingImage.url}
              target="_blank"
              rel="noopener noreferrer"
              className="mt-4 px-4 py-2 bg-white/10 hover:bg-white/20 text-white rounded-none text-sm font-medium transition-colors backdrop-blur-md"
              onClick={(e) => e.stopPropagation()}
            >
              Open Original Image
            </a>

          </div>
        </div>
      )}
    </div>
  );
};

export default Home;
