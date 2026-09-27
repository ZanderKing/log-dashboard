"""Launch the source checkout for local development.

Auto-installs missing dependencies and builds the frontend on first run.
OCR remains a user-triggered operation — no background watcher.
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import urlopen
import webbrowser


ROOT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = ROOT_DIR / "backend"
FRONTEND_DIR = ROOT_DIR / "frontend"
BACKEND_URL = "http://127.0.0.1:8000/api/health"
FRONTEND_URL = "http://127.0.0.1:3000"
STARTUP_TIMEOUT_SECONDS = 60


def ensure_backend_deps() -> None:
    print("Checking Python dependencies...")
    try:
        import fastapi  # noqa: F401
    except ImportError:
        print("  Installing backend dependencies...")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
            cwd=BACKEND_DIR,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(result.stderr, file=sys.stderr)
            raise RuntimeError("Failed to install backend dependencies.")
        print("  Done.")


def ensure_frontend_deps() -> None:
    if not (FRONTEND_DIR / "node_modules").is_dir():
        print("Installing frontend dependencies...")
        npm = "npm.cmd" if os.name == "nt" else "npm"
        result = subprocess.run(
            [npm, "ci"],
            cwd=FRONTEND_DIR,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(result.stderr, file=sys.stderr)
            raise RuntimeError("Failed to install frontend dependencies.")
        print("  Done.")


def ensure_ocr_models() -> None:
    models_dir = BACKEND_DIR / "easyocr_models"
    required = ("craft_mlt_25k.pth", "english_g2.pth")
    if all((models_dir / name).is_file() for name in required):
        return
    print("Downloading OCR models (one-time)...")
    result = subprocess.run(
        [sys.executable, "-c",
         "from easyocr import Reader; "
         "r = Reader(['en'], gpu=False, download_enabled=True); "
         "del r"],
        cwd=BACKEND_DIR,
    )
    if result.returncode != 0:
        print("  Warning: could not download EasyOCR models automatically.", file=sys.stderr)
        print("  Run prepare_ocr_models.py or place the model files in backend/easyocr_models/", file=sys.stderr)


def wait_until_ready(url: str, process: subprocess.Popen, label: str) -> None:
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"{label} stopped during startup (exit {process.returncode}).")
        try:
            with urlopen(url, timeout=2) as response:
                if response.status < 500:
                    return
        except (OSError, URLError):
            time.sleep(0.4)
    raise TimeoutError(f"{label} did not become ready within {STARTUP_TIMEOUT_SECONDS} seconds.")


def stop_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def run_local_app() -> int:
    npm_command = "npm.cmd" if os.name == "nt" else "npm"
    processes: list[subprocess.Popen] = []

    print("Starting Security Center...")

    try:
        ensure_backend_deps()
        ensure_frontend_deps()
        ensure_ocr_models()

        backend = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "main:app",
                "--host",
                "127.0.0.1",
                "--port",
                "8000",
                "--reload",
            ],
            cwd=BACKEND_DIR,
        )
        processes.append(backend)

        frontend = subprocess.Popen(
            [npm_command, "run", "dev", "--", "--hostname", "127.0.0.1"],
            cwd=FRONTEND_DIR,
        )
        processes.append(frontend)

        wait_until_ready(BACKEND_URL, backend, "Backend")
        wait_until_ready(FRONTEND_URL, frontend, "Frontend")
        webbrowser.open(FRONTEND_URL)

        print("\nSecurity Center is running. Press Ctrl+C to stop.")
        while all(process.poll() is None for process in processes):
            time.sleep(0.5)
        failed = next(process for process in processes if process.poll() is not None)
        raise RuntimeError(f"A service stopped unexpectedly (exit {failed.returncode}).")
    except KeyboardInterrupt:
        print("\nStopping...")
        return 0
    except (OSError, RuntimeError, TimeoutError) as exc:
        print(f"\nStartup failed: {exc}", file=sys.stderr)
        return 1
    finally:
        for process in reversed(processes):
            stop_process(process)


if __name__ == "__main__":
    raise SystemExit(run_local_app())
