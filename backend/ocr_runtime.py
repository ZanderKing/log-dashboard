"""RAM-aware, quantized EasyOCR runtime and adaptive magnification policy."""

from __future__ import annotations

import os
from pathlib import Path
import sys
import threading
from typing import Any, Optional


OCR_FAST_MAG_RATIO = 1.0
OCR_MAG_RATIO = 1.0
OCR_CANVAS_SIZE = 2560
OCR_MODEL_FILENAMES = ("craft_mlt_25k.pth", "english_g2.pth")


def get_ocr_model_directory():
    """Return the local model directory without using a user profile."""
    configured = os.getenv("SECURITY_CENTER_OCR_MODEL_DIR", "").strip()
    if configured:
        return Path(configured).resolve()
    return Path(__file__).resolve().parent / "easyocr_models"


def missing_ocr_models():
    model_dir = get_ocr_model_directory()
    return [name for name in OCR_MODEL_FILENAMES if not (model_dir / name).is_file()]


def ocr_models_available():
    return not missing_ocr_models()

reader_lock = threading.Lock()


def get_total_physical_memory_bytes():
    """Return installed RAM without adding a deployment dependency."""
    if sys.platform == "win32":
        try:
            import ctypes

            class MemoryStatus(ctypes.Structure):
                _fields_ = [
                    ("length", ctypes.c_ulong),
                    ("memory_load", ctypes.c_ulong),
                    ("total_physical", ctypes.c_ulonglong),
                    ("available_physical", ctypes.c_ulonglong),
                    ("total_page_file", ctypes.c_ulonglong),
                    ("available_page_file", ctypes.c_ulonglong),
                    ("total_virtual", ctypes.c_ulonglong),
                    ("available_virtual", ctypes.c_ulonglong),
                    ("available_extended_virtual", ctypes.c_ulonglong),
                ]

            status = MemoryStatus()
            status.length = ctypes.sizeof(status)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return int(status.total_physical)
        except (AttributeError, OSError, ValueError):
            pass
    try:
        return int(os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE"))
    except (AttributeError, OSError, ValueError):
        return 0

def choose_ocr_worker_count(total_memory_bytes: int):
    """Use one inference on 8 GB PCs and at most two on 16 GB PCs."""
    return 2 if total_memory_bytes >= 12 * 1024**3 else 1

def choose_ocr_magnification_plan(max_dimension: int, strictness: str = "high"):
    """Always use native 1.0x ratio."""
    return (1.0,)

def get_ocr_magnification_plan(file_path: Path):
    return (1.0,)


def configured_integer(name: str, default: int, minimum: int, maximum: int):
    try:
        return min(maximum, max(minimum, int(os.getenv(name, str(default)))))
    except ValueError:
        return default

OCR_TOTAL_MEMORY_BYTES = get_total_physical_memory_bytes()
OCR_MAX_WORKERS = configured_integer(
    "SECURITY_CENTER_OCR_WORKERS",
    choose_ocr_worker_count(OCR_TOTAL_MEMORY_BYTES),
    1,
    2,
)
OCR_TORCH_THREADS = configured_integer(
    "SECURITY_CENTER_TORCH_THREADS",
    min(8, max(1, (os.cpu_count() or 1) // OCR_MAX_WORKERS)),
    1,
    8,
)

reader: Optional[Any] = None
def get_ocr_reader():
    """Load one quantized CPU reader using only verified bundled model files."""
    global reader
    with reader_lock:
        if reader is None:
            model_dir = get_ocr_model_directory()
            missing = missing_ocr_models()
            if missing:
                raise RuntimeError(
                    "EasyOCR models are missing: " + ", ".join(missing)
                    + ". Run prepare_ocr_models.py before offline deployment."
                )
            import warnings
            warnings.filterwarnings("ignore", category=UserWarning)
            warnings.filterwarnings("ignore", message=".*quantize_per_tensor.*")
            warnings.filterwarnings("ignore", message=".*pin_memory.*")
            import easyocr
            import torch

            torch.set_num_threads(OCR_TORCH_THREADS)
            reader = easyocr.Reader(
                ["en"],
                gpu=False,
                quantize=True,
                verbose=False,
                model_storage_directory=str(model_dir),
                download_enabled=False,
            )
    return reader
