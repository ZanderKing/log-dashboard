"""Small persistence helpers shared by cache and settings stores."""

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Optional


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json_atomic(path: Path, value: Any, *, indent: Optional[int] = None) -> None:
    """Persist JSON without leaving a partially written state file on failure."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_file = path.with_suffix(path.suffix + ".tmp")
    try:
        with open(temporary_file, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, indent=indent, sort_keys=indent is not None)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_file, path)
    finally:
        try:
            temporary_file.unlink(missing_ok=True)
        except OSError:
            pass
