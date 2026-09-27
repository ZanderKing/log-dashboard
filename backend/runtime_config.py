"""Minimal environment-file loading for source deployments."""

from __future__ import annotations

import os
from pathlib import Path
import re


ENV_KEY_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
MAX_ENV_LINE_LENGTH = 8192


def load_environment_file(path: Path) -> int:
    """Load simple KEY=VALUE entries without overriding the process environment."""
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except FileNotFoundError:
        return 0
    except OSError:
        return 0

    loaded = 0
    for raw_line in lines:
        if len(raw_line) > MAX_ENV_LINE_LENGTH:
            continue
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not ENV_KEY_PATTERN.fullmatch(key):
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        if "\x00" in value:
            continue
        if key not in os.environ:
            os.environ[key] = value
            loaded += 1
    return loaded
