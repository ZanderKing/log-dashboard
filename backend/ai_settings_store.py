"""Persistent settings for the optional local vision-model fallback."""

from __future__ import annotations

import json
from pathlib import Path
import threading

from storage import write_json_atomic


AI_SETTINGS_FILE = Path("ai_settings.json")
ai_settings_lock = threading.Lock()
DEFAULT_AI_SETTINGS = {
    "mode": "off",
    "max_image_dimension": 1600,
    "timeout_seconds": 120,
}
current_ai_settings: dict[str, object] = DEFAULT_AI_SETTINGS.copy()


def _validated_settings(value) -> dict[str, object]:
    source = value if isinstance(value, dict) else {}
    mode = source.get("mode", DEFAULT_AI_SETTINGS["mode"])
    if mode not in {"off", "review_only"}:
        mode = DEFAULT_AI_SETTINGS["mode"]
    try:
        max_dimension = int(source.get("max_image_dimension", 1600))
    except (TypeError, ValueError):
        max_dimension = 1600
    try:
        timeout_seconds = int(source.get("timeout_seconds", 120))
    except (TypeError, ValueError):
        timeout_seconds = 120
    return {
        "mode": mode,
        "max_image_dimension": min(2560, max(960, max_dimension)),
        "timeout_seconds": min(300, max(30, timeout_seconds)),
    }


def configure_ai_settings_store(base_dir: Path) -> None:
    global AI_SETTINGS_FILE
    AI_SETTINGS_FILE = base_dir / "ai_settings.json"
    loaded = DEFAULT_AI_SETTINGS.copy()
    try:
        if AI_SETTINGS_FILE.is_file():
            with open(AI_SETTINGS_FILE, "r", encoding="utf-8") as handle:
                loaded = _validated_settings(json.load(handle))
    except (OSError, json.JSONDecodeError):
        loaded = DEFAULT_AI_SETTINGS.copy()
    current_ai_settings.clear()
    current_ai_settings.update(loaded)


def validate_ai_settings_update(updates: dict[str, object]) -> dict[str, object]:
    unknown = set(updates).difference(DEFAULT_AI_SETTINGS)
    if unknown:
        raise ValueError("Unknown local AI setting: " + ", ".join(sorted(unknown)))
    combined = current_ai_settings.copy()
    combined.update(updates)
    validated = _validated_settings(combined)
    for key, value in updates.items():
        if validated[key] != value:
            if key == "mode" and value in {"off", "review_only"}:
                continue
            if key in {"max_image_dimension", "timeout_seconds"}:
                try:
                    if int(value) == validated[key]:
                        continue
                except (TypeError, ValueError):
                    pass
            raise ValueError(f"Invalid local AI setting: {key}")
    return {key: validated[key] for key in updates}


def save_ai_settings() -> None:
    write_json_atomic(AI_SETTINGS_FILE, current_ai_settings, indent=2)