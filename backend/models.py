"""API request and log response models."""

from typing import Literal, Optional

from pydantic import BaseModel, Field


class Thresholds(BaseModel):
    """Partial settings update; omitted engines remain unchanged."""

    mcafee: Optional[float] = None
    clamwin: Optional[float] = None
    trellix: Optional[float] = None
    symantec: Optional[float] = None
    zero_threat_confidence: Optional[float] = Field(
        default=None,
        ge=0.00,
        le=0.99,
        description="Minimum OCR confidence for accepting an explicit zero-threat result.",
    )
    ocr_strictness: Optional[str] = Field(
        default=None,
        description="Global OCR strictness profile: high, medium, or low.",
    )


class AISettingsUpdate(BaseModel):
    """Partial update for the optional loopback-only local vision fallback."""

    mode: Optional[Literal["off", "review_only"]] = None
    max_image_dimension: Optional[int] = Field(default=None, ge=960, le=2560)
    timeout_seconds: Optional[int] = Field(default=None, ge=30, le=300)


class VerificationDecision(BaseModel):
    path: str
    verdict: str
    reviewer: str = Field(default="", max_length=128)
    reason: str = Field(default="", max_length=1000)


class MonthScanRequest(BaseModel):
    month: str = Field(min_length=1, max_length=64)


class SingleFileScanRequest(BaseModel):
    """Portable evidence token supplied by a row-level Scan button."""

    path: str = Field(min_length=1, max_length=4096)


class LogFile(BaseModel):
    system: str
    filename: str
    status: str
    path: str
    type: str
    dat_version: str = "Unknown"
    last_scan: str = "Unknown"
    is_outdated: bool = False
    checklist_remarks: str = ""
    checklist_dat_version: str = ""
    checklist_date_scan: str = ""
    checklist_virus_found: str = ""
    checklist_av_software: str = ""
    checklist_match: str = "No checklist row"
    checklist_mismatches: list[str] = Field(default_factory=list)
