"""OCR geometry, evidence extraction, and conservative audit decisions."""

from collections import Counter
from datetime import date, datetime
from functools import lru_cache
from pathlib import Path
import re
from typing import Callable, Optional

def confidence_threshold() -> float:
    strictness = current_thresholds.get("ocr_strictness", "high")
    if strictness == "low": return 0.40
    if strictness == "medium": return 0.55
    return 0.80

def positive_detection_confidence_threshold() -> float:
    strictness = current_thresholds.get("ocr_strictness", "high")
    if strictness == "low": return 0.55
    if strictness == "medium": return 0.70
    return 0.90

def metadata_context_confidence_threshold() -> float:
    strictness = current_thresholds.get("ocr_strictness", "high")
    if strictness == "low": return 0.00
    if strictness == "medium": return 0.35
    return 0.45
OCR_CONTEXT_GAP = "[OCR CONTEXT GAP]"
OCR_MAG_RATIO = 1.0
OCR_CANVAS_SIZE = 2560
THREAT_RESULT_POSITIVE = "positive"
THREAT_RESULT_ZERO = "explicit_zero"
THREAT_RESULT_UNKNOWN = "unknown"
DEFAULT_ZERO_THREAT_CONFIDENCE = 0.00

current_thresholds: dict[str, float] = {}
month_sort_key: Callable[[str], tuple[int, int]]


def configure_ocr_analysis(
    thresholds: dict[str, float],
    month_key: Callable[[str], tuple[int, int]],
) -> None:
    """Bind the small amount of mutable application state used by parsing."""
    global current_thresholds, month_sort_key
    current_thresholds = thresholds
    month_sort_key = month_key


def extract_with_fail_safe(reader, image_path, *, mag_ratio: float = 1.0):
    return reader.readtext(
        image_path,
        detail=1,
        paragraph=False,
        mag_ratio=mag_ratio,
        canvas_size=OCR_CANVAS_SIZE,
        batch_size=1,
        workers=0,
        text_threshold=0.5,
        low_text=0.3,
    )


def ocr_box_geometry(bbox):
    """Return stable geometry for an EasyOCR quadrilateral, if available."""
    if bbox is None:
        return None
    try:
        xs = [float(point[0]) for point in bbox]
        ys = [float(point[1]) for point in bbox]
    except (TypeError, ValueError, IndexError):
        return None
    if len(xs) < 2 or len(ys) < 2:
        return None
    left, right = min(xs), max(xs)
    top, bottom = min(ys), max(ys)
    return {
        "left": left,
        "right": right,
        "top": top,
        "bottom": bottom,
        "center_y": (top + bottom) / 2,
        "height": max(bottom - top, 1.0),
    }

def build_spatial_ocr_rows(ocr_results):
    """Rebuild visual rows so wrapped/table OCR retains label-value context."""
    boxes = []
    for index, (bbox, text, confidence) in enumerate(ocr_results):
        geometry = ocr_box_geometry(bbox)
        if geometry is None or not str(text).strip():
            continue
        try:
            numeric_confidence = float(confidence)
        except (TypeError, ValueError):
            numeric_confidence = 0.0
        boxes.append({
            "index": index,
            "text": str(text).strip(),
            "confidence": numeric_confidence,
            **geometry,
        })

    if not boxes:
        return []

    rows = []
    for box in sorted(boxes, key=lambda item: (item["center_y"], item["left"])):
        best_row = None
        best_distance = None
        for row in reversed(rows[-6:]):
            distance = abs(box["center_y"] - row["center_y"])
            tolerance = max(3.0, 0.25 * min(box["height"], row["height"]))
            vertical_overlap = max(
                0.0,
                min(box["bottom"], row["bottom"]) - max(box["top"], row["top"]),
            )
            overlap_ratio = vertical_overlap / min(box["height"], row["height"])
            if distance <= tolerance or overlap_ratio >= 0.50:
                if best_distance is None or distance < best_distance:
                    best_row = row
                    best_distance = distance
        if best_row is None:
            rows.append({
                "items": [box],
                "top": box["top"],
                "bottom": box["bottom"],
                "center_y": box["center_y"],
                "height": box["height"],
            })
            continue

        best_row["items"].append(box)
        centers = sorted(item["center_y"] for item in best_row["items"])
        heights = sorted(item["height"] for item in best_row["items"])
        best_row["center_y"] = centers[len(centers) // 2]
        best_row["height"] = heights[len(heights) // 2]
        best_row["top"] = best_row["center_y"] - best_row["height"] / 2
        best_row["bottom"] = best_row["center_y"] + best_row["height"] / 2

    for row in rows:
        row["items"].sort(key=lambda item: (item["left"], item["index"]))
        row["text"] = " ".join(item["text"] for item in row["items"])
    rows.sort(key=lambda row: (row["center_y"], row["items"][0]["left"]))
    return rows

def spatial_row_text(row, minimum_confidence: float = 0.0):
    return " ".join(
        item["text"]
        for item in row.get("items", [])
        if item["confidence"] >= minimum_confidence
    ).strip()

def content_lines(content: str):
    return [" ".join(line.split()) for line in content.splitlines() if line.strip()]


def classify_threat_result(
    *,
    has_positive: bool,
    has_resolved_count: bool,
    has_unresolved_count: bool = False,
    flags=None,
):
    """Return the explicit positive/zero/unknown threat evidence state."""
    if has_positive:
        return THREAT_RESULT_POSITIVE
    if has_resolved_count and not has_unresolved_count and not flags:
        return THREAT_RESULT_ZERO
    return THREAT_RESULT_UNKNOWN


def normalize_ocr_date(value: str):
    """Apply layout-only OCR cleanup; never guess invalid date/time digits."""
    value = " ".join(value.split())
    value = re.sub(
        r'\b(Mon|Tue|Wed|Thu|Fri|Sat|Sun)(?=[A-Za-z]{3}\b)',
        r'\1 ',
        value,
        flags=re.IGNORECASE,
    )
    value = re.sub(r'(\d{1,2})([A-Za-z]{3,9})\b', r'\1 \2', value)
    value = re.sub(r'([A-Za-z]{3,9})(\d{1,2})\b', r'\1 \2', value)
    value = re.sub(r'\b(\d{1,2})/(\d{1,2})(\d{4})\b', r'\1/\2/\3', value)
    value = re.sub(r'\b(\d{1,2}),(\d{1,2})/(\d{4})\b', r'\1/\2/\3', value)
    value = re.sub(r'Time\s*[:;.]?\s*(\d{1,2})[.:](\d{2})[.:](\d{2})', r'\1:\2:\3', value, flags=re.IGNORECASE)
    value = value.strip(' "\'_-`')
    return value

def normalize_clamwin_scan_date(value: str):
    # Repair joined weekday/month text first (for example ``MonJan``). The
    # following rule can then safely split a joined day/time such as
    # ``Jan 1917.42.07`` into ``Jan 19 17.42.07``.
    value = value.replace('`', ' ')
    value = normalize_ocr_date(value)
    value = re.sub(
        r'\b((?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+[A-Za-z]{3}\s+\d{1,2})(\d{1,2}[.:]\d{2})',
        r'\1 \2',
        value,
        flags=re.IGNORECASE,
    )
    value = re.sub(r'(\d{1,2}[.:]\d{2}[.:]\d{2})(\d{4})\b', r'\1 \2', value)
    # Split OCR-joined day and valid hour: "May 1303.15.17" -> "May 13 03.15.17"
    value = re.sub(r'(\d{1,2})(0\d|1\d|2[0-3])[.:](\d{2})[.:](\d{2})', r'\1 \2.\3.\4', value)
    value = re.sub(r'(\d{1,2})(0\d|1\d|2[0-3])[.:](\d{2})', r'\1 \2.\3', value)
    return normalize_ocr_date(value)

def normalize_clamwin_update(value: str):
    value = re.sub(r'(\d{1,2})[.:](\d{2})(\d{1,2}\s+[A-Za-z]+\s+\d{4})', r'\1:\2 \3', value)
    value = re.sub(r'(\d{1,2})[.:](\d{2})\s*(\d{1,2}\s+[A-Za-z]+\s+\d{4})', r'\1:\2 \3', value)
    return normalize_ocr_date(value)

def evidence_period(value: str):
    """Return the folder's (year, month), or (0, 0) without valid context."""
    year, month = month_sort_key(value or "")
    return (year, month) if year >= 2000 and 1 <= month <= 12 else (0, 0)

def validated_time(hour: int, minute: int, second: int, meridiem: str):
    """Validate clock fields and return a 24-hour value, never an OCR guess."""
    if not 0 <= minute <= 59 or not 0 <= second <= 59:
        return None
    marker = re.sub(r'[^APM]', '', (meridiem or '').upper())
    if marker:
        if marker not in {"AM", "PM"} or not 1 <= hour <= 12:
            return None
        if marker == "AM":
            return 0 if hour == 12 else hour
        return 12 if hour == 12 else hour + 12
    return hour if 0 <= hour <= 23 else None

def validated_scan_datetime(value: str, evidence_month: str = ""):
    """Return a canonical timestamp only when every component is defensible.

    Numeric day/month order is accepted only when the selected evidence folder
    resolves the ambiguity. Dates outside that folder are routed to manual
    review rather than being silently presented as valid scan evidence.
    """
    candidate = normalize_ocr_date(value)
    expected_year, expected_month = evidence_period(evidence_month)

    iso_match = re.fullmatch(
        r'(\d{4})[-/](\d{1,2})[-/](\d{1,2})[ T]+'
        r'(\d{1,2})[:.](\d{2})(?:[:.\-](\d{2}))?(?:\.\d+)?Z?',
        candidate,
        re.IGNORECASE,
    )
    text_match = re.fullmatch(
        r'(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+)?'
        r'([A-Za-z]{3,9})\s+(\d{1,2})\s+'
        r'(\d{1,2})[:.](\d{2})(?:[:.\-](\d{2}))?\s+(\d{4})',
        candidate,
        re.IGNORECASE,
    )
    text_day_first = re.fullmatch(
        r'(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+)?'
        r'(\d{1,2})\s+([A-Za-z]{3,9})\s+'
        r'(?:(\d{4})\s+)?'
        r'(\d{1,2})[:.](\d{2})(?:[:.\-](\d{2}))?'
        r'(?:\s+(\d{4}))?',
        candidate,
        re.IGNORECASE,
    )
    numeric_match = re.fullmatch(
        r'(\d{1,2})[/.-](\d{1,2})[/.-](\d{2,4})\s+'
        r'(\d{1,2})[:.](\d{2})(?:[:.\-](\d{2}))?\s*([AP]\.?M\.?)?',
        candidate,
        re.IGNORECASE,
    )
    date_only_match = re.fullmatch(
        r'(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+)?'
        r'(?:(\d{1,2})\s+([A-Za-z]{3,9})|([A-Za-z]{3,9})\s+(\d{1,2}))\s+'
        r'(\d{4})',
        candidate,
        re.IGNORECASE,
    )

    has_seconds = False
    meridiem = ""
    hour_24 = 0
    minute = 0
    second_value = 0

    if iso_match:
        year, month, day, hour, minute, second = iso_match.groups()
        year, month, day = int(year), int(month), int(day)
        has_seconds = second is not None
    elif text_match:
        month_name, day, hour, minute, second, year = text_match.groups()
        try:
            month = datetime.strptime(month_name[:3], "%b").month
        except ValueError:
            return ""
        year, day = int(year), int(day)
        has_seconds = second is not None
    elif text_day_first:
        day_str, month_name, y1, hour, minute, second, y2 = text_day_first.groups()
        try:
            month = datetime.strptime(month_name[:3], "%b").month
        except ValueError:
            return ""
        day = int(day_str)
        year_val = y1 or y2 or (expected_year if expected_year else None)
        if not year_val:
            return ""
        year = int(year_val)
        has_seconds = second is not None
    elif numeric_match:
        first, second_date, year, hour, minute, second, meridiem = numeric_match.groups()
        first, second_date, year = int(first), int(second_date), int(year)
        year = year + 2000 if year < 100 else year
        has_seconds = second is not None

        if expected_month:
            if first == expected_month:
                month, day = first, second_date
            elif second_date == expected_month:
                month, day = second_date, first
            else:
                return ""
        elif first > 12 >= second_date:
            month, day = second_date, first
        elif second_date > 12 >= first:
            month, day = first, second_date
        elif first == second_date and 1 <= first <= 12:
            month, day = first, second_date
        else:
            return ""
    elif date_only_match:
        d1, m1, m2, d2, year_str = date_only_match.groups()
        day = int(d1 or d2)
        month_name = m1 or m2
        try:
            month = datetime.strptime(month_name[:3], "%b").month
        except ValueError:
            return ""
        year = int(year_str)
        hour_24 = 0
        minute = 0
        second_value = 0
    else:
        return ""

    if not date_only_match:
        hour, minute = int(hour), int(minute)
        second_value = int(second) if second is not None else 0
        hour_24 = validated_time(hour, minute, second_value, meridiem)
        if hour_24 is None:
            return ""
    if expected_year and (year != expected_year or month != expected_month):
        return ""
    if not expected_year and not 2000 <= year <= date.today().year + 1:
        return ""

    try:
        parsed = datetime(year, month, day, hour_24, minute, second_value)
    except ValueError:
        return ""
    return parsed.strftime("%Y-%m-%d %H:%M:%S" if has_seconds else "%Y-%m-%d %H:%M" if not date_only_match else "%Y-%m-%d")

def find_date_in_text(value: str, evidence_month: str = ""):
    """Find the first fully valid timestamp near a scan-status marker."""
    normalized = normalize_ocr_date(value)
    date_patterns = [
        r'(?<!\d)\d{4}[-/]\d{1,2}[-/]\d{1,2}[ T]+\d{1,2}[:.]\d{2}(?:[:.\-]\d{2})?(?:\.\d+)?Z?(?!\d)',
        r'(?<!\d)\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}\s+\d{1,2}[:.]\d{2}(?:[:.\-]\d{2})?\s*(?:[AP][\.A-Za-z]{1,2})?(?!\w)',
        r'\b(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+)?[A-Za-z]{3,9}\s+\d{1,2}\s+\d{1,2}[:.]\d{2}(?:[:.\-]\d{2})?\s+\d{4}\b',
        r'\b(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+)?\d{1,2}\s+[A-Za-z]{3,9}\s+(?:\d{4}\s+)?\d{1,2}[:.]\d{2}(?:[:.\-]\d{2})?(?:\s+\d{4})?\b',
        r'\b(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+)?\d{1,2}\s+[A-Za-z]{3,9}\s+\d{4}\b',
        r'\b(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+)?[A-Za-z]{3,9}\s+\d{1,2}\s+\d{4}\b',
    ]
    matches = []
    for pattern in date_patterns:
        matches.extend(re.finditer(pattern, normalized, re.IGNORECASE))
    for match in sorted(matches, key=lambda item: item.start()):
        validated = validated_scan_datetime(match.group(0).strip(), evidence_month)
        if validated:
            return validated
    return ""

def clean_version_value(raw_value: str, minimum: float = 1000.0):
    if re.search(r'\b\d+\s*[.,-]\s*\d+\s*[.,-]\s*\d+\b', raw_value):
        return ""
    value = raw_value.replace('|', ' ').replace(',', '.')
    value = re.sub(r'(?<=\d)\s*\.\s*(?=\d)', '.', value)
    value = re.sub(r'(?<=\d)\s*-\s*(?=\d)', '.', value)

    decimal_match = re.search(r'(?<!\d)(0?\d{4,5})\s*[.,-]\s*(\d{1,4})(?!\d)', value)
    if decimal_match:
        major = decimal_match.group(1).lstrip('0') or '0'
        candidate = f"{major}.{decimal_match.group(2)}"
        if float(candidate) >= minimum:
            return candidate

    split_match = re.search(r'(?<!\d)(0?\d{4,5})\s+(\d{1,4})(?!\d)', value)
    if split_match:
        major = split_match.group(1).lstrip('0') or '0'
        candidate = f"{major}.{split_match.group(2)}"
        if float(candidate) >= minimum:
            return candidate

    whole_match = re.search(r'(?<!\d)(\d{4,6})(?!\d)', value)
    if whole_match:
        digits = whole_match.group(1)
        if len(digits) == 6 and digits.startswith('1') and digits.endswith('0'):
            candidate = f"{digits[:5]}.0"
        else:
            candidate = digits.lstrip('0') or '0'
        if float(candidate) >= minimum:
            return candidate

    return ""

def extract_spatial_dat_version(ocr_results, minimum_confidence: float):
    """Associate DAT/content values with labels by visual row, not OCR order."""
    target_re = re.compile(
        r'(?:\b(?:amcore|a[i1l]?core)|~core)\s+content\s+versi[oc]n\b|\b(?:anti[- ]?virus\s+dat\s+version|dat\s+version)\b',
        re.IGNORECASE,
    )
    nuisance_re = re.compile(
        r'\b(?:scan\s+engine|amcore\s+engine|engine|systemcore|mcafee\s+agent|endpoint\s+security)\s+version\b',
        re.IGNORECASE,
    )
    boxes = []
    for bbox, text, confidence in ocr_results:
        geometry = ocr_box_geometry(bbox)
        if geometry is None:
            continue
        try:
            numeric_confidence = float(confidence)
        except (TypeError, ValueError):
            numeric_confidence = 0.0
        boxes.append({"text": str(text), "confidence": numeric_confidence, **geometry})

    labels = []
    for box in boxes:
        label_type = (
            "target" if target_re.search(box["text"])
            else "nuisance" if nuisance_re.search(box["text"])
            else ""
        )
        if not label_type:
            continue
        labels.append({**box, "label_type": label_type})
        if label_type == "target" and box["confidence"] >= minimum_confidence:
            inline = clean_version_value(target_re.sub("", box["text"]), minimum=1000.0)
            if inline:
                return inline

    assignments = []
    for candidate in boxes:
        if candidate["confidence"] < minimum_confidence:
            continue
        if re.search(r'\b(?:engine|date|time)\b', candidate["text"], re.IGNORECASE):
            continue
        value = clean_version_value(candidate["text"], minimum=1000.0)
        if not value:
            continue
        possible_labels = [
            label for label in labels
            if label["confidence"] >= minimum_confidence
            if candidate["left"] >= label["right"] - 20
            and abs(candidate["center_y"] - label["center_y"])
            <= max(120.0, 3.0 * max(candidate["height"], label["height"]))
        ]
        if not possible_labels:
            continue
        nearest = min(
            possible_labels,
            key=lambda label: (
                abs(candidate["center_y"] - label["center_y"])
                / max(candidate["height"], label["height"]),
                max(0.0, candidate["left"] - label["right"]),
            ),
        )
        if nearest["label_type"] == "target":
            assignments.append((
                abs(candidate["center_y"] - nearest["center_y"])
                / max(candidate["height"], nearest["height"]),
                candidate["left"] - nearest["right"],
                value,
            ))

    if not assignments:
        # Fallback: check joined spatial rows. When OCR splits "AMCore",
        # "content", and "version" into separate boxes, the row text joins them.
        # Only the text after the label match is searched for a version number.
        spatial_rows = build_spatial_ocr_rows(ocr_results)
        for row in spatial_rows:
            label_match = target_re.search(row["text"])
            if not label_match:
                continue
            tail = row["text"][label_match.end():]
            cleaned = clean_version_value(tail, minimum=1000.0)
            if cleaned:
                return cleaned
        return ""

    def assignment_key(item):
        v_dist, h_dist, val = item
        try:
            num = float(val.split()[0])
        except ValueError:
            num = 0.0
        is_valid_dat_range = 1 if 4000 <= num <= 40000 else 0
        precision = 1 if "." in val else 0
        return (-is_valid_dat_range, -precision, v_dist, h_dist)

    return min(assignments, key=assignment_key)[2]

def has_spatial_dat_label(ocr_results, minimum_confidence: float = 0.0):
    """Check individual OCR boxes and joined spatial rows for a DAT label."""
    label_re = re.compile(
        r'(?:\b(?:amcore|a[i1l]?core)|~core)\s+content\s+versi[oc]n\b|\b(?:anti[- ]?virus\s+dat\s+version|dat\s+version)\b',
        re.IGNORECASE,
    )
    for bbox, text, confidence in ocr_results:
        try:
            numeric_confidence = float(confidence)
        except (TypeError, ValueError):
            numeric_confidence = 0.0
        if (
            ocr_box_geometry(bbox) is not None
            and numeric_confidence >= minimum_confidence
            and label_re.search(str(text))
        ):
            return True

    for row in build_spatial_ocr_rows(ocr_results):
        if label_re.search(row["text"]):
            return True
    return False

def _has_non_count_numeric_context(value: str) -> bool:
    """Reject dates, times, and dotted versions as threat-count sources."""
    return bool(
        re.search(
            r"\b\d{1,4}[/-]\d{1,2}[/-]\d{1,4}\b|"
            r"\b\d{1,2}:\d{2}(?::\d{2})?\b|"
            r"\b\d{3,}\.\d+\b",
            str(value),
        )
    )

def _canonical_threat_count_from_line(text: str) -> Optional[str]:
    """Return a count only when it follows a recognised threat label."""
    normalized = re.sub(_DETECTION_OCR_WORD, "detections", str(text), flags=re.IGNORECASE)
    match = _THREAT_LABEL_RE.search(normalized)
    if not match:
        return None
    tail = normalized[match.end():]
    if _has_non_count_numeric_context(tail):
        return None
    if re.fullmatch(r"\s*[:=.\-]?\s*[oO]\s*", tail):
        return "0"
    number_match = re.search(r"(?<![:\d])(\d{1,7})(?![:\d])", tail)
    if not number_match:
        return None
    return str(int(number_match.group(1)))


def _recognize_threat_line_consensus(grayscale, reader) -> Optional[tuple[str, float, str]]:
    """Read one complete row twice and require the same labelled count."""
    import numpy as np
    from PIL import Image, ImageOps

    row_height = max(1, grayscale.height)
    scale = max(2, min(4, round(42 / row_height)))
    grayscale = grayscale.resize(
        (grayscale.width * scale, grayscale.height * scale),
        Image.Resampling.LANCZOS,
    )
    contrast = ImageOps.autocontrast(grayscale)
    variants = (
        contrast,
        contrast.point(lambda pixel: 255 if pixel > 165 else 0),
    )
    agreed = []
    for variant in variants:
        array = np.array(variant)
        results = reader.recognize(
            array,
            horizontal_list=[[0, array.shape[1], 0, array.shape[0]]],
            free_list=[],
            decoder="greedy",
            detail=1,
            paragraph=False,
            contrast_ths=0.05,
            adjust_contrast=0.7,
        )
        if not results:
            return None
        text = " ".join(str(result[1]).strip() for result in results if str(result[1]).strip())
        count = _canonical_threat_count_from_line(text)
        if count is None:
            return None
        confidence = min(float(result[2]) for result in results)
        agreed.append((count, confidence, text))
    if len(agreed) != 2 or agreed[0][0] != agreed[1][0]:
        return None
    confidences = [item[1] for item in agreed]
    if min(confidences) < 0.35:
        return None
    best_text = max(agreed, key=lambda item: item[1])[2]
    return agreed[0][0], sum(confidences) / len(confidences), best_text


def recover_unresolved_threat_digit(
    image_path: str,
    label_left: float,
    label_right: float,
    label_top: float,
    label_bottom: float,
) -> Optional[tuple[str, float]]:
    """Retry the complete label/value row, then the tiny value area.

    Whole-line recognition bypasses word-box detection, which commonly drops a
    small standalone zero. Two independently preprocessed views must agree, and
    an unreadable crop is never treated as zero.
    """
    if not image_path:
        return None
    try:
        import numpy as np
        from PIL import Image, ImageOps
        from ocr_runtime import get_ocr_reader

        img_p = Path(image_path)
        if not img_p.is_file():
            return None
        with Image.open(img_p) as img:
            w, h = img.size
            row_height = max(4.0, label_bottom - label_top)
            reader = get_ocr_reader()

            for padding in (0, max(1, round(row_height * 0.15))):
                crop_top = int(max(0, label_top - padding))
                crop_bottom = int(min(h, label_bottom + padding))
                line_left = int(max(0, label_left - row_height * 0.25))
                line_right = int(min(w, label_right + max(90.0, row_height * 6.0)))
                if line_right > line_left and crop_bottom > crop_top:
                    line = ImageOps.grayscale(
                        img.crop((line_left, crop_top, line_right, crop_bottom))
                    )
                    consensus = _recognize_threat_line_consensus(line, reader)
                    if consensus is not None:
                        count, confidence, _text = consensus
                        return count, confidence

                # Retain a value-only fallback for layouts where the label and
                # value are rendered using substantially different fonts.
                crop_left = int(min(w - 1, max(0, label_right)))
                crop_right = int(min(w, label_right + max(60.0, row_height * 4.0)))
                if crop_right <= crop_left or crop_bottom <= crop_top:
                    continue
                grayscale = ImageOps.grayscale(
                    img.crop((crop_left, crop_top, crop_right, crop_bottom))
                )
                scale = max(2, min(5, round(70 / max(1, grayscale.height))))
                grayscale = grayscale.resize(
                    (grayscale.width * scale, grayscale.height * scale),
                    Image.Resampling.LANCZOS,
                )
                contrast = ImageOps.autocontrast(grayscale)
                agreed = []
                for threshold in (150, 170):
                    variant = contrast.point(lambda pixel, cutoff=threshold: 255 if pixel > cutoff else 0)
                    results = reader.readtext(
                        np.array(variant),
                        detail=1,
                        paragraph=False,
                        allowlist="0123456789Oo",
                        text_threshold=0.15,
                        low_text=0.05,
                    )
                    candidates = []
                    for _bbox, text, confidence in results:
                        clean_text = re.sub(r"^[:=\s]+|\s+$", "", str(text))
                        if re.fullmatch(r"[oO]", clean_text):
                            candidates.append(("0", float(confidence)))
                        elif re.fullmatch(r"\d{1,7}", clean_text):
                            candidates.append((str(int(clean_text)), float(confidence)))
                    values = {value for value, _confidence in candidates}
                    if len(values) != 1:
                        agreed = []
                        break
                    value = next(iter(values))
                    confidence = max(score for candidate, score in candidates if candidate == value)
                    agreed.append((value, confidence))
                if len(agreed) == 2 and agreed[0][0] == agreed[1][0]:
                    return agreed[0][0], min(agreed[0][1], agreed[1][1])
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        return None
    return None

_DETECTION_OCR_WORD = r'd[e3]t[e3]c\s*[t7][i1l]\s*[o0][nr][s5]?'
_THREAT_LABEL_RE = re.compile(
    rf'(infect[e3]d\s+f[i1l]l[e3][s5]|files?\s+(?:with\s+)?{_DETECTION_OCR_WORD}|'
    rf'process(?:es)?\s+detect[e3]d|boot\s+sectors?\s+detect[e3]d|'
    rf'registry\s+{_DETECTION_OCR_WORD}|\b{_DETECTION_OCR_WORD}\s*:?)',
    re.IGNORECASE,
)
_THREAT_IGNORE_RE = re.compile(
    r'(?:number|names|of|0f|0t|signatures?).{0,50}(?:detection|signatures?|extra|dat)|'
    rf'extra\s*dat|{_DETECTION_OCR_WORD}\s+(?:name|help)|^\s*detectioni?\s*$|'
    r'threat\s+prevention|adaptive\s+threat|'
    r'mfetp|odsbl|<\s*SYSTEM\s*>|odsruntask|scanprogress|scan\s+summary',
    re.IGNORECASE,
)

def _isolated_count(value: str) -> Optional[str]:
    cleaned = re.sub(r'^\s*[:=]?\s*|\s*$', '', str(value))
    if re.fullmatch(r'[oO]', cleaned): return "0"
    return cleaned if re.fullmatch(r'\d{1,7}', cleaned) else None
def _has_competing_count_owner(rows, candidate, threat_label) -> bool:
    """Reject a number that aligns more closely with another text label."""
    threat_vertical = abs(candidate["center_y"] - threat_label["center_y"])
    threat_score = (
        threat_vertical / max(candidate["height"], threat_label["height"]),
        max(0.0, candidate["left"] - threat_label["right"]),
    )
    for row in rows:
        for owner in row["items"]:
            if owner["index"] in {candidate["index"], threat_label["index"]}:
                continue
            if owner["confidence"] < 0.25 or not re.search(r"[A-Za-z]{3}", owner["text"]):
                continue
            if _THREAT_LABEL_RE.search(owner["text"]):
                continue
            if owner["right"] > candidate["left"] + 2:
                continue
            vertical_distance = abs(candidate["center_y"] - owner["center_y"])
            if vertical_distance > 0.65 * max(candidate["height"], owner["height"]):
                continue
            horizontal_gap = max(0.0, candidate["left"] - owner["right"])
            if horizontal_gap > max(240.0, owner["height"] * 20.0):
                continue
            owner_score = (
                vertical_distance / max(candidate["height"], owner["height"]),
                horizontal_gap,
            )
            if owner_score < threat_score:
                return True
    return False

_MCAFEE_SUMMARY_ANCHOR_RE = re.compile(
    r"\bmfetp\b|ods\w*[.\s_-]*activity|scan\s+(?:summary|surrary|su[mn]{1,2}ary|summ\w*)",
    re.IGNORECASE,
)


def _adaptive_panel_bounds(row, anchor_items, row_height: float) -> tuple[int, int]:
    """Expand through the anchor's text group and stop at panel whitespace."""
    panel_items = list(anchor_items)
    remaining = [item for item in row["items"] if item not in panel_items]
    gap_limit = max(18.0, row_height * 4.0)
    changed = True
    while changed:
        changed = False
        left = min(item["left"] for item in panel_items)
        right = max(item["right"] for item in panel_items)
        center = sorted(item["center_y"] for item in panel_items)[len(panel_items) // 2]
        for item in list(remaining):
            vertical_distance = abs(item["center_y"] - center)
            if vertical_distance > 0.65 * max(item["height"], row_height):
                continue
            horizontal_gap = max(left - item["right"], item["left"] - right, 0.0)
            if horizontal_gap <= gap_limit:
                panel_items.append(item)
                remaining.remove(item)
                changed = True

    margin = max(8.0, row_height * 1.5)
    return (
        max(0, round(min(item["left"] for item in panel_items) - margin)),
        round(max(item["right"] for item in panel_items) + margin),
    )

def _panel_row_candidates(ocr_results) -> tuple[tuple[int, int, int, int, int], ...]:
    """Return adaptive McAfee panel regions that may contain result rows."""
    rows = build_spatial_ocr_rows(ocr_results)
    if not rows:
        return ()

    # A readable threat label is handled by the cheaper label-bound row retry.
    if any(
        _THREAT_LABEL_RE.search(item["text"])
        for row in rows
        for item in row["items"]
    ):
        return ()

    candidates = []
    seen_vertical_bands = set()
    for row in rows:
        if not _MCAFEE_SUMMARY_ANCHOR_RE.search(row["text"]):
            continue
        anchor_items = [
            item for item in row["items"]
            if _MCAFEE_SUMMARY_ANCHOR_RE.search(item["text"])
            or re.search(r"\bscan\b|su[mn]{1,2}ary|surrary", item["text"], re.IGNORECASE)
        ]
        if not anchor_items:
            continue
        anchor = max(anchor_items, key=lambda item: item["right"] - item["left"])
        row_height = max(6.0, anchor["height"])
        vertical_key = round(anchor["center_y"] / max(4.0, row_height / 2.0))
        if vertical_key in seen_vertical_bands:
            continue
        seen_vertical_bands.add(vertical_key)
        crop_left, crop_right = _adaptive_panel_bounds(row, anchor_items, row_height)
        search_top = max(0, round(anchor["top"] - row_height * 0.50))
        search_bottom = round(anchor["bottom"] + row_height * 3.50)
        if crop_right > crop_left and search_bottom > search_top:
            candidates.append(
                (crop_left, search_top, crop_right, search_bottom, round(row_height))
            )
        if len(candidates) >= 6:
            break
    return tuple(candidates)


def _horizontal_text_bands(grayscale, expected_height: int) -> tuple[tuple[int, int], ...]:
    """Find single visual text lines using row-wise ink density."""
    import numpy as np

    pixels = np.asarray(grayscale)
    if pixels.ndim != 2 or pixels.shape[0] < 3 or pixels.shape[1] < 10:
        return ()
    background = np.percentile(pixels, 90, axis=1, keepdims=True)
    ink = pixels < np.minimum(220, background - 35)
    active = ink.mean(axis=1) > 0.007

    # Bridge one- or two-pixel antialiasing gaps inside the same text line.
    for _pass in range(2):
        for index in range(1, len(active) - 1):
            if not active[index] and active[index - 1] and active[index + 1]:
                active[index] = True

    raw_bands = []
    start = None
    for index, is_active in enumerate(active):
        if is_active and start is None:
            start = index
        if start is not None and (not is_active or index == len(active) - 1):
            end = index if not is_active else index + 1
            height = end - start
            if max(3, expected_height * 0.20) <= height <= expected_height * 1.60:
                raw_bands.append((start, end))
            start = None

    padding = max(2, round(expected_height * 0.18))
    return tuple(
        (max(0, top - padding), min(pixels.shape[0], bottom + padding))
        for top, bottom in raw_bands
    )

@lru_cache(maxsize=512)
def _recover_mcafee_summary_rows_cached(
    image_path: str,
    modified_ns: int,
    file_size: int,
    candidates: tuple[tuple[int, int, int, int, int], ...],
) -> tuple:
    """Read candidate activity rows once per unchanged image and process."""
    del modified_ns, file_size  # They are cache identity, not OCR inputs.
    try:
        from PIL import Image, ImageOps
        from ocr_runtime import get_ocr_reader

        reader = get_ocr_reader()
        with Image.open(image_path) as img:
            width, height = img.size
            rows_examined = 0
            for left, top, right, bottom, expected_height in candidates:
                right = min(width, right)
                bottom = min(height, bottom)
                if right <= left or bottom <= top:
                    continue
                region = ImageOps.grayscale(img.crop((left, top, right, bottom)))
                for band_top, band_bottom in _horizontal_text_bands(region, expected_height):
                    rows_examined += 1
                    line = region.crop((0, band_top, region.width, band_bottom))
                    consensus = _recognize_threat_line_consensus(line, reader)
                    if consensus is not None:
                        count, confidence, _raw_text = consensus
                        original_top = top + band_top
                        original_bottom = top + band_bottom
                        bbox = (
                            (float(left), float(original_top)),
                            (float(right), float(original_top)),
                            (float(right), float(original_bottom)),
                            (float(left), float(original_bottom)),
                        )
                        return (bbox, f"[ROW OCR] Detections: {count}", confidence)
                    if rows_examined >= 12:
                        return ()
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        return ()
    return ()


def recover_mcafee_summary_threat_rows(ocr_results, image_path: str):
    """Recover a missing McAfee threat row from its own panel only."""
    if not image_path:
        return []
    candidates = _panel_row_candidates(ocr_results)
    if not candidates:
        return []
    try:
        image = Path(image_path)
        stats = image.stat()
    except OSError:
        return []
    recovered = _recover_mcafee_summary_rows_cached(
        str(image.resolve()),
        stats.st_mtime_ns,
        stats.st_size,
        candidates,
    )
    return [recovered] if recovered else []

def extract_spatial_threat_findings(
    ocr_results,
    minimum_confidence: float,
    *,
    include_resolution: bool = False,
    image_path: str = "",
    recovery_cache: Optional[dict] = None,
):
    """Resolve threat counts from visual rows, then a small targeted retry."""

    rows = build_spatial_ocr_rows(ocr_results)

    all_row_texts = [spatial_row_text(r, minimum_confidence) for r in rows]
    all_text_lower = "\n".join(all_row_texts).lower()
    explicit_zero_context = bool(
        re.search(
            r'\bnothing\s+found\b|\bno\s+(?:threats?|malware|infections?)\s+found\b|'
            r'\b(?:detections?|threats?)\s*[:=]\s*[0o]\b',
            all_text_lower,
        )
    )
    empty_mcafee_table_context = (
        "clean delete" in all_text_lower
        and "detection name" in all_text_lower
        and "action taken" in all_text_lower
    )

    threats = []
    flags = []
    unresolved_count = False
    resolved_count = explicit_zero_context
    recovery_cache = recovery_cache if recovery_cache is not None else {}

    label_confidence_floor = min(minimum_confidence, 0.25)
    for row in rows:
        label_row_text = spatial_row_text(row, label_confidence_floor)
        if not label_row_text:
            continue
        match = _THREAT_LABEL_RE.search(label_row_text)
        if not match:
            continue

        label_box = next(
            (
                item for item in row["items"]
                if item["confidence"] >= label_confidence_floor
                and (
                    _THREAT_LABEL_RE.search(item["text"])
                    or re.search(r"d[e3]t[e3]c|infect", item["text"], re.IGNORECASE)
                )
            ),
            row["items"][-1],
        )
        if _THREAT_IGNORE_RE.search(label_box["text"]):
            continue
        raw_count = None

        # An inline count is trusted only when the complete label/value text
        # meets this pass's threshold. A weaker label can still be corroborated
        # by a high-confidence neighbouring value or consensus crop below.
        trusted_label_text = (
            label_box["text"]
            if label_box["confidence"] >= minimum_confidence
            else ""
        )
        trusted_match = _THREAT_LABEL_RE.search(trusted_label_text)
        if trusted_match:
            tail = trusted_label_text[trusted_match.end():]
            inline = (
                None
                if _has_non_count_numeric_context(tail)
                else re.search(r'(?<![:\d])(\d{1,7})(?![:\d])', tail)
            )
            if inline and not re.search(r'ignatures?|\$ignatures?|extra\s*dat', tail, re.IGNORECASE):
                raw_count = inline.group(1)
            elif re.fullmatch(r'\s*[:=]?\s*[oO]\s*', tail):
                raw_count = "0"

        # Strict row grouping can place a slightly lower value box into a
        # separate row. Associate only an isolated value after the label and
        # within the same visual row band.
        if raw_count is None:
            nearby_values = []
            for candidate_row in rows:
                for item in candidate_row["items"]:
                    vertical_distance = abs(item["center_y"] - label_box["center_y"])
                    row_band = 0.65 * max(item["height"], label_box["height"])
                    if vertical_distance > row_band:
                        continue
                    if item["confidence"] < minimum_confidence:
                        continue
                    if item["left"] < label_box["right"] - 2:
                        continue
                    horizontal_gap = max(0.0, item["left"] - label_box["right"])
                    if horizontal_gap > max(240.0, label_box["height"] * 20.0):
                        continue
                    value = _isolated_count(item["text"])
                    if value is not None and _has_competing_count_owner(rows, item, label_box):
                        continue
                    if value is not None:
                        nearby_values.append(
                            (
                                vertical_distance,
                                horizontal_gap,
                                -item["confidence"],
                                value,
                                item["confidence"],
                            )
                        )
            if nearby_values:
                _vertical, _horizontal, _negative_confidence, raw_count, _confidence = min(nearby_values)

        # Only unresolved rows pay for a tiny retry. All three confidence
        # passes share the result through this per-image cache.
        if raw_count is None and image_path:
            cache_key = (
                round(label_box["left"]),
                round(label_box["right"]),
                round(label_box["top"]),
                round(label_box["bottom"]),
            )
            if cache_key not in recovery_cache:
                recovery_cache[cache_key] = recover_unresolved_threat_digit(
                    image_path,
                    label_box["left"],
                    label_box["right"],
                    label_box["top"],
                    label_box["bottom"],
                )
            recovered = recovery_cache[cache_key]
            if recovered is not None:
                recovered_count, recovered_confidence = recovered
                if recovered_confidence >= minimum_confidence:
                    raw_count = recovered_count

        if raw_count is None and empty_mcafee_table_context:
            # Table headers are supporting evidence only. This inference is
            # allowed because a threat-count label was also read above.
            raw_count = "0"

        if raw_count is None:
            unresolved_count = True
            continue

        count = int(raw_count)
        resolved_count = True
        if count > 0:
            finding = f"{match.group(1)}: {count}"
            if finding not in threats:
                threats.append(finding)

    if unresolved_count and not resolved_count:
        flags.append(
            "A threat-count label was readable, but its value could not be associated safely."
        )
    unique_flags = list(dict.fromkeys(flags))
    threat_result = classify_threat_result(
        has_positive=bool(threats),
        has_resolved_count=resolved_count,
        has_unresolved_count=unresolved_count,
        flags=unique_flags,
    )
    if include_resolution:
        return threats, unique_flags, threat_result
    return threats, unique_flags

def find_value_near_label(lines, label_pattern: str, minimum: float = 1000.0):
    label_re = re.compile(label_pattern, re.IGNORECASE)
    ignored_re = re.compile(
        r'(number|names).{0,30}(detection|signature|extra)|engine|systemcore|exploit|real protect|adaptive|credential|buffer overflow|access protection',
        re.IGNORECASE,
    )
    candidates = []

    for index, line in enumerate(lines):
        if not label_re.search(line) or ignored_re.search(line):
            continue

        window = " ".join(lines[index:index + 4])
        label_match = label_re.search(window)
        search_area = window[label_match.end():] if label_match else window
        version = clean_version_value(search_area, minimum)
        if version:
            candidates.append(version)

    if not candidates:
        return ""

    def score(version: str):
        try:
            numeric = float(version)
        except ValueError:
            numeric = 0.0
        precision_score = 0
        if re.search(r'\.\d{4}$', version):
            precision_score += 4
        elif re.search(r'\.0$', version):
            precision_score += 2
        if 4000 <= numeric <= 30000:
            precision_score += 1
        return (precision_score, numeric)

    return max(candidates, key=score)

def signature_threshold_for(engine: str):
    threshold = current_thresholds.get(engine, 1.0)
    if engine == "trellix":
        threshold = max(threshold, current_thresholds.get("mcafee", 1.0))
    return threshold

def zero_threat_confidence_threshold():
    """Return the validated setting used only to accept explicit zero results."""
    strictness = current_thresholds.get("ocr_strictness", "high")
    if strictness == "low": return 0.00
    if strictness == "medium": return 0.50
    try:
        threshold = float(current_thresholds.get(
            "zero_threat_confidence", DEFAULT_ZERO_THREAT_CONFIDENCE
        ))
    except (TypeError, ValueError):
        threshold = DEFAULT_ZERO_THREAT_CONFIDENCE
    return min(0.99, max(0.50, threshold))


def signature_number(dat_version: str):
    first_token = dat_version.split(' ')[0]
    clean_version = re.sub(r'[^\d.]', '', first_token)
    if not clean_version:
        return None
    try:
        return float(clean_version)
    except ValueError:
        return None

def find_created_date(lines):
    label_re = re.compile(r'dat\s+cr\w*\s+(?:on|0n)|dat\s+created\s+on', re.IGNORECASE)
    for index, line in enumerate(lines):
        if not label_re.search(line):
            continue
        window = " ".join(lines[index:index + 4])
        window_norm = normalize_ocr_date(window)
        match = re.search(r'\b(\d{1,2}\s+[A-Za-z]{3,9}\s+\d{4}|[A-Za-z]{3,9}\s+\d{1,2}\s+\d{4})\b', window_norm)
        if match:
            return match.group(1)
    return ""

def extract_last_scan(
    lines,
    evidence_month: str = "",
    *,
    require_scan_context: bool = False,
):
    """Extract only a calendar-valid scan timestamp from relevant OCR context."""
    def dates_near_marker(index: int):
        # Prefer the marker line and following OCR lines because UI labels are
        # commonly separated from their values. Only then inspect two lines
        # immediately before the label; a wide window could capture an
        # unrelated definition-update date and create a false scan timestamp.
        nearby_indices = [index]
        for nearby in range(index + 1, min(len(lines), index + 7)):
            if lines[nearby] == OCR_CONTEXT_GAP:
                break
            nearby_indices.append(nearby)
        preceding = []
        for nearby in range(index - 1, max(-1, index - 7), -1):
            if lines[nearby] == OCR_CONTEXT_GAP:
                break
            preceding.append(nearby)
        nearby_indices.extend(preceding)

        found_dates = []
        for nearby in nearby_indices:
            candidate = lines[nearby]
            variants = [candidate]
            # EasyOCR sometimes emits AM/PM as its own box. Join only a pure
            # meridiem neighbor so unrelated text cannot alter the timestamp.
            if nearby + 1 < len(lines) and re.fullmatch(
                r'\s*[AP]\.?M\.?\s*', lines[nearby + 1], re.IGNORECASE
            ):
                variants.insert(0, f"{candidate} {lines[nearby + 1]}")
            for variant in variants:
                found = find_date_in_text(variant, evidence_month)
                if found:
                    found_dates.append(found)
                    break
        return found_dates

    def date_for_latest_marker(marker):
        marker_indices = [
            index for index, line in enumerate(lines) if marker.search(line)
        ]
        if not marker_indices:
            return False, ""
        candidates = dates_near_marker(marker_indices[-1])
        if not candidates:
            return True, ""
        return True, max(candidates, key=datetime.fromisoformat)

    joined = "\n".join(lines)
    authoritative_dates = []
    for context_block in joined.split(OCR_CONTEXT_GAP):
        for last_full_match in re.finditer(
            r'last\s+full\s+scan.*?\(([^)]*?\d{1,2}[/-]\d{1,2}[/-]\d{2,4}[^)]*)\)',
            context_block,
            re.IGNORECASE | re.DOTALL,
        ):
            found = find_date_in_text(last_full_match.group(1), evidence_month)
            if found:
                authoritative_dates.append(found)
    if authoritative_dates:
        return max(authoritative_dates, key=datetime.fromisoformat)

    last_scan_markers = re.compile(
        r'last\s+(?:full\s+)?scan\b|scan\s+date|date\s+scanned',
        re.IGNORECASE,
    )
    complete_markers = re.compile(
        r'scan\s+comp(?:l|[\]\|i1])?ete(?:d)?',
        re.IGNORECASE,
    )
    summary_markers = re.compile(
        r'scan\s+su[mn]{1,2}ary|full\s+scan|quick\s+scan|\bodsbl\.ods\.activity\b|scanned\s*:?|scan\s+stopped|scan\s+resumed|scan\s+paused|scan\s+started|on-demand\s+scan|amcore|content\s+version',
        re.IGNORECASE,
    )

    # Explicit "last scan" wording is authoritative. Otherwise prefer a
    # completion event, then a scan summary. Generic engines do not treat
    # started, paused, or stopped scans as evidence of a completed review.
    for marker in (last_scan_markers, complete_markers, summary_markers):
        marker_present, found = date_for_latest_marker(marker)
        if marker_present:
            if not found:
                created_dt = find_created_date(lines)
                if created_dt:
                    found = find_date_in_text(created_dt, evidence_month)
                if not found:
                    for line in lines:
                        found_candidate = find_date_in_text(line, evidence_month)
                        if found_candidate:
                            found = found_candidate
                            break
            return found or "Unknown"

    # OCR screenshots must tie the timestamp to scan wording. Structured text
    # and PDF reports may legitimately present scan dates in table rows.
    if not require_scan_context:
        for line in lines:
            found = find_date_in_text(line, evidence_month)
            if found:
                return found

    full_text_lower = "\n".join(lines).lower()
    if (
        "nothing found" in full_text_lower
        or "no threats found" in full_text_lower
        or "no malware found" in full_text_lower
        or re.search(r'\bnothing\s+found\b|\bno\s+(?:threats?|malware|infections?)\s+found\b', full_text_lower)
    ):
        created_dt = find_created_date(lines)
        if created_dt:
            found = find_date_in_text(created_dt, evidence_month)
            if found:
                return found
        for line in lines:
            found_candidate = find_date_in_text(line, evidence_month)
            if found_candidate:
                return found_candidate

    return "Unknown"

def extract_epo_threat_event_total(lines):
    """Read an ePO threat-events report only from its explicit final total."""
    report_text = "\n".join(lines)
    if not re.search(r'\bnumber\s+of\s+threat\s+events\b', report_text, re.IGNORECASE):
        return None, []

    totals = []
    total_pattern = re.compile(
        r'^total(?:\s+number\s+of\s+threat\s+events)?\s*[:=]?\s*(\d{1,9})$',
        re.IGNORECASE,
    )
    for line in lines:
        match = total_pattern.fullmatch(line.strip())
        if match:
            totals.append(int(match.group(1)))

    if not totals:
        return None, [
            "An ePO threat-events report was detected, but its Total value was unreadable."
        ]
    unique_totals = set(totals)
    if len(unique_totals) != 1:
        return None, [
            "The ePO threat-events report contains inconsistent Total values."
        ]
    return totals[0], []


def extract_threat_findings(
    lines,
    *,
    include_result: bool = False,
    allow_wrapped_positive: bool = False,
):
    """Extract threat counts and preserve a positive/zero/unknown state."""
    threats = []
    flags = []
    full_text_lower = "\n".join(lines).lower()
    resolved_count = bool(
        any(phrase in full_text_lower for phrase in ["nothing found", "no threats found", "no malware found", "no infection found", "no infections found", "no threat found"])
        or bool(re.search(r'\bnothing\s+found\b|\bno\s+(?:threats?|malware|infections?)\s+found\b|\bdetections?\s*:\s*0\b|\bthreats?\s*:\s*0\b', full_text_lower))
    )
    unresolved_count = False
    label_pattern = _THREAT_LABEL_RE
    ignore_pattern = _THREAT_IGNORE_RE

    epo_total, epo_flags = extract_epo_threat_event_total(lines)
    flags.extend(epo_flags)
    if epo_total is not None:
        resolved_count = True
        if epo_total > 0:
            threats.append(f"Number of Threat Events: {epo_total}")
    elif epo_flags:
        unresolved_count = True

    for index, line in enumerate(lines):
        normalized = line
        normalized = re.sub(r'\b[I\[\|]+(?=infected|detections)', '', normalized, flags=re.IGNORECASE)
        normalized = re.sub(_DETECTION_OCR_WORD, 'detections', normalized, flags=re.IGNORECASE)
        normalized = re.sub(r'f(?:ue|i)les?\s+w(?:i|r)?th', 'Files with', normalized, flags=re.IGNORECASE)
        lower_line = normalized.lower()

        if (
            ("malware found" in lower_line or "threat detected" in lower_line)
            and "threat prevention" not in lower_line
            and "no threat detected" not in lower_line
        ):
            threats.append(f"Keyword Flagged: '{line}'")
            continue

        if ignore_pattern.search(normalized) or not label_pattern.search(normalized):
            continue

        match = label_pattern.search(normalized)
        tail = normalized[match.end():] if match else normalized
        count_source = tail.strip()
        same_line_value = bool(re.search(r'\d|\b[oO]\b', count_source))

        # Structured text/PDF extraction commonly wraps a table value onto the
        # next line. OCR without geometry remains conservative: a separated
        # positive is review evidence, never an automatically confirmed threat.
        if not same_line_value and index + 1 < len(lines):
            next_line = lines[index + 1].strip()
            separated_value = re.fullmatch(r'[:=\s]*([0-9oO]{1,7})\s*', next_line)
            if separated_value and (
                allow_wrapped_positive
                or not re.search(r'[1-9]', separated_value.group(1))
            ):
                count_source = next_line
            elif separated_value:
                unresolved_count = True
                flags.append(
                    f"A separated possible positive count near '{match.group(1)}' requires review."
                )
                continue
            else:
                unresolved_count = True
                flags.append(
                    f"A threat-count label was readable, but its value was unresolved: '{match.group(1)}'."
                )
                continue

        if not count_source:
            unresolved_count = True
            flags.append(
                f"A threat-count label was readable, but its value was unresolved: '{match.group(1)}'."
            )
            continue

        if re.search(r'[:=\s]*[oO]\s*$', count_source):
            count_source = "0"

        number_match = (
            None
            if _has_non_count_numeric_context(count_source)
            else re.search(r'(?<!\d)(\d{1,7})(?!\d)', count_source)
        )
        if not number_match:
            unresolved_count = True
            flags.append(
                f"A threat-count label was readable, but its value was unresolved: '{match.group(1)}'."
            )
            continue

        count = int(number_match.group(1))
        resolved_count = True
        if count > 0:
            threats.append(f"{match.group(1)}: {count}")

    threats = list(dict.fromkeys(threats))
    flags = list(dict.fromkeys(flags))
    threat_result = classify_threat_result(
        has_positive=bool(
            [finding for finding in threats if not finding.startswith("Keyword Flagged:")]
        ),
        has_resolved_count=resolved_count,
        has_unresolved_count=unresolved_count,
        flags=flags,
    )
    if include_result:
        return threats, flags, threat_result
    return threats, flags

def infer_av_engine(system_name: str, content: str = ""):
    """Apply the project antivirus mapping before conservative keyword fallback."""
    lower_content = str(content).lower()
    if system_name == "RADIO":
        return "clamwin"
    if system_name in {"CCTV", "EPM", "INFO"}:
        return "mcafee"
    if "clamwin" in lower_content or "clam win" in lower_content:
        return "clamwin"
    if "symantec" in lower_content:
        return "symantec"
    if "trellix" in lower_content:
        return "trellix"
    return "mcafee"

# Note: Added system_name as an argument to enforce AV mapping rules
def extract_metadata(
    content: str,
    system_name: str = "",
    evidence_month: str = "",
    *,
    require_scan_context: bool = False,
):
    dat_version = "Unknown"
    last_scan = "Unknown"
    is_outdated = False
    lines = content_lines(content)
    joined_lines = "\n".join(lines)
    lower_content = joined_lines.lower()

    # --- ENFORCE SYSTEM/AV MAPPING RULES ---
    engine = infer_av_engine(system_name, lower_content)

    if engine == "clamwin":
        for index, line in enumerate(lines):
            if re.search(r'scan\s+started', line, re.IGNORECASE):
                raw_scan = normalize_clamwin_scan_date(
                    re.sub(r'.*?scan\s+started\s*[:;.]?\s*', '', line, flags=re.IGNORECASE)
                )
                last_scan = find_date_in_text(raw_scan, evidence_month) or "Unknown"
                break

        daily_match = re.search(r'Virus\s+DB\s+Version:.*?daily\s*[:;]?\s*(\d+)', joined_lines, re.IGNORECASE | re.DOTALL)
        daily_value = daily_match.group(1) if daily_match and int(daily_match.group(1)) >= 1000 else ""
        update_match = re.search(r'Updated:\s*([^\n]+)', joined_lines, re.IGNORECASE)
        update_value = normalize_clamwin_update(update_match.group(1)) if update_match else ""
        if daily_value and update_value:
            dat_version = f"{daily_value} (Updated: {update_value})"
        elif daily_value:
            dat_version = daily_value
        elif update_value:
            dat_version = f"Updated: {update_value}"

    elif engine == "symantec":
        dat_match = re.search(r'(?:Definitions|Defs?|Version)[\s:=]+([\d.]+)', joined_lines, re.IGNORECASE)
        if dat_match:
            dat_version = dat_match.group(1).strip()
        last_scan = extract_last_scan(
            lines,
            evidence_month,
            require_scan_context=require_scan_context,
        )

    else:
        label_pattern = r'(?:amcore|amcorc|amc0re|mcore|m"core|~"?core|"core|acore|akcore|axcore|antore|core)\s+content\s+vers\w*|(?:anti[- ]?virus|antvirus|dit|dat)\s+(?:dat\s+)?ver\w*|dat\s+v(?:ersion|acion|ersicn)'
        dat_version = find_value_near_label(lines, label_pattern)
        if (dat_version == "Unknown" or not dat_version) and not require_scan_context:
            fallback = re.search(r'\b([456789]\d{3}[.,-]\d+)\b', joined_lines)
            if fallback:
                dat_version = fallback.group(1).replace(',', '.').replace('-', '.')
        if not dat_version:
            # Conservative OCR/PDF decisions require a labelled DAT value; an
            # arbitrary four-digit table total or engine version is not enough.
            dat_version = "Unknown"

        created_date = find_created_date(lines)
        if dat_version != "Unknown" and created_date:
            dat_version += f" ({created_date})"
        last_scan = extract_last_scan(
            lines,
            evidence_month,
            require_scan_context=require_scan_context,
        )
        if extract_epo_threat_event_total(lines)[0] is not None:
            if not any(re.search(r'last\s+(?:full\s+)?scan|scan\s+date|date\s+scanned|scan\s+completed?|completed', line, re.IGNORECASE) for line in lines):
                last_scan = "Unknown"

    threshold = signature_threshold_for(engine)
    version_number = signature_number(dat_version)
    if version_number is not None:
        is_outdated = version_number < threshold

    return dat_version, last_scan, is_outdated

def apply_signature_status(status: str, is_outdated: bool):
    """Outdated signatures are displayed as a UI warning (is_outdated flag).

    Files with clean scans and older DAT versions no longer require a manual
    review — the operator can see the outdated indicator and decide.
    """
    return status

def apply_evidence_quality_status(
    status: str,
    last_scan: str,
    dat_version: str = "Unknown",
    *,
    require_dat: bool = False,
):
    """A clean verdict requires a defensible scan timestamp and DAT version."""
    if current_thresholds.get("ocr_strictness") in ("low", "medium"):
        return status
    if status == "Clean" and (
        last_scan == "Unknown" or (require_dat and dat_version == "Unknown")
    ):
        return "Manual Verification Needed"
    return status

def analyze_and_audit(ocr_results, system_name: str = "", evidence_month: str = "", image_path: str = ""):
    # Keep every OCR line in the transcript, but only let sufficiently reliable
    # text drive automated metadata and threat decisions. Ambiguous positive
    # evidence is deliberately escalated for human review instead of being
    # reported as a confirmed threat.
    ocr_results = list(ocr_results)
    recovered_rows = recover_mcafee_summary_threat_rows(ocr_results, image_path)
    if recovered_rows:
        ocr_results.extend(recovered_rows)
    recognized_lines = []
    for _bbox, text, confidence in ocr_results:
        try:
            numeric_confidence = float(confidence)
        except (TypeError, ValueError):
            numeric_confidence = 0.0
        recognized_lines.append((str(text), numeric_confidence))

    spatial_rows = build_spatial_ocr_rows(ocr_results)
    raw_lines = (
        [row["text"] for row in spatial_rows]
        if spatial_rows
        else [text for text, _confidence in recognized_lines]
    )
    normalized_lines = content_lines("\n".join(raw_lines))

    # Candidate matches from weaker OCR are review flags only. A confirmed
    # positive requires the higher positive-detection confidence threshold.
    (
        generic_candidate_threats,
        generic_candidate_flags,
        generic_candidate_result,
    ) = extract_threat_findings(normalized_lines, include_result=True)
    if spatial_rows:
        threat_recovery_cache = {}
        (
            spatial_candidate_threats,
            candidate_flags,
            spatial_candidate_result,
        ) = extract_spatial_threat_findings(
            ocr_results,
            0.0,
            include_resolution=True,
            image_path=image_path,
            recovery_cache=threat_recovery_cache,
        )
        candidate_threat_result = spatial_candidate_result
        candidate_threats = spatial_candidate_threats + [
            finding for finding in generic_candidate_threats
            if finding.startswith("Keyword Flagged:")
        ]
        trusted_findings, trusted_flags, trusted_threat_result = extract_spatial_threat_findings(
            ocr_results,
            positive_detection_confidence_threshold(),
            include_resolution=True,
            image_path=image_path,
            recovery_cache=threat_recovery_cache,
        )
        _zero_findings, _zero_flags, zero_threat_result = extract_spatial_threat_findings(
            ocr_results,
            zero_threat_confidence_threshold(),
            include_resolution=True,
            image_path=image_path,
            recovery_cache=threat_recovery_cache,
        )
        if trusted_threat_result != THREAT_RESULT_POSITIVE and zero_threat_result == THREAT_RESULT_ZERO:
            trusted_threat_result = THREAT_RESULT_ZERO
    else:
        candidate_threat_result = generic_candidate_result
        candidate_threats = generic_candidate_threats
        candidate_flags = generic_candidate_flags
        trusted_threat_text = "\n".join(
            text
            for text, confidence in recognized_lines
            if confidence >= positive_detection_confidence_threshold()
        )
        (
            trusted_findings,
            trusted_flags,
            trusted_threat_result,
        ) = extract_threat_findings(
            content_lines(trusted_threat_text),
            include_result=True,
        )
        zero_threat_text = "\n".join(
            text
            for text, confidence in recognized_lines
            if confidence >= zero_threat_confidence_threshold()
        )
        _zero_findings, _zero_flags, zero_threat_result = extract_threat_findings(
            content_lines(zero_threat_text),
            include_result=True,
        )
        if trusted_threat_result != THREAT_RESULT_POSITIVE and zero_threat_result == THREAT_RESULT_ZERO:
            trusted_threat_result = THREAT_RESULT_ZERO

    # A zero accepted at the configured zero-confidence threshold resolves the
    # count even when the same row is below the stricter positive threshold.
    # Keep unrelated parser flags, but do not make the accepted zero review
    # itself merely because it was not strong enough to confirm a positive.
    if trusted_threat_result == THREAT_RESULT_ZERO:
        trusted_flags = [
            flag
            for flag in trusted_flags
            if flag != "A threat-count label was readable, but its value could not be associated safely."
        ]

    # Keyword-only matches are useful leads but are not sufficiently specific
    # for a critical-system confirmed alert. Only an explicit positive count
    # on trusted OCR can cross the automated positive-verdict boundary.
    keyword_candidates = [
        finding for finding in candidate_threats if finding.startswith("Keyword Flagged:")
    ]
    threats = [
        finding for finding in trusted_findings if not finding.startswith("Keyword Flagged:")
    ]
    confirmed_threats = set(threats)
    uncertain_threats = [
        threat
        for threat in candidate_threats
        if threat not in confirmed_threats and not threat.startswith("Keyword Flagged:")
    ]
    flags = list(
        dict.fromkeys(
            candidate_flags
            + trusted_flags
            + [
                f"Keyword-only possible threat requires review: {finding}"
                for finding in keyword_candidates
            ]
            + [
                f"Low-confidence possible threat requires review: {threat}"
                for threat in uncertain_threats
            ]
        )
    )
    if not threats and trusted_threat_result != THREAT_RESULT_ZERO:
        flags.append("No explicit, resolved zero-threat outcome was extracted.")
    if current_thresholds.get("ocr_strictness") in ("low", "medium"):
        status = "Threats Found" if threats else "Clean"
    else:
        status = (
            "Threats Found"
            if threats
            else "Clean"
            if trusted_threat_result == THREAT_RESULT_ZERO and not flags
            else "Manual Verification Needed"
        )

    raw_text = "\n".join(raw_lines)
    metadata_context_re = re.compile(
        r'last\s+(?:full\s+|quick\s+)?scan|scan\s+(?:started|stopped|comp(?:l|[\]\|i1])?ete(?:d)?|su[mn]{1,2}ary)|scan\s+date|date\s+scanned',
        re.IGNORECASE,
    )
    trusted_metadata_parts = []
    if spatial_rows:
        for row in spatial_rows:
            row_text = row["text"]
            marker_confidence = max(
                (item["confidence"] for item in row["items"]),
                default=0.0,
            )
            threshold = (
                metadata_context_confidence_threshold()
                if metadata_context_re.search(row_text)
                and marker_confidence >= metadata_context_confidence_threshold()
                else confidence_threshold()
            )
            trusted_text = spatial_row_text(row, threshold)
            if trusted_text:
                trusted_metadata_parts.append(trusted_text)
    else:
        trusted_metadata_indices = {
            index
            for index, (_text, confidence) in enumerate(recognized_lines)
            if confidence >= confidence_threshold()
        }
        metadata_bridge_indices = set()
        for index, (text, confidence) in enumerate(recognized_lines):
            if (
                confidence >= metadata_context_confidence_threshold()
                and metadata_context_re.search(text)
            ):
                # Preserve a small sequential neighborhood for legacy OCR
                # cache entries that predate stored bounding-box coordinates.
                for nearby in range(max(0, index - 6), min(len(recognized_lines), index + 7)):
                    if recognized_lines[nearby][1] >= metadata_context_confidence_threshold():
                        trusted_metadata_indices.add(nearby)
                    else:
                        metadata_bridge_indices.add(nearby)
        metadata_output_indices = trusted_metadata_indices | metadata_bridge_indices
        previous_index = None
        for index in sorted(metadata_output_indices):
            if previous_index is not None and index != previous_index + 1:
                trusted_metadata_parts.append(OCR_CONTEXT_GAP)
            trusted_metadata_parts.append(
                recognized_lines[index][0]
                if index in trusted_metadata_indices
                else "[LOW CONFIDENCE OCR]"
            )
            previous_index = index
    trusted_metadata_text = "\n".join(trusted_metadata_parts)
    dat_version, last_scan, is_outdated = extract_metadata(
        trusted_metadata_text,
        system_name,
        evidence_month,
        require_scan_context=True,
    )
    if spatial_rows and system_name != "RADIO":
        spatial_dat_version = extract_spatial_dat_version(
            ocr_results,
            metadata_context_confidence_threshold(),
        )
        spatial_label_confirmed = has_spatial_dat_label(
            ocr_results,
            metadata_context_confidence_threshold(),
        )
        spatial_label_present = has_spatial_dat_label(ocr_results, 0.0)
        if spatial_label_present and not spatial_label_confirmed:
            # A fuzzy/low-confidence DAT label blocks the generic numeric
            # fallback from promoting nearby Windows or engine versions.
            dat_version = "Unknown"
            is_outdated = False
        if spatial_label_confirmed:
            dat_version = spatial_dat_version or "Unknown"
            is_outdated = False
        if spatial_dat_version:
            dat_version = spatial_dat_version
            lower_metadata = trusted_metadata_text.lower()
            if system_name in ["CCTV", "EPM", "INFO"]:
                spatial_engine = "mcafee"
            elif "symantec" in lower_metadata:
                spatial_engine = "symantec"
            elif "trellix" in lower_metadata:
                spatial_engine = "trellix"
            else:
                spatial_engine = "mcafee"
            version_number = signature_number(dat_version)
            is_outdated = (
                version_number is not None
                and version_number < signature_threshold_for(spatial_engine)
            )
        spatial_number = signature_number(dat_version)
        if spatial_number is not None and (
            1900 <= spatial_number <= 2100 or spatial_number > 50000
        ):
            # Calendar years and five/six-digit table totals are common near
            # scan metadata and are not plausible non-ClamWin content versions
            # in this evidence set.
            dat_version = "Unknown"
            is_outdated = False

    # Preserve useful low-confidence metadata as a clearly labelled candidate
    # instead of discarding it. Candidates are never used for signature
    # threshold decisions or a clean verdict until stronger evidence exists.
    raw_dat_version, _raw_last_scan, _raw_outdated = extract_metadata(
        raw_text,
        system_name,
        evidence_month,
        require_scan_context=True,
    )
    if spatial_rows and system_name != "RADIO":
        raw_spatial_dat = extract_spatial_dat_version(ocr_results, 0.0)
        if has_spatial_dat_label(ocr_results):
            raw_dat_version = raw_spatial_dat or "Unknown"
        raw_spatial_number = signature_number(raw_dat_version)
        if raw_spatial_number is not None and (
            1900 <= raw_spatial_number <= 2100 or raw_spatial_number > 50000
        ):
            raw_dat_version = "Unknown"
    timestamp_counts = Counter(
        timestamp
        for text in raw_lines
        if (timestamp := find_date_in_text(text, evidence_month))
    )
    review_details = {
        "dat_version_candidate": "",
        "last_scan_candidate": "",
        "verification_reasons": [],
        "date_evidence_count": 0,
        "threat_result": trusted_threat_result,
        "threat_result_candidate": candidate_threat_result,
        "av_engine": infer_av_engine(system_name, raw_text),
    }
    review_details["verification_reasons"].extend(flags)
    if dat_version.startswith("Updated:") and signature_number(dat_version) is None:
        review_details["verification_reasons"].append(
            "A ClamWin update date was found, but the numeric daily signature version was unreadable."
        )
        status = "Threats Found" if threats else "Manual Verification Needed"
    if dat_version == "Unknown" and raw_dat_version != "Unknown":
        review_details["dat_version_candidate"] = raw_dat_version
        review_details["verification_reasons"].append(
            "DAT version was found in lower-confidence OCR and needs confirmation."
        )
    elif dat_version == "Unknown":
        review_details["verification_reasons"].append(
            "No confirmed DAT/signature version was extracted."
        )

    # If the visually latest scan event itself is below the contextual trust
    # floor, an older readable timestamp must not be presented as "last".
    # Route the screenshot to review and keep the timestamp unknown instead.
    if system_name == "RADIO":
        decision_marker_re = re.compile(r'scan\s+started', re.IGNORECASE)
    else:
        decision_marker_re = re.compile(
            r'last\s+(?:full\s+)?scan\b|scan\s+(?:comp(?:l|[\]\|i1])?ete(?:d)?|su[mn]{1,2}ary)',
            re.IGNORECASE,
        )
    if spatial_rows:
        decision_markers = [
            (
                index,
                max((item["confidence"] for item in row["items"]), default=0.0),
            )
            for index, row in enumerate(spatial_rows)
            if decision_marker_re.search(row["text"])
        ]
    else:
        decision_markers = [
            (index, confidence)
            for index, (text, confidence) in enumerate(recognized_lines)
            if decision_marker_re.search(text)
        ]

    # Repeated identical timestamps across a scan summary are strong evidence
    # even when one individual OCR box has a modest confidence score. Requiring
    # three repetitions plus a trusted scan marker recovers dense activity-log
    # screenshots without accepting a lone content-update or desktop-clock date.
    consensus_dates = [
        timestamp for timestamp, count in timestamp_counts.items() if count >= 3
    ]
    consensus_date = (
        max(consensus_dates, key=datetime.fromisoformat) if consensus_dates else ""
    )
    consensus_used = bool(
        consensus_date
        and decision_markers
        and max(confidence for _index, confidence in decision_markers)
        >= metadata_context_confidence_threshold()
    )
    if consensus_used:
        last_scan = consensus_date
        review_details["date_evidence_count"] = timestamp_counts[consensus_date]

    if (
        decision_markers
        and decision_markers[-1][1] < metadata_context_confidence_threshold()
        and not consensus_used
    ):
        last_scan = "Unknown"
        flags.append(
            "The latest scan event label has low OCR confidence; verify its timestamp manually."
        )
        review_details["verification_reasons"].append(
            "The latest scan event label has low OCR confidence."
        )
        status = "Threats Found" if threats else "Manual Verification Needed"

    if last_scan == "Unknown" and timestamp_counts:
        candidate = max(timestamp_counts, key=datetime.fromisoformat)
        review_details["last_scan_candidate"] = candidate
        review_details["date_evidence_count"] = timestamp_counts[candidate]
        review_details["verification_reasons"].append(
            "A valid date was found, but it could not be confirmed as the completed scan time."
        )
    elif last_scan == "Unknown":
        review_details["verification_reasons"].append(
            "No calendar-valid completed-scan timestamp was extracted."
        )

    summary_parts = []
    if threats:
        summary_parts.append("--- 🚨 CONFIRMED THREAT ALERTS ---")
        for threat in threats:
            summary_parts.append(threat)
        summary_parts.append("")
    if flags:
        summary_parts.append("--- 🔍 MANUAL VERIFICATION REQUIRED ---")
        for flag in flags:
            summary_parts.append(flag)
        summary_parts.append("")
    if last_scan == "Unknown":
        summary_parts.append("--- VALID SCAN DATE REQUIRES MANUAL VERIFICATION ---")
        summary_parts.append(
            "No timestamp passed calendar, clock, and evidence-month validation."
        )
        summary_parts.append("")

    summary_parts.append("--- RAW OCR TEXT TRANSCRIPT ---")
    summary_parts.append(raw_text)

    status = apply_evidence_quality_status(
        status,
        last_scan,
        dat_version,
        require_dat=True,
    )
    status = apply_signature_status(status, is_outdated)

    if is_outdated:
        summary_parts.insert(0, "--- SIGNATURE THRESHOLD ACTION REQUIRED ---")
        summary_parts.insert(1, f"Reported signature {dat_version} is below the configured minimum threshold.")
        summary_parts.insert(2, "")

    return (
        status,
        "\n".join(summary_parts),
        dat_version,
        last_scan,
        is_outdated,
        review_details,
    )

def fast_ocr_has_complete_evidence(
    ocr_results,
    system_name: str,
    evidence_month: str,
):
    """Accept native-resolution OCR only when every dashboard field is strong."""
    if not ocr_results or any(
        float(confidence) < confidence_threshold()
        for _bbox, _text, confidence in ocr_results
    ) or not all(
        ocr_box_geometry(bbox) is not None for bbox, _text, _confidence in ocr_results
    ):
        return False

    _threats, threat_flags, positive_result = extract_spatial_threat_findings(
        ocr_results,
        positive_detection_confidence_threshold(),
        include_resolution=True,
    )
    _zero_threats, _zero_flags, zero_result = extract_spatial_threat_findings(
        ocr_results,
        zero_threat_confidence_threshold(),
        include_resolution=True,
    )
    resolved_result = (
        positive_result if positive_result == THREAT_RESULT_POSITIVE
        else THREAT_RESULT_ZERO if zero_result == THREAT_RESULT_ZERO
        else THREAT_RESULT_UNKNOWN
    )
    if resolved_result == THREAT_RESULT_UNKNOWN or threat_flags:
        return False

    (
        _status,
        _summary,
        dat_version,
        last_scan,
        _is_outdated,
        review_details,
    ) = analyze_and_audit(ocr_results, system_name, evidence_month)
    if dat_version == "Unknown" or last_scan == "Unknown":
        return False
    if review_details.get("dat_version_candidate") or review_details.get("last_scan_candidate"):
        return False
    return not review_details.get("verification_reasons")


def analyze_text_content(content: str, system_name: str = "", evidence_month: str = ""):
    threats, flags, threat_result = extract_threat_findings(
        content_lines(content),
        include_result=True,
        allow_wrapped_positive=True,
    )
    if current_thresholds.get("ocr_strictness") in ("low", "medium"):
        status = "Threats Found" if threats else "Clean"
    else:
        status = (
            "Threats Found"
            if threats
            else "Clean"
            if threat_result == THREAT_RESULT_ZERO and not flags
            else "Manual Verification Needed"
        )
    dat_version, last_scan, is_outdated = extract_metadata(
        content,
        system_name,
        evidence_month,
        require_scan_context=True,
    )
    status = apply_evidence_quality_status(
        status,
        last_scan,
        dat_version,
        require_dat=True,
    )
    return apply_signature_status(status, is_outdated), dat_version, last_scan, is_outdated
