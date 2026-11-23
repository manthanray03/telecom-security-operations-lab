"""Small helpers shared by the modules."""
from __future__ import annotations

import csv
import math
from datetime import datetime, timedelta
from pathlib import Path

from . import config

TS_FORMAT = "%Y-%m-%d %H:%M:%S"


def parse_ts(value: str) -> datetime:
    """Parse 'YYYY-MM-DD HH:MM:SS' (or ISO with a T) into a naive local datetime."""
    return datetime.fromisoformat(value.strip().replace("T", " "))


def fmt_ts(value: datetime | None) -> str:
    return value.strftime(TS_FORMAT) if value else ""


def read_csv(path: Path) -> list[dict]:
    with Path(path).open(newline="", encoding="utf-8") as fh:
        return [{k: (v or "").strip() for k, v in row.items()} for row in csv.DictReader(fh)]


def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two points in kilometres."""
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = p2 - p1
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def next_run(ts: datetime) -> datetime:
    """Time of the first scheduled rule run at or after ts."""
    step = config.RUN_INTERVAL_MINUTES
    base = ts.replace(second=0, microsecond=0)
    if base < ts:
        base += timedelta(minutes=1)
    remainder = base.minute % step
    if remainder:
        base += timedelta(minutes=step - remainder)
    return base


def is_business_hours(ts: datetime) -> bool:
    return ts.weekday() < 5 and config.BUSINESS_START_HOUR <= ts.hour < config.BUSINESS_END_HOUR


def country_for(number: str) -> tuple[str, str, float, bool]:
    """Return (code, country, rate per minute, high_risk) for a dialled E.164 number."""
    for table, high in ((config.HIGH_RISK_COUNTRIES, True), (config.STANDARD_RATES, False)):
        for code in sorted(table, key=len, reverse=True):
            if number.startswith(code):
                name, rate = table[code]
                return code, name, rate, high
    return "", "Other", 0.10, False


def severity_rank(sev: str) -> int:
    return config.SEVERITIES.index(sev)


def max_severity(*sevs: str) -> str:
    return max(sevs, key=severity_rank)


def bump(sev: str) -> str:
    """One level higher, capped at Critical."""
    i = min(severity_rank(sev) + 1, len(config.SEVERITIES) - 1)
    return config.SEVERITIES[i]


def median(values: list[float]) -> float | None:
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return None
    mid = len(vals) // 2
    return vals[mid] if len(vals) % 2 else (vals[mid - 1] + vals[mid]) / 2
