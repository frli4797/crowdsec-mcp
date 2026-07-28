from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re

_WINDOW_RE = re.compile(r"^(?P<count>\d+)(?P<unit>[mhdw])$")


def parse_window(window: str | None, default: str = "24h") -> timedelta:
    value = window or default
    match = _WINDOW_RE.match(value)
    if not match:
        raise ValueError("window must look like 15m, 6h, 7d, or 2w")
    count = int(match.group("count"))
    unit = match.group("unit")
    if unit == "m":
        return timedelta(minutes=count)
    if unit == "h":
        return timedelta(hours=count)
    if unit == "d":
        return timedelta(days=count)
    return timedelta(weeks=count)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def since_iso(window: str | None, default: str = "24h") -> str:
    return (utc_now() - parse_window(window, default)).isoformat()

