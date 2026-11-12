"""Small, dependency-free formatting helpers shared across the project."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional


def format_ts(ts: Optional[float], with_tz: bool = True) -> str:
    """Convert a Unix epoch timestamp (seconds, float) to a readable UTC string.

    Args:
        ts: Seconds since 1970-01-01 UTC, as reported by PyShark's
            ``packet.sniff_timestamp``. ``None`` means "no such packet".
        with_tz: Append the literal " UTC" suffix when True.

    Returns:
        A string such as ``2026-11-12 10:41:03.482 UTC`` or ``N/A`` for None.
    """
    if ts is None:
        return "N/A"
    # We always render in UTC so the output is identical on every machine and
    # can be compared to Wireshark when its View > Time Display Format is set to UTC.
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    # strftime's %f gives microseconds (6 digits); slicing [:-3] keeps milliseconds.
    text = dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    return f"{text} UTC" if with_tz else text


def format_duration(seconds: Optional[float]) -> str:
    """Render a duration in seconds as a compact human-readable string.

    Args:
        seconds: Duration in seconds (may be fractional) or None.

    Returns:
        ``"0.482 s"`` for sub-minute values, ``"3 min 12.4 s"`` for longer ones,
        or ``"N/A"`` when the input is None.
    """
    if seconds is None:
        return "N/A"
    if seconds < 60:
        return f"{seconds:.3f} s"
    # divmod splits the value into whole minutes and the remaining seconds.
    minutes, rest = divmod(seconds, 60)
    if minutes < 60:
        return f"{int(minutes)} min {rest:.1f} s"
    hours, minutes = divmod(minutes, 60)
    return f"{int(hours)} h {int(minutes)} min {rest:.0f} s"
