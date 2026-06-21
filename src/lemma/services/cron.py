"""A minimal, dependency-free 5-field cron evaluator (Refs #111).

Backs the scheduled "pull" execution model for connectors: ``lemma connector
run`` reads the ``schedule`` field of a ``lemma_connector_config.yaml`` and
fires the connector when the schedule is due. Keeping this in-tree avoids
adding ``croniter`` as a runtime dependency for a deliberately small feature.

Supported syntax per field: ``*``, single values, ``a-b`` ranges, ``a,b,c``
lists, and ``*/n`` / ``a-b/n`` steps. Fields are the standard five:

    minute(0-59) hour(0-23) day-of-month(1-31) month(1-12) day-of-week(0-6)

Day-of-week is Sunday=0, and 7 is also accepted for Sunday. When both
day-of-month and day-of-week are restricted (neither is ``*``), a timestamp
matches if **either** field matches — the long-standing Vixie-cron rule.
Named months/weekdays and macros like ``@hourly`` are intentionally not
supported; use the numeric form.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime as _datetime
from datetime import timedelta

_FIELD_BOUNDS = {
    "minute": (0, 59),
    "hour": (0, 23),
    "dom": (1, 31),
    "month": (1, 12),
    "dow": (0, 6),
}
_FIELD_ORDER = ("minute", "hour", "dom", "month", "dow")

# Safety bound on next_after's minute-by-minute scan (just over 4 years),
# so an unsatisfiable schedule raises instead of looping forever.
_MAX_SCAN_MINUTES = 366 * 4 * 24 * 60


def _parse_field(spec: str, field: str) -> frozenset[int]:
    low, high = _FIELD_BOUNDS[field]
    allowed: set[int] = set()

    for part in spec.split(","):
        part = part.strip()
        if not part:
            msg = f"Empty term in cron {field} field."
            raise ValueError(msg)

        step = 1
        if "/" in part:
            base, _, step_str = part.partition("/")
            try:
                step = int(step_str)
            except ValueError as exc:
                msg = f"Invalid step '{step_str}' in cron {field} field."
                raise ValueError(msg) from exc
            if step <= 0:
                msg = f"Step must be positive in cron {field} field."
                raise ValueError(msg)
        else:
            base = part

        if base == "*":
            start, end = low, high
        elif "-" in base:
            start_str, _, end_str = base.partition("-")
            start, end = _as_int(start_str, field), _as_int(end_str, field)
        else:
            start = end = _as_int(base, field)

        # Day-of-week: accept 7 as Sunday and normalize to 0.
        if field == "dow":
            start = 0 if start == 7 else start
            end = 0 if end == 7 else end

        if start > end:
            msg = f"Range start {start} exceeds end {end} in cron {field} field."
            raise ValueError(msg)
        if start < low or end > high:
            msg = f"Value out of range ({low}-{high}) in cron {field} field: '{part}'."
            raise ValueError(msg)

        allowed.update(range(start, end + 1, step))

    return frozenset(allowed)


def _as_int(token: str, field: str) -> int:
    try:
        return int(token)
    except ValueError as exc:
        msg = f"Invalid value '{token}' in cron {field} field."
        raise ValueError(msg) from exc


@dataclass(frozen=True)
class CronSchedule:
    """A parsed 5-field cron expression."""

    minutes: frozenset[int]
    hours: frozenset[int]
    doms: frozenset[int]
    months: frozenset[int]
    dows: frozenset[int]
    dom_restricted: bool
    dow_restricted: bool

    @classmethod
    def parse(cls, expression: str) -> CronSchedule:
        fields = expression.split()
        if len(fields) != 5:
            msg = (
                f"Cron expression must have 5 fields "
                f"(minute hour day-of-month month day-of-week), got {len(fields)}: "
                f"'{expression}'."
            )
            raise ValueError(msg)

        parsed = {name: _parse_field(fields[i], name) for i, name in enumerate(_FIELD_ORDER)}
        return cls(
            minutes=parsed["minute"],
            hours=parsed["hour"],
            doms=parsed["dom"],
            months=parsed["month"],
            dows=parsed["dow"],
            dom_restricted=fields[2].strip() != "*",
            dow_restricted=fields[4].strip() != "*",
        )

    def matches(self, dt: _datetime) -> bool:
        """Whether ``dt`` (minute resolution) satisfies the schedule."""
        if dt.minute not in self.minutes:
            return False
        if dt.hour not in self.hours:
            return False
        if dt.month not in self.months:
            return False

        # cron weekday: Sunday=0..Saturday=6; Python weekday(): Monday=0..Sunday=6.
        cron_dow = (dt.weekday() + 1) % 7
        dom_ok = dt.day in self.doms
        dow_ok = cron_dow in self.dows

        if self.dom_restricted and self.dow_restricted:
            # Vixie-cron "or" semantics when both are restricted.
            return dom_ok or dow_ok
        return dom_ok and dow_ok

    def next_after(self, dt: _datetime) -> _datetime:
        """The first matching minute strictly after ``dt``."""
        candidate = (dt + timedelta(minutes=1)).replace(second=0, microsecond=0)
        for _ in range(_MAX_SCAN_MINUTES):
            if self.matches(candidate):
                return candidate
            candidate += timedelta(minutes=1)
        msg = "No matching time found within the scan horizon for this cron schedule."
        raise ValueError(msg)
