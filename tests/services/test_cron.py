"""Tests for the minimal 5-field cron evaluator (Refs #111)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest


def _dt(y=2026, mo=6, d=20, h=12, mi=0):
    return datetime(y, mo, d, h, mi, tzinfo=UTC)


class TestParse:
    def test_rejects_wrong_field_count(self):
        from lemma.services.cron import CronSchedule

        with pytest.raises(ValueError, match=r"(?i)5 fields|five fields"):
            CronSchedule.parse("* * * *")

    def test_rejects_out_of_range(self):
        from lemma.services.cron import CronSchedule

        with pytest.raises(ValueError, match=r"(?i)range|invalid"):
            CronSchedule.parse("99 * * * *")

    def test_rejects_garbage(self):
        from lemma.services.cron import CronSchedule

        with pytest.raises(ValueError):
            CronSchedule.parse("@hourly")


class TestMatches:
    def test_every_minute_matches_any(self):
        from lemma.services.cron import CronSchedule

        sched = CronSchedule.parse("* * * * *")
        assert sched.matches(_dt(mi=37, h=3))

    def test_specific_minute_hour(self):
        from lemma.services.cron import CronSchedule

        sched = CronSchedule.parse("30 6 * * *")  # 06:30 daily
        assert sched.matches(_dt(h=6, mi=30))
        assert not sched.matches(_dt(h=6, mi=31))
        assert not sched.matches(_dt(h=7, mi=30))

    def test_step_values(self):
        from lemma.services.cron import CronSchedule

        sched = CronSchedule.parse("*/15 * * * *")  # every 15 minutes
        assert sched.matches(_dt(mi=0))
        assert sched.matches(_dt(mi=15))
        assert sched.matches(_dt(mi=45))
        assert not sched.matches(_dt(mi=20))

    def test_list_and_range(self):
        from lemma.services.cron import CronSchedule

        sched = CronSchedule.parse("0 9-17 * * 1,2,3,4,5")  # top of hour, business hrs, Mon-Fri
        # 2026-06-22 is a Monday.
        assert sched.matches(_dt(y=2026, mo=6, d=22, h=9, mi=0))
        assert sched.matches(_dt(y=2026, mo=6, d=22, h=17, mi=0))
        assert not sched.matches(_dt(y=2026, mo=6, d=22, h=8, mi=0))
        # 2026-06-20 is a Saturday → excluded.
        assert not sched.matches(_dt(y=2026, mo=6, d=20, h=10, mi=0))

    def test_day_of_week_sunday_both_0_and_7(self):
        from lemma.services.cron import CronSchedule

        # 2026-06-21 is a Sunday.
        sunday = _dt(y=2026, mo=6, d=21, h=0, mi=0)
        assert CronSchedule.parse("0 0 * * 0").matches(sunday)
        assert CronSchedule.parse("0 0 * * 7").matches(sunday)


class TestNextAfter:
    def test_next_after_advances_to_following_match(self):
        from lemma.services.cron import CronSchedule

        sched = CronSchedule.parse("30 6 * * *")
        nxt = sched.next_after(_dt(h=6, mi=30))  # strictly after the current match
        assert nxt == _dt(y=2026, mo=6, d=21, h=6, mi=30)

    def test_next_after_within_same_hour(self):
        from lemma.services.cron import CronSchedule

        sched = CronSchedule.parse("*/15 * * * *")
        assert sched.next_after(_dt(mi=2)) == _dt(mi=15)

    def test_next_after_is_strict(self):
        from lemma.services.cron import CronSchedule

        sched = CronSchedule.parse("* * * * *")
        # Even when the current minute matches, next_after returns the *next* minute.
        assert sched.next_after(_dt(mi=0)) == _dt(mi=1)
