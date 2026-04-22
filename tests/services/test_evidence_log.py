"""Tests for the append-only EvidenceLog."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path


def _compliance_payload(uid: str = "evt-1", when: datetime | None = None) -> dict:
    when = when or datetime.now(UTC)
    return {
        "class_uid": 2003,
        "class_name": "Compliance Finding",
        "category_uid": 2000,
        "category_name": "Findings",
        "type_uid": 200301,
        "activity_id": 1,
        "time": when.isoformat(),
        "metadata": {
            "version": "1.3.0",
            "product": {"name": "Lemma"},
            "uid": uid,
        },
    }


def _auth_payload(uid: str = "auth-1", when: datetime | None = None) -> dict:
    when = when or datetime.now(UTC)
    return {
        "class_uid": 3002,
        "class_name": "Authentication",
        "category_uid": 3000,
        "category_name": "IAM",
        "type_uid": 300201,
        "activity_id": 1,
        "time": when.isoformat(),
        "metadata": {
            "version": "1.3.0",
            "product": {"name": "Okta"},
            "uid": uid,
        },
    }


def test_append_writes_one_line_and_read_all_round_trips(tmp_path: Path):
    from lemma.models.ocsf import ComplianceFinding
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.ocsf_normalizer import normalize

    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    event = normalize(_compliance_payload())

    wrote = log.append(event)

    assert wrote is True
    files = list((tmp_path / ".lemma" / "evidence").glob("*.jsonl"))
    assert len(files) == 1
    assert len(files[0].read_text().strip().splitlines()) == 1

    out = log.read_all()
    assert len(out) == 1
    assert isinstance(out[0], ComplianceFinding)
    assert out[0].metadata["uid"] == "evt-1"


def test_evidence_log_is_append_only(tmp_path: Path):
    from lemma.services.evidence_log import EvidenceLog

    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    assert not hasattr(log, "update")
    assert not hasattr(log, "delete")
    assert not hasattr(log, "clear")


def test_read_all_returns_events_across_files_in_chronological_order(tmp_path: Path):
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.ocsf_normalizer import normalize

    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    yesterday = datetime.now(UTC) - timedelta(days=1)
    today = datetime.now(UTC)

    event_yesterday = normalize(_compliance_payload("y-1", when=yesterday))
    event_today = normalize(_compliance_payload("t-1", when=today))

    # Append out-of-order to prove sort is by file name, not insertion order
    log.append(event_today)
    log.append(event_yesterday)

    files = sorted((tmp_path / ".lemma" / "evidence").glob("*.jsonl"))
    assert len(files) == 2  # one file per UTC date

    out = log.read_all()
    assert [e.metadata["uid"] for e in out] == ["y-1", "t-1"]


def test_append_dedupes_by_metadata_uid(tmp_path: Path):
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.ocsf_normalizer import normalize

    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    event = normalize(_compliance_payload("dup-1"))

    assert log.append(event) is True
    assert log.append(event) is False  # second call is a no-op

    files = list((tmp_path / ".lemma" / "evidence").glob("*.jsonl"))
    assert len(files[0].read_text().strip().splitlines()) == 1


def test_append_content_hash_dedupe_when_uid_absent(tmp_path: Path):
    """Producers that don't set metadata.uid fall back to content-hash dedupe."""
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.ocsf_normalizer import normalize

    payload = _compliance_payload()
    del payload["metadata"]["uid"]

    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    event = normalize(payload)

    assert log.append(event) is True
    assert log.append(event) is False

    files = list((tmp_path / ".lemma" / "evidence").glob("*.jsonl"))
    assert len(files[0].read_text().strip().splitlines()) == 1


def test_filter_by_class_and_time_range(tmp_path: Path):
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.ocsf_normalizer import normalize

    log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    t_early = datetime(2026, 4, 20, 12, 0, 0, tzinfo=UTC)
    t_mid = datetime(2026, 4, 21, 12, 0, 0, tzinfo=UTC)
    t_late = datetime(2026, 4, 22, 12, 0, 0, tzinfo=UTC)

    log.append(normalize(_compliance_payload("c-early", when=t_early)))
    log.append(normalize(_compliance_payload("c-late", when=t_late)))
    log.append(normalize(_auth_payload("a-mid", when=t_mid)))

    # filter_by_class
    compliance = log.filter_by_class(2003)
    assert {e.metadata["uid"] for e in compliance} == {"c-early", "c-late"}
    auth = log.filter_by_class(3002)
    assert {e.metadata["uid"] for e in auth} == {"a-mid"}
    assert log.filter_by_class(9999) == []

    # filter_by_time_range — half-open [start, end)
    window = log.filter_by_time_range(t_early, t_late)
    assert {e.metadata["uid"] for e in window} == {"c-early", "a-mid"}
