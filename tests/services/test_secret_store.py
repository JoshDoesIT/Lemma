"""Tests for the encrypted connector secret store (Refs #117)."""

from __future__ import annotations

from pathlib import Path

import pytest


def _store(tmp_path: Path, passphrase: str = "correct horse battery staple"):
    from lemma.services.secret_store import SecretStore

    return SecretStore(tmp_path / ".lemma" / "secrets.json", passphrase=passphrase)


class TestRoundTrip:
    def test_set_then_get_returns_value(self, tmp_path: Path):
        store = _store(tmp_path)
        store.set("GITHUB_TOKEN", "ghp_supersecret")
        assert store.get("GITHUB_TOKEN") == "ghp_supersecret"

    def test_get_missing_returns_none(self, tmp_path: Path):
        store = _store(tmp_path)
        assert store.get("NOPE") is None

    def test_set_overwrites_rotates_value(self, tmp_path: Path):
        store = _store(tmp_path)
        store.set("TOK", "old")
        store.set("TOK", "new")
        assert store.get("TOK") == "new"

    def test_names_lists_without_values(self, tmp_path: Path):
        store = _store(tmp_path)
        store.set("A", "1")
        store.set("B", "2")
        assert sorted(store.names()) == ["A", "B"]

    def test_delete_removes_secret(self, tmp_path: Path):
        store = _store(tmp_path)
        store.set("A", "1")
        store.delete("A")
        assert store.get("A") is None
        assert store.names() == []

    def test_persists_across_instances(self, tmp_path: Path):
        _store(tmp_path).set("TOK", "persisted")
        # A fresh instance over the same file + passphrase reads it back.
        assert _store(tmp_path).get("TOK") == "persisted"


class TestEncryptionAtRest:
    def test_plaintext_secret_absent_from_file_bytes(self, tmp_path: Path):
        store = _store(tmp_path)
        store.set("TOK", "ghp_plaintext_should_not_appear")

        raw = (tmp_path / ".lemma" / "secrets.json").read_bytes()
        assert b"ghp_plaintext_should_not_appear" not in raw
        # The secret name is also not stored in plaintext (whole map is encrypted).
        assert b"TOK" not in raw

    def test_wrong_passphrase_raises_clear_error(self, tmp_path: Path):
        _store(tmp_path, passphrase="right").set("TOK", "v")

        with pytest.raises(ValueError, match=r"(?i)passphrase|decrypt|corrupt"):
            _store(tmp_path, passphrase="wrong").get("TOK")

    def test_file_written_with_owner_only_permissions(self, tmp_path: Path):
        store = _store(tmp_path)
        store.set("TOK", "v")
        mode = (tmp_path / ".lemma" / "secrets.json").stat().st_mode & 0o777
        assert mode == 0o600


class TestPassphraseRequired:
    def test_missing_passphrase_raises_on_use(self, tmp_path: Path, monkeypatch):
        from lemma.services.secret_store import SecretStore

        monkeypatch.delenv("LEMMA_SECRET_PASSPHRASE", raising=False)
        store = SecretStore(tmp_path / ".lemma" / "secrets.json")
        with pytest.raises(ValueError, match=r"LEMMA_SECRET_PASSPHRASE"):
            store.set("TOK", "v")

    def test_passphrase_read_from_environment(self, tmp_path: Path, monkeypatch):
        from lemma.services.secret_store import SecretStore

        monkeypatch.setenv("LEMMA_SECRET_PASSPHRASE", "env-pass")
        path = tmp_path / ".lemma" / "secrets.json"
        SecretStore(path).set("TOK", "fromenv")
        assert SecretStore(path).get("TOK") == "fromenv"


class TestNoTokenInEvidenceLog:
    """Acceptance spot-check (#117): a credential resolved from the store and
    handed to a connector is used only for auth — it never lands in the
    signed evidence log."""

    def test_connector_token_absent_from_evidence_log(self, tmp_path: Path):
        import httpx

        from lemma.sdk.connectors.jira import JiraConnector
        from lemma.services.evidence_log import EvidenceLog

        token = "SUPER_SECRET_TOKEN_DO_NOT_LEAK"

        def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "total": 1,
                    "issues": [
                        {
                            "fields": {
                                "status": {"name": "Approved"},
                                "labels": ["change-management"],
                            }
                        }
                    ],
                },
            )

        client = httpx.Client(
            base_url="https://acme.atlassian.net",
            transport=httpx.MockTransport(_handler),
        )
        connector = JiraConnector(
            base_url="https://acme.atlassian.net",
            email="ci@acme.test",
            token=token,
            client=client,
        )

        log_dir = tmp_path / ".lemma" / "evidence"
        result = connector.run(EvidenceLog(log_dir=log_dir))
        assert result.ingested >= 1

        # The token must not appear anywhere in the persisted log bytes.
        for log_file in log_dir.glob("*.jsonl"):
            assert token not in log_file.read_text()
