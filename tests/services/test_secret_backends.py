"""Tests for pluggable secret backends (Refs #227).

Backends source connector credentials behind the existing ``${secret:NAME}``
resolution (#117) so secrets can come from HashiCorp Vault, AWS Secrets
Manager, or an OS keyring instead of the local encrypted store — selectable
via ``LEMMA_SECRET_BACKEND`` without changing the reference syntax.

Every backend exposes an injectable client seam so CI never touches a live
secret store: each test wires a fake client/keyring in and asserts ``get``
behaviour against it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

# --------------------------------------------------------------------------
# Fakes — stand in for hvac / boto3 / keyring so CI never touches a live store
# --------------------------------------------------------------------------


class _FakeKvV2:
    def __init__(self, store: dict[str, dict[str, str]]) -> None:
        self._store = store
        self.calls: list[tuple[str, str]] = []

    def read_secret_version(self, *, path: str, mount_point: str, **_: object):
        self.calls.append((mount_point, path))
        if path not in self._store:
            raise InvalidPath(f"no secret at {mount_point}/{path}")
        return {"data": {"data": dict(self._store[path])}}


class InvalidPath(Exception):  # noqa: N818 — mirrors hvac.exceptions.InvalidPath exactly
    """Stand-in for ``hvac.exceptions.InvalidPath`` — same class name, which is
    what the Vault backend keys on to map a missing path to ``None``."""


class _FakeHvacClient:
    def __init__(self, store: dict[str, dict[str, str]]) -> None:
        self.secrets = type("S", (), {})()
        self.secrets.kv = type("KV", (), {})()
        self.secrets.kv.v2 = _FakeKvV2(store)


class _FakeBotoExceptions:
    class ResourceNotFoundException(Exception):  # noqa: N818 — mirrors boto3's name
        pass


class _FakeSecretsManager:
    def __init__(self, secret_strings: dict[str, str]) -> None:
        self._secret_strings = secret_strings
        self.exceptions = _FakeBotoExceptions()
        self.calls: list[str] = []

    def get_secret_value(self, *, SecretId: str):  # noqa: N803 — boto3 kwarg name
        self.calls.append(SecretId)
        if SecretId not in self._secret_strings:
            raise self.exceptions.ResourceNotFoundException(f"no secret {SecretId}")
        return {"SecretString": self._secret_strings[SecretId]}


class _FakeKeyring:
    def __init__(self, store: dict[tuple[str, str], str]) -> None:
        self._store = store
        self.calls: list[tuple[str, str]] = []

    def get_password(self, service: str, name: str) -> str | None:
        self.calls.append((service, name))
        return self._store.get((service, name))


# --------------------------------------------------------------------------
# Vault backend
# --------------------------------------------------------------------------


class TestVaultBackend:
    def test_get_returns_value_from_kv_v2_path(self) -> None:
        from lemma.services.secret_backends import VaultSecretBackend

        client = _FakeHvacClient({"lemma/connectors": {"JIRA_TOKEN": "vault-tok"}})
        backend = VaultSecretBackend(client=client, mount_point="secret", path="lemma/connectors")
        assert backend.get("JIRA_TOKEN") == "vault-tok"
        # Read from the configured mount + path, not a hard-coded default.
        assert client.secrets.kv.v2.calls == [("secret", "lemma/connectors")]

    def test_get_missing_name_returns_none(self) -> None:
        from lemma.services.secret_backends import VaultSecretBackend

        client = _FakeHvacClient({"lemma/connectors": {"OTHER": "x"}})
        backend = VaultSecretBackend(client=client, path="lemma/connectors")
        assert backend.get("ABSENT") is None

    def test_get_missing_path_returns_none(self) -> None:
        from lemma.services.secret_backends import VaultSecretBackend

        client = _FakeHvacClient({})  # the path itself does not exist
        backend = VaultSecretBackend(client=client, path="lemma/connectors")
        assert backend.get("ANY") is None


# --------------------------------------------------------------------------
# AWS Secrets Manager backend
# --------------------------------------------------------------------------


class TestAwsSecretsManagerBackend:
    def test_get_returns_value_from_json_secret(self) -> None:
        from lemma.services.secret_backends import AwsSecretsManagerBackend

        client = _FakeSecretsManager({"lemma/connectors": json.dumps({"JIRA_TOKEN": "aws-tok"})})
        backend = AwsSecretsManagerBackend(client=client, secret_id="lemma/connectors")
        assert backend.get("JIRA_TOKEN") == "aws-tok"
        assert client.calls == ["lemma/connectors"]

    def test_get_missing_name_returns_none(self) -> None:
        from lemma.services.secret_backends import AwsSecretsManagerBackend

        client = _FakeSecretsManager({"lemma/connectors": json.dumps({"A": "1"})})
        backend = AwsSecretsManagerBackend(client=client, secret_id="lemma/connectors")
        assert backend.get("ABSENT") is None

    def test_get_missing_secret_id_returns_none(self) -> None:
        from lemma.services.secret_backends import AwsSecretsManagerBackend

        client = _FakeSecretsManager({})  # the secret id does not exist
        backend = AwsSecretsManagerBackend(client=client, secret_id="lemma/connectors")
        assert backend.get("ANY") is None


# --------------------------------------------------------------------------
# OS keyring backend
# --------------------------------------------------------------------------


class TestKeyringBackend:
    def test_get_returns_value_from_keyring(self) -> None:
        from lemma.services.secret_backends import KeyringSecretBackend

        kr = _FakeKeyring({("lemma-connectors", "JIRA_TOKEN"): "kr-tok"})
        backend = KeyringSecretBackend(keyring=kr, service="lemma-connectors")
        assert backend.get("JIRA_TOKEN") == "kr-tok"
        assert kr.calls == [("lemma-connectors", "JIRA_TOKEN")]

    def test_get_missing_name_returns_none(self) -> None:
        from lemma.services.secret_backends import KeyringSecretBackend

        kr = _FakeKeyring({})
        backend = KeyringSecretBackend(keyring=kr, service="lemma-connectors")
        assert backend.get("ABSENT") is None


# --------------------------------------------------------------------------
# Protocol conformance
# --------------------------------------------------------------------------


class TestProtocol:
    def test_local_secret_store_satisfies_backend_protocol(self, tmp_path: Path) -> None:
        from lemma.services.secret_backends import SecretBackend
        from lemma.services.secret_store import SecretStore

        store = SecretStore(tmp_path / ".lemma" / "secrets.json", passphrase="p")
        assert isinstance(store, SecretBackend)

    def test_remote_backends_satisfy_backend_protocol(self) -> None:
        from lemma.services.secret_backends import (
            AwsSecretsManagerBackend,
            KeyringSecretBackend,
            SecretBackend,
            VaultSecretBackend,
        )

        assert isinstance(VaultSecretBackend(client=_FakeHvacClient({})), SecretBackend)
        assert isinstance(AwsSecretsManagerBackend(client=_FakeSecretsManager({})), SecretBackend)
        assert isinstance(KeyringSecretBackend(keyring=_FakeKeyring({})), SecretBackend)


# --------------------------------------------------------------------------
# Backend selection (AC1) — selectable via env without changing ${secret:NAME}
# --------------------------------------------------------------------------


class TestResolveBackend:
    def test_default_local_with_passphrase_returns_secret_store(self, tmp_path: Path) -> None:
        from lemma.services.secret_backends import resolve_secret_backend
        from lemma.services.secret_store import SecretStore

        backend = resolve_secret_backend(
            project_root=tmp_path, env={"LEMMA_SECRET_PASSPHRASE": "p"}
        )
        assert isinstance(backend, SecretStore)

    def test_default_local_without_passphrase_returns_none(self, tmp_path: Path) -> None:
        from lemma.services.secret_backends import resolve_secret_backend

        assert resolve_secret_backend(project_root=tmp_path, env={}) is None

    def test_explicit_local_selects_secret_store(self, tmp_path: Path) -> None:
        from lemma.services.secret_backends import resolve_secret_backend
        from lemma.services.secret_store import SecretStore

        backend = resolve_secret_backend(
            project_root=tmp_path,
            env={"LEMMA_SECRET_BACKEND": "local", "LEMMA_SECRET_PASSPHRASE": "p"},
        )
        assert isinstance(backend, SecretStore)

    def test_vault_selected_via_env(self, tmp_path: Path) -> None:
        from lemma.services.secret_backends import VaultSecretBackend, resolve_secret_backend

        backend = resolve_secret_backend(
            project_root=tmp_path,
            env={
                "LEMMA_SECRET_BACKEND": "vault",
                "VAULT_ADDR": "https://vault.example:8200",
                "VAULT_TOKEN": "s.xxx",
                "LEMMA_VAULT_PATH": "team/lemma",
                "LEMMA_VAULT_MOUNT": "kv",
            },
        )
        assert isinstance(backend, VaultSecretBackend)

    def test_aws_secrets_manager_selected_via_env(self, tmp_path: Path) -> None:
        from lemma.services.secret_backends import (
            AwsSecretsManagerBackend,
            resolve_secret_backend,
        )

        backend = resolve_secret_backend(
            project_root=tmp_path,
            env={
                "LEMMA_SECRET_BACKEND": "aws-secrets-manager",
                "LEMMA_AWS_SECRET_ID": "lemma/connectors",
            },
        )
        assert isinstance(backend, AwsSecretsManagerBackend)

    def test_keyring_selected_via_env(self, tmp_path: Path) -> None:
        from lemma.services.secret_backends import KeyringSecretBackend, resolve_secret_backend

        backend = resolve_secret_backend(
            project_root=tmp_path, env={"LEMMA_SECRET_BACKEND": "keyring"}
        )
        assert isinstance(backend, KeyringSecretBackend)

    def test_unknown_backend_raises_clear_error(self, tmp_path: Path) -> None:
        from lemma.services.secret_backends import resolve_secret_backend

        with pytest.raises(ValueError, match=r"(?i)LEMMA_SECRET_BACKEND|unknown|nope"):
            resolve_secret_backend(project_root=tmp_path, env={"LEMMA_SECRET_BACKEND": "nope"})

    def test_selection_is_case_insensitive(self, tmp_path: Path) -> None:
        from lemma.services.secret_backends import VaultSecretBackend, resolve_secret_backend

        backend = resolve_secret_backend(
            project_root=tmp_path, env={"LEMMA_SECRET_BACKEND": "Vault"}
        )
        assert isinstance(backend, VaultSecretBackend)


# --------------------------------------------------------------------------
# Integration (AC1) — ${secret:NAME} resolves from a remote backend unchanged
# --------------------------------------------------------------------------


class TestSecretRefResolvesFromRemoteBackend:
    def test_vault_backend_resolves_secret_reference_in_config(self, tmp_path: Path) -> None:
        from lemma.services.connector_config import load_connector_config
        from lemma.services.secret_backends import VaultSecretBackend

        client = _FakeHvacClient({"lemma/connectors": {"JIRA_TOKEN": "from-vault"}})
        backend = VaultSecretBackend(client=client, path="lemma/connectors")

        cfg_path = tmp_path / "lemma_connector_config.yaml"
        cfg_path.write_text(
            "connector: jira\nconfig:\n  token: ${secret:JIRA_TOKEN}\n",
            encoding="utf-8",
        )

        cfg = load_connector_config(cfg_path, secret_store=backend)
        assert cfg.config == {"token": "from-vault"}
