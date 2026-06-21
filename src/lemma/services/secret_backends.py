"""Pluggable secret backends for connector credentials (Refs #227).

The local encrypted store (``SecretStore``, #117) is the canonical home for
connector credentials, resolved through ``${secret:NAME}`` references in
``lemma_connector_config.yaml``. This module slots **remote** backends behind
that same reference syntax so an operator can source secrets from where their
org already keeps them:

- ``vault`` — HashiCorp Vault (KV v2).
- ``aws-secrets-manager`` — AWS Secrets Manager (one JSON secret).
- ``keyring`` — the OS keyring (Keychain / Secret Service / Credential Manager).

Selection is via ``LEMMA_SECRET_BACKEND`` (default ``local``); the
``${secret:NAME}`` syntax never changes, so swapping backends is a config/env
change, not a config-file rewrite.

**Injectable client seam.** Every remote backend takes a ``client=`` (or
``keyring=``) argument. Tests inject a fake, so CI never touches a live secret
store. Real clients are built lazily — the third-party library (``hvac`` for
Vault, ``keyring`` for the OS keyring; ``boto3`` ships with Lemma) is imported
only when a backend actually resolves a secret with no injected client, so the
module imports cleanly whether or not the optional extras are installed.

**Read-only by design.** Remote backends only *source* secrets; ``lemma
connector set-secret`` / ``list-secrets`` / ``rm-secret`` continue to manage
the local store. Lemma never writes to your Vault / AWS / keyring — secrets in
those systems are managed there, which keeps the blast radius of a Lemma
compromise to read-only access to the specific path you point it at.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Mapping

# Vault KV v2 read defaults — a single path holds a ``{name: value}`` bag,
# mirroring the local store's single-envelope model.
_VAULT_DEFAULT_MOUNT = "secret"
_VAULT_DEFAULT_PATH = "lemma/connectors"
# AWS Secrets Manager: one secret whose ``SecretString`` is a JSON ``{name: value}`` map.
_AWS_DEFAULT_SECRET_ID = "lemma/connectors"
# OS keyring: secrets stored under one service, keyed by secret name.
_KEYRING_DEFAULT_SERVICE = "lemma-connectors"


@runtime_checkable
class SecretBackend(Protocol):
    """A read-only source for ``${secret:NAME}`` resolution.

    The resolution seam in ``connector_config`` needs only ``get``; the local
    ``SecretStore`` satisfies this protocol (and additionally supports the
    write CLI), as do all the remote backends here.
    """

    def get(self, name: str) -> str | None:
        """Return the secret's value, or ``None`` if it isn't present."""
        ...


class VaultSecretBackend:
    """Source secrets from a HashiCorp Vault KV v2 path (a ``{name: value}`` bag)."""

    def __init__(
        self,
        *,
        client: Any | None = None,
        mount_point: str = _VAULT_DEFAULT_MOUNT,
        path: str = _VAULT_DEFAULT_PATH,
        url: str | None = None,
        token: str | None = None,
    ) -> None:
        self._client = client
        self._mount_point = mount_point
        self._path = path
        self._url = url
        self._token = token

    def _ensure_client(self) -> Any:
        if self._client is None:
            import hvac  # lazy: only when no client is injected

            self._client = hvac.Client(url=self._url, token=self._token)
        return self._client

    def get(self, name: str) -> str | None:
        client = self._ensure_client()
        try:
            response = client.secrets.kv.v2.read_secret_version(
                path=self._path, mount_point=self._mount_point
            )
        except Exception as exc:  # narrowed to InvalidPath by class name below
            # ``hvac.exceptions.InvalidPath`` means the whole path is absent;
            # treat that like a missing secret so resolution gives the clear
            # "not in store" error rather than a stack trace. Anything else
            # (auth, network) is a real failure and propagates.
            if type(exc).__name__ == "InvalidPath":
                return None
            raise
        data = response["data"]["data"]
        value = data.get(name)
        return None if value is None else str(value)

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> VaultSecretBackend:
        return cls(
            url=env.get("VAULT_ADDR"),
            token=env.get("VAULT_TOKEN"),
            mount_point=env.get("LEMMA_VAULT_MOUNT", _VAULT_DEFAULT_MOUNT),
            path=env.get("LEMMA_VAULT_PATH", _VAULT_DEFAULT_PATH),
        )


class AwsSecretsManagerBackend:
    """Source secrets from one AWS Secrets Manager JSON secret (a ``{name: value}`` map)."""

    def __init__(
        self,
        *,
        client: Any | None = None,
        secret_id: str = _AWS_DEFAULT_SECRET_ID,
        region: str | None = None,
    ) -> None:
        self._client = client
        self._secret_id = secret_id
        self._region = region

    def _ensure_client(self) -> Any:
        if self._client is None:
            import boto3  # ships with Lemma

            self._client = boto3.client("secretsmanager", region_name=self._region)
        return self._client

    def get(self, name: str) -> str | None:
        client = self._ensure_client()
        try:
            response = client.get_secret_value(SecretId=self._secret_id)
        except client.exceptions.ResourceNotFoundException:
            # The secret id itself doesn't exist — treat as a missing secret.
            return None
        payload = json.loads(response["SecretString"])
        value = payload.get(name)
        return None if value is None else str(value)

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> AwsSecretsManagerBackend:
        return cls(
            secret_id=env.get("LEMMA_AWS_SECRET_ID", _AWS_DEFAULT_SECRET_ID),
            region=env.get("AWS_REGION") or env.get("AWS_DEFAULT_REGION"),
        )


class KeyringSecretBackend:
    """Source secrets from the OS keyring, one entry per secret name under a service."""

    def __init__(
        self,
        *,
        keyring: Any | None = None,
        service: str = _KEYRING_DEFAULT_SERVICE,
    ) -> None:
        self._keyring = keyring
        self._service = service

    def _ensure_keyring(self) -> Any:
        if self._keyring is None:
            import keyring  # lazy: only when no keyring is injected

            self._keyring = keyring
        return self._keyring

    def get(self, name: str) -> str | None:
        keyring = self._ensure_keyring()
        return keyring.get_password(self._service, name)

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> KeyringSecretBackend:
        return cls(service=env.get("LEMMA_KEYRING_SERVICE", _KEYRING_DEFAULT_SERVICE))


def resolve_secret_backend(*, project_root: Path, env: Mapping[str, str]) -> SecretBackend | None:
    """Pick a secret backend from ``LEMMA_SECRET_BACKEND`` (default ``local``).

    Returns ``None`` for the local backend when no ``LEMMA_SECRET_PASSPHRASE``
    is set, preserving the existing behaviour where a config that uses only
    plain ``${ENV_VAR}`` references works with no passphrase. Remote backends
    are always returned (inert until first ``get``) so a misconfigured remote
    surfaces at resolution time with a clear error.

    Raises:
        ValueError: If ``LEMMA_SECRET_BACKEND`` names an unknown backend.
    """
    name = (env.get("LEMMA_SECRET_BACKEND") or "local").strip().lower()

    if name in ("", "local"):
        if not env.get("LEMMA_SECRET_PASSPHRASE"):
            return None
        from lemma.services.secret_store import SecretStore

        return SecretStore(Path(project_root) / ".lemma" / "secrets.json")
    if name == "vault":
        return VaultSecretBackend.from_env(env)
    if name in ("aws-secrets-manager", "aws"):
        return AwsSecretsManagerBackend.from_env(env)
    if name == "keyring":
        return KeyringSecretBackend.from_env(env)

    msg = (
        f"Unknown LEMMA_SECRET_BACKEND '{name}'. Valid values: "
        "local, vault, aws-secrets-manager, keyring."
    )
    raise ValueError(msg)
