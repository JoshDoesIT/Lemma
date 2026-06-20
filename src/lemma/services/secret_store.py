"""Encrypted, passphrase-keyed secret store for connector credentials (Refs #117).

Connectors accept API tokens via env vars or constructor args. ``${ENV_VAR}``
interpolation in ``lemma_connector_config.yaml`` (#116) keeps secrets out of
git, but env vars aren't always the right home — they leak into process
listings and child processes. This module adds a file-backed alternative: an
**encrypted-at-rest** secret store under ``.lemma/secrets.json``, keyed to a
passphrase from ``LEMMA_SECRET_PASSPHRASE``.

**Format.** A single JSON envelope holding a salt and a Fernet token; the
Fernet token encrypts the whole ``{name: value}`` map, so neither secret
names nor values appear in plaintext on disk:

    {"version": 1, "kdf": "pbkdf2-sha256", "iterations": 600000,
     "salt": "<b64>", "data": "<fernet-token>"}

The Fernet key is derived from the passphrase via PBKDF2-HMAC-SHA256 over the
stored salt. A wrong passphrase fails the decrypt with a clear error rather
than silently returning garbage.

**Rotation.** ``set`` overwrites in place; the next ``lemma evidence collect``
run re-reads the store, so a rotated token is picked up without restarting any
long-running process. Pluggable remote backends (OS keyring, HashiCorp Vault,
AWS Secrets Manager) are intentionally deferred — this is the local canonical
store they would slot behind.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

_ENV_PASSPHRASE = "LEMMA_SECRET_PASSPHRASE"
_PBKDF2_ITERATIONS = 600_000
_SALT_BYTES = 16


class SecretStore:
    """A passphrase-encrypted ``{name: secret}`` map persisted to one file."""

    def __init__(self, path: Path, *, passphrase: str | None = None) -> None:
        self._path = Path(path)
        self._passphrase = passphrase

    # --- public API ---

    def set(self, name: str, value: str) -> None:
        """Add or rotate a secret, then persist the encrypted store."""
        if not name:
            msg = "Secret name must be non-empty."
            raise ValueError(msg)
        secrets = self._load()
        secrets[name] = value
        self._save(secrets)

    def get(self, name: str) -> str | None:
        """Return a secret's value, or ``None`` if it isn't stored."""
        return self._load().get(name)

    def names(self) -> list[str]:
        """Return the stored secret names (never the values)."""
        return sorted(self._load().keys())

    def delete(self, name: str) -> None:
        """Remove a secret if present, then persist."""
        secrets = self._load()
        if name in secrets:
            del secrets[name]
            self._save(secrets)

    # --- internals ---

    def _resolve_passphrase(self) -> str:
        passphrase = self._passphrase or os.environ.get(_ENV_PASSPHRASE)
        if not passphrase:
            msg = (
                f"The secret store requires a passphrase. Set {_ENV_PASSPHRASE} "
                "in the environment (or pass passphrase=... to SecretStore)."
            )
            raise ValueError(msg)
        return passphrase

    def _derive_key(self, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=_PBKDF2_ITERATIONS,
        )
        return base64.urlsafe_b64encode(kdf.derive(self._resolve_passphrase().encode("utf-8")))

    def _load(self) -> dict[str, str]:
        if not self._path.exists():
            return {}
        try:
            envelope = json.loads(self._path.read_text(encoding="utf-8"))
            salt = base64.b64decode(envelope["salt"])
            token = envelope["data"].encode("utf-8")
        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            msg = f"Secret store at {self._path} is malformed or corrupted: {exc}"
            raise ValueError(msg) from exc

        fernet = Fernet(self._derive_key(salt))
        try:
            plaintext = fernet.decrypt(token)
        except InvalidToken as exc:
            msg = (
                f"Could not decrypt the secret store at {self._path}: wrong "
                f"{_ENV_PASSPHRASE} passphrase or a corrupted file."
            )
            raise ValueError(msg) from exc
        data = json.loads(plaintext.decode("utf-8"))
        return {str(k): str(v) for k, v in data.items()}

    def _save(self, secrets: dict[str, str]) -> None:
        salt = os.urandom(_SALT_BYTES)
        fernet = Fernet(self._derive_key(salt))
        token = fernet.encrypt(json.dumps(secrets).encode("utf-8"))
        envelope = {
            "version": 1,
            "kdf": "pbkdf2-sha256",
            "iterations": _PBKDF2_ITERATIONS,
            "salt": base64.b64encode(salt).decode("ascii"),
            "data": token.decode("ascii"),
        }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # Write then tighten perms to owner-only (secrets must not be world/group readable).
        self._path.write_text(json.dumps(envelope, indent=2), encoding="utf-8")
        self._path.chmod(0o600)
