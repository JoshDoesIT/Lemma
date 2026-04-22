"""Ed25519 key management, signing, and lifecycle for evidence chains.

Keys are organized under the project's ``.lemma/keys/`` directory:

    .lemma/keys/<producer>/<key_id>.private.pem   (mode 0600)
    .lemma/keys/<producer>/<key_id>.public.pem
    .lemma/keys/<producer>/meta.json              (KeyLifecycle)

``meta.json`` records every key the producer has ever held and its
lifecycle state (ACTIVE / RETIRED / REVOKED). Verification consults
this file to decide whether a historical signature is still trusted.

Flat pre-#98 layouts (``<producer>.private.pem`` next to
``<producer>.public.pem``) are auto-migrated on first access so
existing projects don't lose their keys when the versioned layout
ships.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, Field

from lemma.models.key_metadata import KeyRecord, KeyStatus


def _safe_producer(producer: str) -> str:
    """Producer names can contain characters unsafe for filenames."""
    return producer.replace("/", "_").replace(" ", "_")


def _producer_dir(producer: str, key_dir: Path) -> Path:
    return key_dir / _safe_producer(producer)


def _meta_path(producer: str, key_dir: Path) -> Path:
    return _producer_dir(producer, key_dir) / "meta.json"


def _key_path(producer: str, key_id: str, key_dir: Path, *, kind: str) -> Path:
    return _producer_dir(producer, key_dir) / f"{key_id}.{kind}.pem"


def _compute_key_id_from_public_bytes(raw_public: bytes) -> str:
    digest = hashlib.sha256(raw_public).hexdigest()[:16]
    return f"ed25519:{digest}"


def _public_raw(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


class KeyLifecycle(BaseModel):
    """Persisted lifecycle record for all of a producer's keys."""

    keys: list[KeyRecord] = Field(default_factory=list)

    def active(self) -> KeyRecord | None:
        for record in self.keys:
            if record.status == KeyStatus.ACTIVE:
                return record
        return None

    def find(self, key_id: str) -> KeyRecord | None:
        for record in self.keys:
            if record.key_id == key_id:
                return record
        return None


# ---------------------------------------------------------------------------
# Migration from the pre-#98 flat layout
# ---------------------------------------------------------------------------


def _legacy_flat_paths(producer: str, key_dir: Path) -> tuple[Path, Path]:
    safe = _safe_producer(producer)
    return key_dir / f"{safe}.private.pem", key_dir / f"{safe}.public.pem"


def _migrate_flat_layout_if_present(producer: str, key_dir: Path) -> None:
    """If the pre-#98 flat layout exists for ``producer``, migrate to the versioned one."""
    legacy_priv, legacy_pub = _legacy_flat_paths(producer, key_dir)
    if not legacy_priv.exists() or not legacy_pub.exists():
        return

    public_key = serialization.load_pem_public_key(legacy_pub.read_bytes())  # type: ignore[assignment]
    key_id = _compute_key_id_from_public_bytes(_public_raw(public_key))

    producer_dir = _producer_dir(producer, key_dir)
    producer_dir.mkdir(parents=True, exist_ok=True)

    new_priv = _key_path(producer, key_id, key_dir, kind="private")
    new_pub = _key_path(producer, key_id, key_dir, kind="public")
    legacy_priv.rename(new_priv)
    legacy_pub.rename(new_pub)
    os.chmod(new_priv, 0o600)

    _write_lifecycle(
        producer,
        key_dir,
        KeyLifecycle(
            keys=[
                KeyRecord(
                    key_id=key_id,
                    status=KeyStatus.ACTIVE,
                    activated_at=datetime.now(UTC),
                )
            ]
        ),
    )


# ---------------------------------------------------------------------------
# Lifecycle persistence
# ---------------------------------------------------------------------------


def _read_lifecycle(producer: str, key_dir: Path) -> KeyLifecycle:
    path = _meta_path(producer, key_dir)
    if not path.exists():
        return KeyLifecycle()
    return KeyLifecycle.model_validate_json(path.read_text())


def _write_lifecycle(producer: str, key_dir: Path, lifecycle: KeyLifecycle) -> None:
    producer_dir = _producer_dir(producer, key_dir)
    producer_dir.mkdir(parents=True, exist_ok=True)
    _meta_path(producer, key_dir).write_text(
        json.dumps(json.loads(lifecycle.model_dump_json()), indent=2)
    )


def read_lifecycle(producer: str, *, key_dir: Path) -> KeyLifecycle:
    """Return the full lifecycle record for ``producer`` (public accessor)."""
    _migrate_flat_layout_if_present(producer, key_dir)
    return _read_lifecycle(producer, key_dir)


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------


def _write_new_keypair(producer: str, key_dir: Path) -> tuple[str, Ed25519PrivateKey]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    key_id = _compute_key_id_from_public_bytes(_public_raw(public_key))

    _producer_dir(producer, key_dir).mkdir(parents=True, exist_ok=True)

    priv_path = _key_path(producer, key_id, key_dir, kind="private")
    pub_path = _key_path(producer, key_id, key_dir, kind="public")

    priv_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    os.chmod(priv_path, 0o600)
    pub_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return key_id, private_key


def generate_keypair(*, producer: str, key_dir: Path) -> str:
    """Generate (or return the existing) Ed25519 keypair for ``producer``.

    Idempotent with respect to an existing ACTIVE key: a second call
    returns the active key's ``key_id`` without creating a new one. If
    the pre-#98 flat layout exists for the producer, it's migrated to
    the versioned layout before anything else happens.
    """
    key_dir.mkdir(parents=True, exist_ok=True)
    _migrate_flat_layout_if_present(producer, key_dir)

    lifecycle = _read_lifecycle(producer, key_dir)
    active = lifecycle.active()
    if active is not None:
        return active.key_id

    key_id, _ = _write_new_keypair(producer, key_dir)
    lifecycle.keys.append(
        KeyRecord(
            key_id=key_id,
            status=KeyStatus.ACTIVE,
            activated_at=datetime.now(UTC),
        )
    )
    _write_lifecycle(producer, key_dir, lifecycle)
    return key_id


def public_key_id(*, producer: str, key_dir: Path) -> str:
    """Return the ACTIVE ``key_id`` for ``producer``, migrating if needed."""
    _migrate_flat_layout_if_present(producer, key_dir)
    lifecycle = _read_lifecycle(producer, key_dir)
    active = lifecycle.active()
    if active is None:
        msg = f"No active key on file for producer '{producer}' in {key_dir}"
        raise FileNotFoundError(msg)
    return active.key_id


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


def _load_private_by_key_id(producer: str, key_id: str, key_dir: Path) -> Ed25519PrivateKey:
    pem = _key_path(producer, key_id, key_dir, kind="private").read_bytes()
    return serialization.load_pem_private_key(pem, password=None)  # type: ignore[return-value]


def _load_public_by_key_id(producer: str, key_id: str, key_dir: Path) -> Ed25519PublicKey | None:
    path = _key_path(producer, key_id, key_dir, kind="public")
    if not path.exists():
        return None
    return serialization.load_pem_public_key(path.read_bytes())  # type: ignore[return-value]


def sign(message: bytes, *, producer: str, key_dir: Path) -> bytes:
    """Sign ``message`` with the producer's currently ACTIVE key."""
    _migrate_flat_layout_if_present(producer, key_dir)
    lifecycle = _read_lifecycle(producer, key_dir)
    active = lifecycle.active()
    if active is None:
        msg = f"No active key on file for producer '{producer}' in {key_dir}"
        raise FileNotFoundError(msg)
    private_key = _load_private_by_key_id(producer, active.key_id, key_dir)
    return private_key.sign(message)


def verify(
    message: bytes,
    signature: bytes,
    *,
    producer: str,
    key_dir: Path,
    key_id: str | None = None,
) -> bool:
    """Return ``True`` iff ``signature`` is a valid Ed25519 signature over ``message``.

    Args:
        message: Payload that was signed.
        signature: Signature bytes to verify.
        producer: Producer identifier used to locate the keystore.
        key_dir: Base keystore directory.
        key_id: Optional specific key to verify against. When omitted,
            the producer's ACTIVE key is used.

    Returns False (never raises) on any failure, so callers get a clean
    boolean for lifecycle verdicts.
    """
    _migrate_flat_layout_if_present(producer, key_dir)
    if key_id is None:
        lifecycle = _read_lifecycle(producer, key_dir)
        active = lifecycle.active()
        if active is None:
            return False
        key_id = active.key_id

    public_key = _load_public_by_key_id(producer, key_id, key_dir)
    if public_key is None:
        return False
    try:
        public_key.verify(signature, message)
    except Exception:
        return False
    return True


# ---------------------------------------------------------------------------
# Rotation and revocation
# ---------------------------------------------------------------------------


def rotate_key(*, producer: str, key_dir: Path) -> str:
    """Retire the producer's current ACTIVE key and generate a fresh one.

    Returns the new active ``key_id``. Raises if no ACTIVE key exists
    (there is nothing to rotate from).
    """
    _migrate_flat_layout_if_present(producer, key_dir)
    lifecycle = _read_lifecycle(producer, key_dir)
    active = lifecycle.active()
    if active is None:
        msg = f"No active key on file for producer '{producer}' — nothing to rotate."
        raise FileNotFoundError(msg)

    now = datetime.now(UTC)
    new_key_id, _ = _write_new_keypair(producer, key_dir)

    # Update prior record.
    active.status = KeyStatus.RETIRED
    active.retired_at = now
    active.successor_key_id = new_key_id

    lifecycle.keys.append(
        KeyRecord(
            key_id=new_key_id,
            status=KeyStatus.ACTIVE,
            activated_at=now,
        )
    )
    _write_lifecycle(producer, key_dir, lifecycle)
    return new_key_id


def revoke_key(*, producer: str, key_id: str, reason: str, key_dir: Path) -> KeyRecord:
    """Mark a specific key as REVOKED with a timestamp and reason."""
    if not reason:
        msg = "revoke_key requires a non-empty reason."
        raise ValueError(msg)

    _migrate_flat_layout_if_present(producer, key_dir)
    lifecycle = _read_lifecycle(producer, key_dir)
    record = lifecycle.find(key_id)
    if record is None:
        msg = f"Key '{key_id}' not found in lifecycle for producer '{producer}'."
        raise FileNotFoundError(msg)

    record.status = KeyStatus.REVOKED
    record.revoked_at = datetime.now(UTC)
    record.revoked_reason = reason
    _write_lifecycle(producer, key_dir, lifecycle)
    return record
