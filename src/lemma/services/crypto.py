"""Ed25519 key management and signing primitives for evidence chains.

Keys are persisted per-producer under the project's ``.lemma/keys/``
directory. Each producer (``metadata.product.name`` on an OCSF event)
owns one Ed25519 keypair; downstream code refers to keys by a stable
``key_id`` derived from the public key bytes.

This module is deliberately minimal: generate, load, sign, verify.
Rotation and revocation are tracked in a follow-up issue and layer on
top of this primitive surface without breaking its API.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def _safe_producer(producer: str) -> str:
    """Producer names can contain characters unsafe for filenames.

    Replace the OCSF-typical ``/`` and spaces with underscores so the
    serialized key paths stay predictable.
    """
    return producer.replace("/", "_").replace(" ", "_")


def _private_path(producer: str, key_dir: Path) -> Path:
    return key_dir / f"{_safe_producer(producer)}.private.pem"


def _public_path(producer: str, key_dir: Path) -> Path:
    return key_dir / f"{_safe_producer(producer)}.public.pem"


def generate_keypair(*, producer: str, key_dir: Path) -> str:
    """Generate (or return the existing) Ed25519 keypair for ``producer``.

    Idempotent: a second call for the same producer returns the
    existing ``key_id`` without regenerating. Private key files are
    written with mode ``0600``.

    Args:
        producer: Logical producer name (e.g., ``"Lemma"``, ``"Okta"``).
        key_dir: Directory under which the keypair is persisted.

    Returns:
        A stable ``key_id`` derived from the public key bytes.
    """
    key_dir.mkdir(parents=True, exist_ok=True)
    private_path = _private_path(producer, key_dir)
    public_path = _public_path(producer, key_dir)

    if private_path.exists() and public_path.exists():
        return public_key_id(producer=producer, key_dir=key_dir)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path.write_bytes(private_bytes)
    os.chmod(private_path, 0o600)
    public_path.write_bytes(public_bytes)

    return public_key_id(producer=producer, key_dir=key_dir)


def _load_private(producer: str, key_dir: Path) -> Ed25519PrivateKey:
    pem = _private_path(producer, key_dir).read_bytes()
    return serialization.load_pem_private_key(pem, password=None)  # type: ignore[return-value]


def _load_public(producer: str, key_dir: Path) -> Ed25519PublicKey | None:
    path = _public_path(producer, key_dir)
    if not path.exists():
        return None
    return serialization.load_pem_public_key(path.read_bytes())  # type: ignore[return-value]


def public_key_id(*, producer: str, key_dir: Path) -> str:
    """Return the stable ``key_id`` for a producer's public key.

    Format: ``ed25519:<first 16 hex chars of SHA256(public_key_raw_bytes)>``.
    """
    public_key = _load_public(producer, key_dir)
    if public_key is None:
        msg = f"No public key on file for producer '{producer}' in {key_dir}"
        raise FileNotFoundError(msg)
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    digest = hashlib.sha256(raw).hexdigest()[:16]
    return f"ed25519:{digest}"


def sign(message: bytes, *, producer: str, key_dir: Path) -> bytes:
    """Sign ``message`` with the producer's private key."""
    private_key = _load_private(producer, key_dir)
    return private_key.sign(message)


def verify(message: bytes, signature: bytes, *, producer: str, key_dir: Path) -> bool:
    """Return ``True`` iff ``signature`` is a valid Ed25519 signature over ``message``.

    Returns ``False`` (never raises) when the signature is invalid, when
    the producer has no key on file, or when verification otherwise
    fails. Callers get a boolean so they can produce a clean
    PROVEN/VIOLATED verdict without exception handling at every site.
    """
    public_key = _load_public(producer, key_dir)
    if public_key is None:
        return False
    try:
        public_key.verify(signature, message)
    except Exception:
        return False
    return True
