"""Tests for Ed25519 key management and signing primitives."""

from __future__ import annotations

from pathlib import Path


def test_generate_keypair_writes_private_and_public_files(tmp_path: Path):
    from lemma.services.crypto import generate_keypair

    key_id = generate_keypair(producer="test-producer", key_dir=tmp_path / "keys")

    assert key_id  # non-empty identifier
    assert (tmp_path / "keys" / "test-producer.private.pem").is_file()
    assert (tmp_path / "keys" / "test-producer.public.pem").is_file()

    # Private key mode is 0600 on POSIX — integrity check
    private_path = tmp_path / "keys" / "test-producer.private.pem"
    mode = private_path.stat().st_mode & 0o777
    assert mode == 0o600, f"private key mode should be 0600, got {oct(mode)}"


def test_generate_keypair_is_idempotent_for_same_producer(tmp_path: Path):
    """Calling generate_keypair twice with the same producer returns the same key_id."""
    from lemma.services.crypto import generate_keypair

    key_dir = tmp_path / "keys"
    first = generate_keypair(producer="dup", key_dir=key_dir)
    second = generate_keypair(producer="dup", key_dir=key_dir)
    assert first == second


def test_sign_and_verify_round_trip(tmp_path: Path):
    from lemma.services.crypto import generate_keypair, sign, verify

    generate_keypair(producer="round-trip", key_dir=tmp_path / "keys")

    message = b"hello world"
    signature = sign(message, producer="round-trip", key_dir=tmp_path / "keys")
    assert verify(message, signature, producer="round-trip", key_dir=tmp_path / "keys") is True


def test_verify_rejects_modified_message(tmp_path: Path):
    from lemma.services.crypto import generate_keypair, sign, verify

    generate_keypair(producer="tamper", key_dir=tmp_path / "keys")
    signature = sign(b"original", producer="tamper", key_dir=tmp_path / "keys")

    assert verify(b"tampered", signature, producer="tamper", key_dir=tmp_path / "keys") is False


def test_verify_rejects_unknown_producer(tmp_path: Path):
    from lemma.services.crypto import generate_keypair, sign, verify

    generate_keypair(producer="known", key_dir=tmp_path / "keys")
    signature = sign(b"msg", producer="known", key_dir=tmp_path / "keys")

    # Verification against a different producer returns False (key not on file)
    assert verify(b"msg", signature, producer="unknown", key_dir=tmp_path / "keys") is False


def test_key_id_is_derived_from_public_key_bytes(tmp_path: Path):
    """key_id is a stable hash of the public key so downstream can reference it."""
    from lemma.services.crypto import generate_keypair, public_key_id

    key_id = generate_keypair(producer="stable", key_dir=tmp_path / "keys")
    derived = public_key_id(producer="stable", key_dir=tmp_path / "keys")
    assert key_id == derived
    assert key_id.startswith("ed25519:")
