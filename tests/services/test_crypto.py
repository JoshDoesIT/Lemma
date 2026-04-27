"""Tests for Ed25519 key management and signing primitives."""

from __future__ import annotations

from pathlib import Path


def test_generate_keypair_writes_private_and_public_files(tmp_path: Path):
    from lemma.services.crypto import generate_keypair

    key_id = generate_keypair(producer="test-producer", key_dir=tmp_path / "keys")

    assert key_id  # non-empty identifier
    producer_dir = tmp_path / "keys" / "test-producer"
    assert (producer_dir / f"{key_id}.private.pem").is_file()
    assert (producer_dir / f"{key_id}.public.pem").is_file()

    # Private key mode is 0600 on POSIX — integrity check
    private_path = producer_dir / f"{key_id}.private.pem"
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


def test_versioned_keystore_layout_on_fresh_generate(tmp_path: Path):
    """New-layout keystore writes keys under <producer>/<key_id>.*.pem."""
    from lemma.services.crypto import generate_keypair

    key_id = generate_keypair(producer="fresh", key_dir=tmp_path / "keys")
    producer_dir = tmp_path / "keys" / "fresh"

    assert producer_dir.is_dir()
    assert (producer_dir / f"{key_id}.private.pem").is_file()
    assert (producer_dir / f"{key_id}.public.pem").is_file()
    assert (producer_dir / "meta.json").is_file()


def test_migrate_flat_keystore_preserves_key_id(tmp_path: Path):
    """A keystore in the old flat layout (pre-#98) is auto-migrated on access."""
    import json

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from lemma.services.crypto import public_key_id

    # Simulate the pre-#98 flat layout.
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    legacy_priv = Ed25519PrivateKey.generate()
    (key_dir / "legacy.private.pem").write_bytes(
        legacy_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    (key_dir / "legacy.public.pem").write_bytes(
        legacy_priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    # Access triggers migration.
    key_id = public_key_id(producer="legacy", key_dir=key_dir)
    assert key_id.startswith("ed25519:")

    # New layout exists; old flat files are gone.
    producer_dir = key_dir / "legacy"
    assert producer_dir.is_dir()
    assert (producer_dir / f"{key_id}.private.pem").is_file()
    assert (producer_dir / "meta.json").is_file()
    assert not (key_dir / "legacy.private.pem").exists()

    # Meta records the migrated key as ACTIVE.
    meta = json.loads((producer_dir / "meta.json").read_text())
    assert len(meta["keys"]) == 1
    assert meta["keys"][0]["key_id"] == key_id
    assert meta["keys"][0]["status"] == "ACTIVE"


def test_rotate_key_retires_active_and_generates_new(tmp_path: Path):
    from lemma.services.crypto import generate_keypair, read_lifecycle, rotate_key

    original = generate_keypair(producer="rot", key_dir=tmp_path / "keys")
    successor = rotate_key(producer="rot", key_dir=tmp_path / "keys")

    assert successor != original

    lifecycle = read_lifecycle("rot", key_dir=tmp_path / "keys")
    by_id = {r.key_id: r for r in lifecycle.keys}

    assert by_id[original].status.value == "RETIRED"
    assert by_id[original].retired_at is not None
    assert by_id[original].successor_key_id == successor

    assert by_id[successor].status.value == "ACTIVE"
    assert by_id[successor].retired_at is None


def test_rotate_key_without_active_key_raises(tmp_path: Path):
    import pytest

    from lemma.services.crypto import rotate_key

    with pytest.raises(FileNotFoundError):
        rotate_key(producer="never-generated", key_dir=tmp_path / "keys")


def test_rotated_retired_key_can_still_verify_historical_signatures(tmp_path: Path):
    from lemma.services.crypto import generate_keypair, rotate_key, sign, verify

    original = generate_keypair(producer="hist", key_dir=tmp_path / "keys")
    historical_signature = sign(b"old message", producer="hist", key_dir=tmp_path / "keys")

    rotate_key(producer="hist", key_dir=tmp_path / "keys")

    # The retired key's material is still on disk and verifiable by key_id.
    assert verify(
        b"old message",
        historical_signature,
        producer="hist",
        key_dir=tmp_path / "keys",
        key_id=original,
    )


def test_revoke_key_requires_reason(tmp_path: Path):
    import pytest

    from lemma.services.crypto import generate_keypair, revoke_key

    key_id = generate_keypair(producer="rev", key_dir=tmp_path / "keys")

    with pytest.raises(ValueError, match="reason"):
        revoke_key(producer="rev", key_id=key_id, reason="", key_dir=tmp_path / "keys")


def test_revoke_key_marks_record(tmp_path: Path):
    from lemma.services.crypto import generate_keypair, read_lifecycle, revoke_key

    key_id = generate_keypair(producer="rev", key_dir=tmp_path / "keys")

    record = revoke_key(
        producer="rev",
        key_id=key_id,
        reason="leaked in private repo",
        key_dir=tmp_path / "keys",
    )

    assert record.status.value == "REVOKED"
    assert record.revoked_at is not None
    assert record.revoked_reason == "leaked in private repo"

    lifecycle = read_lifecycle("rev", key_dir=tmp_path / "keys")
    assert lifecycle.find(key_id).status.value == "REVOKED"


def test_revoke_key_with_unknown_key_id_raises(tmp_path: Path):
    import pytest

    from lemma.services.crypto import generate_keypair, revoke_key

    generate_keypair(producer="rev", key_dir=tmp_path / "keys")

    with pytest.raises(FileNotFoundError):
        revoke_key(
            producer="rev",
            key_id="ed25519:doesnotexist",
            reason="test",
            key_dir=tmp_path / "keys",
        )


# ---------------------------------------------------------------------------
# Offline revocation lists (Refs #101)
# ---------------------------------------------------------------------------


def _public_pem(producer: str, key_id: str, key_dir: Path) -> bytes:
    safe = producer.replace("/", "_").replace(" ", "_")
    return (key_dir / safe / f"{key_id}.public.pem").read_bytes()


def test_revocation_list_round_trips_through_json():
    from datetime import UTC, datetime

    from lemma.models.signed_evidence import RevocationEntry, RevocationList

    crl = RevocationList(
        producer="Lemma",
        revocations=[
            RevocationEntry(
                key_id="ed25519:abc123",
                revoked_at=datetime(2026, 4, 27, tzinfo=UTC),
                reason="leaked",
            ),
        ],
        issuer_key_id="ed25519:def456",
        signature="00" * 64,
    )
    revived = RevocationList.model_validate_json(crl.model_dump_json())
    assert revived == crl


def test_export_crl_includes_revoked_keys_only(tmp_path: Path):
    from lemma.services.crypto import (
        export_crl,
        generate_keypair,
        revoke_key,
        rotate_key,
    )

    keys = tmp_path / "keys"
    k1 = generate_keypair(producer="Lemma", key_dir=keys)
    k2 = rotate_key(producer="Lemma", key_dir=keys)  # k1 -> RETIRED, k2 ACTIVE
    revoke_key(producer="Lemma", key_id=k1, reason="rotation hygiene", key_dir=keys)

    crl = export_crl(producer="Lemma", key_dir=keys)
    assert crl.producer == "Lemma"
    assert crl.issuer_key_id == k2  # signed by current ACTIVE
    assert {e.key_id for e in crl.revocations} == {k1}
    assert crl.revocations[0].reason == "rotation hygiene"


def test_export_crl_excludes_active_and_retired_keys(tmp_path: Path):
    from lemma.services.crypto import export_crl, generate_keypair, rotate_key

    keys = tmp_path / "keys"
    generate_keypair(producer="Lemma", key_dir=keys)
    rotate_key(producer="Lemma", key_dir=keys)  # one ACTIVE + one RETIRED

    crl = export_crl(producer="Lemma", key_dir=keys)
    assert crl.revocations == []  # nothing revoked


def test_export_crl_without_active_key_raises(tmp_path: Path):
    import pytest

    from lemma.services.crypto import export_crl

    with pytest.raises(FileNotFoundError, match=r"(?i)active"):
        export_crl(producer="ghost", key_dir=tmp_path / "keys")


def test_export_crl_signature_round_trips_via_verify_crl(tmp_path: Path):
    from lemma.services.crypto import (
        export_crl,
        generate_keypair,
        revoke_key,
        rotate_key,
        verify_crl,
    )

    keys = tmp_path / "keys"
    k1 = generate_keypair(producer="Lemma", key_dir=keys)
    k2 = rotate_key(producer="Lemma", key_dir=keys)
    revoke_key(producer="Lemma", key_id=k1, reason="leaked", key_dir=keys)

    crl = export_crl(producer="Lemma", key_dir=keys)
    pem = _public_pem("Lemma", k2, keys)
    assert verify_crl(crl, pem) is True


def test_verify_crl_returns_false_when_signature_tampered(tmp_path: Path):
    from lemma.services.crypto import (
        export_crl,
        generate_keypair,
        revoke_key,
        rotate_key,
        verify_crl,
    )

    keys = tmp_path / "keys"
    k1 = generate_keypair(producer="Lemma", key_dir=keys)
    k2 = rotate_key(producer="Lemma", key_dir=keys)
    revoke_key(producer="Lemma", key_id=k1, reason="leaked", key_dir=keys)

    crl = export_crl(producer="Lemma", key_dir=keys)
    pem = _public_pem("Lemma", k2, keys)

    # Flip a hex digit in the signature.
    tampered = crl.model_copy(update={"signature": ("0" + crl.signature[1:])})
    assert verify_crl(tampered, pem) is False


def test_verify_crl_returns_false_when_payload_tampered(tmp_path: Path):
    from datetime import UTC, datetime

    from lemma.models.signed_evidence import RevocationEntry
    from lemma.services.crypto import (
        export_crl,
        generate_keypair,
        revoke_key,
        rotate_key,
        verify_crl,
    )

    keys = tmp_path / "keys"
    k1 = generate_keypair(producer="Lemma", key_dir=keys)
    k2 = rotate_key(producer="Lemma", key_dir=keys)
    revoke_key(producer="Lemma", key_id=k1, reason="leaked", key_dir=keys)

    crl = export_crl(producer="Lemma", key_dir=keys)
    pem = _public_pem("Lemma", k2, keys)

    # Add a bogus revocation entry — the signature was over the original list.
    tampered = crl.model_copy(
        update={
            "revocations": [
                *crl.revocations,
                RevocationEntry(
                    key_id="ed25519:never-existed",
                    revoked_at=datetime(2026, 4, 27, tzinfo=UTC),
                    reason="forged",
                ),
            ]
        }
    )
    assert verify_crl(tampered, pem) is False


def test_verify_crl_with_wrong_public_key_returns_false(tmp_path: Path):
    from lemma.services.crypto import (
        export_crl,
        generate_keypair,
        revoke_key,
        rotate_key,
        verify_crl,
    )

    keys = tmp_path / "keys"
    k1 = generate_keypair(producer="Lemma", key_dir=keys)
    rotate_key(producer="Lemma", key_dir=keys)
    revoke_key(producer="Lemma", key_id=k1, reason="leaked", key_dir=keys)

    # Generate a totally unrelated key and try to verify with that producer's PEM.
    other_kid = generate_keypair(producer="Other", key_dir=keys)
    other_pem = _public_pem("Other", other_kid, keys)

    crl = export_crl(producer="Lemma", key_dir=keys)
    assert verify_crl(crl, other_pem) is False
