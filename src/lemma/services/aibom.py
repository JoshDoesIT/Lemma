"""AI Bill of Materials (AIBOM) builder — CycloneDX 1.6 AI format.

Produces a machine-readable inventory of every AI model registered in
the ``AISystemCard``. The output conforms to the CycloneDX 1.6
specification for AI/ML components so it can be consumed by standard
supply-chain and AI governance tooling.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from importlib import resources

import jsonschema

from lemma.models.system_card import AISystemCard, ModelCard


def _bom_ref(model: ModelCard) -> str:
    """Deterministic component identifier derived from model_id + version."""
    digest = hashlib.sha256(f"{model.model_id}@{model.version}".encode()).hexdigest()
    return f"model-{digest[:16]}"


_CYCLONEDX_HASH_ALG = {
    "sha256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
    "sha1": "SHA-1",
    "md5": "MD5",
}


def _parse_hash(model_hash: str) -> dict | None:
    """Parse an ``alg:hex`` digest into the CycloneDX hashes-array shape.

    Returns ``None`` if the input is blank, malformed, or uses an
    unrecognized algorithm — callers should omit the hashes field in
    that case rather than emit an invalid CycloneDX entry.
    """
    if not model_hash or ":" not in model_hash:
        return None
    algorithm, _, digest = model_hash.partition(":")
    alg = _CYCLONEDX_HASH_ALG.get(algorithm.lower())
    if alg is None or not digest:
        return None
    return {"alg": alg, "content": digest}


def _build_considerations(model: ModelCard) -> list[dict]:
    entries: list[dict] = []
    if model.training_data:
        entries.append({"type": "training-data", "value": model.training_data})
    if model.limitations:
        entries.append({"type": "technical-limitations", "value": "; ".join(model.limitations)})
    return entries


def _build_component(model: ModelCard) -> dict:
    component: dict = {
        "type": "machine-learning-model",
        "bom-ref": _bom_ref(model),
        "name": model.model_id,
        "version": model.version,
        "publisher": model.provider,
        "description": model.purpose,
    }
    hash_entry = _parse_hash(model.model_hash)
    if hash_entry is not None:
        component["hashes"] = [hash_entry]
    considerations = _build_considerations(model)
    if considerations:
        component["modelCard"] = {
            "considerations": {"consideration": considerations},
        }
    return component


def _load_schema() -> dict:
    """Load the bundled CycloneDX 1.6 AI BOM structural schema."""
    schema_file = resources.files("lemma.schemas").joinpath("cyclonedx-1.6-aibom.schema.json")
    return json.loads(schema_file.read_text())


def validate_aibom(bom: dict) -> None:
    """Validate an AIBOM dict against the bundled CycloneDX 1.6 schema.

    Raises:
        ValueError: If the document does not conform to the schema.
    """
    try:
        jsonschema.validate(instance=bom, schema=_load_schema())
    except jsonschema.ValidationError as exc:
        raise ValueError(f"AIBOM failed CycloneDX 1.6 validation: {exc.message}") from exc


def build_aibom(system_card: AISystemCard) -> dict:
    """Build a CycloneDX 1.6 AI BOM document from an AISystemCard.

    Args:
        system_card: The AI system card whose models should be exported.

    Returns:
        A dict matching the CycloneDX 1.6 JSON BOM shape, suitable for
        serialization with ``json.dumps``.
    """
    timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
        },
        "components": [_build_component(model) for model in system_card.models],
    }
