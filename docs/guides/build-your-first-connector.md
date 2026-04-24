# Build Your First Connector

This tutorial walks you end-to-end through writing a Lemma connector — the integration point that pulls evidence from a third-party source and feeds it into Lemma's signed evidence log. By the end you'll have a working connector project on disk, validated OCSF output, and signed entries you can verify.

We'll build a minimal connector that emits a single `ComplianceFinding` per run. The reference base class (`JsonlConnector`) does the OCSF heavy lifting so you can focus on the integration shape.

## Prerequisites

- Lemma installed (`uv pip install -e .` from the repo root).
- A Lemma project directory. Create one with:

  ```bash
  mkdir my-org && cd my-org && lemma init
  ```

## 1. Scaffold the project

`lemma connector init` lays out a working starter project, including a manifest, a `Connector` class subclassing the reference `JsonlConnector`, and an empty fixtures file:

```bash
lemma connector init acme-iam --producer Acme
# Scaffolded acme-iam at /path/to/my-org/acme-iam.
# Edit connector.py and run lemma connector test acme-iam.
```

The `--producer` option sets the **signing identity** — the name the evidence log uses to look up Ed25519 keys when wrapping events into signed envelopes. Default is the project name. Pick a stable identity per upstream system; rotating producers means rotating keys.

The scaffolded layout:

```
acme-iam/
├── manifest.json     # identity + capabilities
├── connector.py      # the Connector subclass — your entry point
├── fixtures/
│   └── events.jsonl  # sample OCSF events for local testing
└── README.md
```

## 2. Look at what the scaffolder wrote

`connector.py` initially looks like this:

```python
from pathlib import Path
from lemma.sdk.reference.jsonl import JsonlConnector


class Connector(JsonlConnector):
    """The entry point `lemma connector test` looks for."""

    def __init__(self) -> None:
        super().__init__(
            source=Path(__file__).parent / "fixtures" / "events.jsonl",
            producer="Acme",
        )
```

The class name **must** be `Connector`. `lemma connector test` looks up that exact symbol and verifies it subclasses `lemma.sdk.connector.Connector`.

`JsonlConnector` reads OCSF events from a local JSONL file. It's there so the scaffolded project works end-to-end immediately — drop fixtures into `fixtures/events.jsonl` and your connector "works." When you're ready to talk to a real upstream, replace `JsonlConnector` with your own `collect()` implementation (next section).

## 3. Add a real `collect()` method

Replace the scaffolded stub with a connector that emits one OCSF `ComplianceFinding` per run:

```python
"""Acme IAM connector — emits one compliance finding per IAM policy review."""

from collections.abc import Iterable
from datetime import UTC, datetime

from lemma.models.connector_manifest import ConnectorManifest
from lemma.models.ocsf import ComplianceFinding, OcsfBaseEvent
from lemma.sdk.connector import Connector as BaseConnector


class Connector(BaseConnector):
    """The entry point `lemma connector test` looks for."""

    manifest = ConnectorManifest(
        name="acme-iam",
        version="0.1.0",
        producer="Acme",
        description="Acme IAM policy posture",
        capabilities=["iam-policy"],
    )

    def collect(self) -> Iterable[OcsfBaseEvent]:
        # In a real connector this reaches out to your IAM system and
        # turns whatever you find into one or more OCSF events. Here we
        # emit one synthetic finding so the tutorial is reproducible.
        now = datetime.now(UTC)
        uid = f"acme-iam:policy-review:{now.strftime('%Y-%m-%d')}"
        yield ComplianceFinding(
            class_name="Compliance Finding",
            category_uid=2000,
            category_name="Findings",
            type_uid=200301,
            activity_id=1,
            time=now,
            message="IAM policy review completed for the day.",
            status_id=1,
            metadata={
                "version": "1.3.0",
                "product": {"name": "Acme", "vendor_name": "Acme Corp", "uid": uid},
                "uid": uid,
            },
        )
```

A few load-bearing details:

- **`metadata.uid`** is the dedupe key. Make it stable per `(event_type, target, UTC date)` so re-running on the same day is a no-op. Operators run connectors on cron and the log refuses duplicate entries by design.
- **`metadata.product.name`** is the signing identity. It must match the manifest's `producer` field; otherwise the storage stage signs under the wrong key.
- **`time` must carry tzinfo.** The OCSF normalizer rejects naive datetimes — that's by design (OCSF wire format is UTC).

## 4. Validate against OCSF

`lemma connector test` imports your `connector.py`, exercises `collect()`, and validates every event against the OCSF schema:

```bash
lemma connector test acme-iam
# Validated 1 event(s) against the OCSF schema.
```

If your event is malformed (missing a required field, wrong `class_uid`, naive `time`), the test fails loud with a Pydantic validation error pointing at the offending field. Iterate until it's clean.

## 5. Run the connector against the evidence log

A connector emits OCSF events; `Connector.run(evidence_log)` is what threads them through the signing + hash-chain pipeline. From your project root:

```python
from pathlib import Path
from lemma.services.evidence_log import EvidenceLog

# Import your connector module
import sys; sys.path.insert(0, "acme-iam")
from connector import Connector

log = EvidenceLog(log_dir=Path(".lemma/evidence"))
result = Connector().run(log)
print(f"{result.ingested} ingested, {result.skipped_duplicates} skipped")
```

Or, if your connector is a first-party connector registered in `lemma evidence collect` (see `src/lemma/sdk/connectors/github.py` for the pattern), the CLI handles the wiring:

```bash
lemma evidence collect <connector-name> [connector-specific options]
```

## 6. Verify the signed output

Every event your connector emits is wrapped in a `SignedEvidence` envelope with an Ed25519 signature, a hash-chained link to the previous entry, and a three-stage provenance chain (source → normalization → storage):

```bash
lemma evidence log
# Shows the entry as PROVEN with the producer name you set
lemma evidence verify <entry-hash>
# Hash, chain, signature, and provenance chain all verify
```

The producer name your connector declares — `"Acme"` in the manifest — is the key identity the signing service uses. Per-producer keys live under `.lemma/keys/Acme/` and are auto-generated on first append.

## 7. Connect evidence to controls

If your connector knows which framework controls the events relate to, set `metadata.control_refs` on the event. Operators run `lemma evidence load` and the events become `Evidence` nodes in the compliance graph with `EVIDENCES` edges to the named controls:

```python
metadata={
    "version": "1.3.0",
    "product": {"name": "Acme", ...},
    "uid": uid,
    "control_refs": ["nist-800-53:ac-2", "nist-csf-2.0:pr.aa-1"],
}
```

`control_refs` is optional — without it the `Evidence` node still lands, just with no `EVIDENCES` edges.

## What the SDK does for you

Behind the scenes, `Connector.run()` handles:

- **Source provenance** — stamps each event with a `source` `ProvenanceRecord` naming `<producer>/<version>` as the actor (so the audit trail starts at your connector, not at the storage write).
- **Normalization** — calls `normalize_with_provenance()` so each event is OCSF-validated and a `normalization` provenance record is added.
- **Signing** — Ed25519 over a canonical hash of `(prev_entry_hash, event, pre-storage provenance)`. Provenance is part of the signed payload, so a tamperer can't rewrite it post-hoc.
- **Hash-chained storage** — `prev_hash → entry_hash` SHA-256 chain across the whole log, plus a final `storage` provenance record carrying the entry hash.
- **Dedupe** — events with `metadata.uid` already in today's log file are silently skipped.

You don't write any of that. You write `collect()` and the SDK handles the rest.

## Where to go from here

- See `src/lemma/sdk/connectors/github.py` for a real first-party connector that hits an HTTP API (with `httpx.MockTransport` test fixtures so CI doesn't touch the real service).
- See `src/lemma/sdk/connectors/aws.py` for a connector built on top of `boto3` with mocked client fixtures.
- See `src/lemma/sdk/connectors/okta.py` for a connector with a required auth token and clean rate-limit handling.

When you publish a connector, make sure the README documents:

- Required environment variables for auth.
- The `metadata.uid` shape so operators can predict dedupe behavior.
- Expected event count per run, so monitoring can spot drift.
