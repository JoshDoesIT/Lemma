"""The ``Connector`` abstract base class and its execution runtime.

A connector is any Python class that:

1. Declares a ``ConnectorManifest`` as a class attribute. The
   manifest's ``producer`` is the identity used for signing — the
   keystore under ``.lemma/keys/<producer>/`` holds the Ed25519 keys
   this connector's events will be signed with.
2. Implements ``collect()`` to yield ``OcsfBaseEvent`` instances.

``Connector.run(evidence_log)`` drives the event stream into the
append-only evidence log, returning a ``CollectResult`` summarising
what was ingested and what was skipped by the dedupe guard.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass

from lemma.models.connector_manifest import ConnectorManifest
from lemma.models.ocsf import OcsfBaseEvent
from lemma.models.signed_evidence import ProvenanceRecord
from lemma.services.evidence_log import EvidenceLog

CONNECTOR_SDK_VERSION = "lemma.sdk.connector/1"


@dataclass(frozen=True)
class CollectResult:
    """Summary of one connector run.

    Attributes:
        ingested: Count of events newly written to the evidence log.
        skipped_duplicates: Count of events skipped because the dedupe
            guard recognised them (same ``metadata.uid`` or identical
            content already on today's log file).
    """

    ingested: int
    skipped_duplicates: int


class Connector(ABC):
    """Base class every connector extends.

    Subclasses must set ``manifest`` as a class attribute and implement
    ``collect()``. The base class provides ``run()`` to tie a connector
    to an ``EvidenceLog``.
    """

    manifest: ConnectorManifest

    @abstractmethod
    def collect(self) -> Iterable[OcsfBaseEvent]:
        """Yield OCSF events representing evidence collected from the source.

        Implementations may raise exceptions on unrecoverable source
        failures; the caller decides how to handle them.
        """
        raise NotImplementedError

    def run(self, evidence_log: EvidenceLog) -> CollectResult:
        """Iterate ``collect()`` and append every event to ``evidence_log``.

        Each event is stamped with a ``source`` provenance record naming
        the connector (``<producer>/<version>``) as the origin of the
        data. The hash is over the typed event — the earliest structured
        form available at this boundary. Connectors with access to the
        pre-typed upstream payload may override this by constructing
        their own provenance and bypassing ``run()``.

        Returns a summary of what was ingested vs skipped. Signing,
        chaining, and dedupe are handled inside ``EvidenceLog.append``.
        """
        ingested = 0
        skipped = 0
        actor = f"{self.manifest.producer}/{self.manifest.version}"
        for event in self.collect():
            source = ProvenanceRecord(
                stage="source",
                actor=actor,
                content_hash=hashlib.sha256(event.model_dump_json().encode()).hexdigest(),
            )
            wrote = evidence_log.append(event, provenance=[source])
            if wrote:
                ingested += 1
            else:
                skipped += 1
        return CollectResult(ingested=ingested, skipped_duplicates=skipped)
