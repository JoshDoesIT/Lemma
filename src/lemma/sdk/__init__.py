"""Lemma Connector SDK — Python.

Authors build connectors by subclassing ``Connector``, declaring a
``ConnectorManifest``, and implementing ``collect()`` to yield
``OcsfBaseEvent`` instances. ``Connector.run(evidence_log)`` drives the
event stream into an append-only, signed, hash-chained evidence log.
"""

from lemma.models.connector_manifest import ConnectorManifest
from lemma.sdk.connector import CollectResult, Connector

__all__ = ["CollectResult", "Connector", "ConnectorManifest"]
