"""ChromaDB vector indexer for compliance framework controls.

Stores control prose as embeddings in a local ChromaDB instance
for semantic retrieval during control mapping.
"""

from __future__ import annotations

from pathlib import Path

import chromadb


class ControlIndexer:
    """Manages ChromaDB collections for indexed framework controls.

    Args:
        index_dir: Path to the local ChromaDB persistence directory.
    """

    def __init__(self, index_dir: Path) -> None:
        self._index_dir = index_dir
        self._index_dir.mkdir(parents=True, exist_ok=True)
        self._client = chromadb.PersistentClient(path=str(self._index_dir))

    def index_controls(self, framework_name: str, controls: list[dict]) -> None:
        """Index a list of control records into a named collection.

        Uses upsert semantics — re-indexing the same framework updates
        existing records without creating duplicates.

        Args:
            framework_name: Collection name (e.g., 'nist-800-53').
            controls: List of control dicts with 'id', 'title', 'prose', 'family'.
        """
        collection = self._client.get_or_create_collection(
            name=framework_name,
            metadata={"hnsw:space": "cosine"},
        )

        ids = []
        documents = []
        metadatas = []

        for control in controls:
            doc_text = f"{control['title']}: {control.get('prose', '')}"
            if not doc_text.strip() or doc_text.strip() == ":":
                doc_text = control["title"]

            ids.append(control["id"])
            documents.append(doc_text)
            metadatas.append(
                {
                    "title": control["title"],
                    "family": control.get("family", ""),
                    "control_id": control["id"],
                }
            )

        collection.upsert(ids=ids, documents=documents, metadatas=metadatas)

    def get_collection_stats(self, framework_name: str) -> dict:
        """Return stats for a framework's collection.

        Args:
            framework_name: Collection name to query.

        Returns:
            Dict with 'count' key. Returns count=0 if collection doesn't exist.
        """
        try:
            collection = self._client.get_collection(name=framework_name)
            return {"count": collection.count()}
        except Exception:
            return {"count": 0}

    def list_indexed_frameworks(self) -> list[str]:
        """Return names of all indexed framework collections.

        Returns:
            List of framework collection names.
        """
        collections = self._client.list_collections()
        return [c.name for c in collections]
