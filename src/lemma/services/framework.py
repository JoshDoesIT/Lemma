"""Framework management service — orchestrates parsing, indexing, and registry.

Provides the business logic layer between CLI commands and the
parser/indexer infrastructure. All framework operations go through
this service.
"""

from __future__ import annotations

import json
from pathlib import Path

from lemma.services.indexer import ControlIndexer
from lemma.services.parsers.oscal import parse_catalog


def get_framework_registry() -> dict[str, Path]:
    """Return the registry of bundled framework catalogs.

    Returns:
        Dict mapping framework short names to their file paths.
    """
    data_dir = Path(__file__).parent.parent / "data" / "frameworks"
    return {
        "nist-800-53": data_dir / "nist-800-53-rev5.json",
    }


def add_bundled_framework(name: str, *, project_dir: Path) -> dict:
    """Add a bundled framework by name — parse and index it.

    Args:
        name: Bundled framework short name (e.g., 'nist-800-53').
        project_dir: Root of the Lemma project (contains .lemma/).

    Returns:
        Dict with 'name', 'control_count', and 'indexed' keys.

    Raises:
        ValueError: If the framework name is not in the registry.
    """
    registry = get_framework_registry()

    if name not in registry:
        available = ", ".join(sorted(registry.keys()))
        msg = f"Unknown framework '{name}'. Available: {available}"
        raise ValueError(msg)

    catalog_path = registry[name]
    raw = json.loads(catalog_path.read_text())

    # OSCAL catalogs wrap the catalog object under a "catalog" key
    catalog_data = raw.get("catalog", raw)
    controls = parse_catalog(catalog_data)

    indexer = ControlIndexer(index_dir=project_dir / ".lemma" / "index")
    indexer.index_controls(name, controls)

    return {
        "name": name,
        "control_count": len(controls),
        "indexed": True,
    }


def list_frameworks(*, project_dir: Path) -> list[dict]:
    """List all indexed frameworks with metadata.

    Args:
        project_dir: Root of the Lemma project (contains .lemma/).

    Returns:
        List of dicts with 'name' and 'control_count' keys.
    """
    index_dir = project_dir / ".lemma" / "index"

    if not index_dir.exists():
        return []

    indexer = ControlIndexer(index_dir=index_dir)
    names = indexer.list_indexed_frameworks()

    frameworks = []
    for name in names:
        stats = indexer.get_collection_stats(name)
        frameworks.append(
            {
                "name": name,
                "control_count": stats["count"],
            }
        )

    return frameworks


def import_framework(file_path: Path, *, project_dir: Path) -> dict:
    """Import a user-provided framework file.

    Dispatches to the appropriate parser based on file extension:
    - .json → OSCAL catalog parser
    - .pdf → Docling parser (requires [ingest] extras)
    - .xlsx/.csv → Excel parser (requires [ingest] extras)

    Args:
        file_path: Path to the framework file.
        project_dir: Root of the Lemma project (contains .lemma/).

    Returns:
        Dict with 'name', 'control_count', and 'indexed' keys.

    Raises:
        ValueError: If the file format is not supported.
    """
    suffix = file_path.suffix.lower()
    name = file_path.stem

    if suffix == ".json":
        raw = json.loads(file_path.read_text())
        catalog_data = raw.get("catalog", raw)
        controls = parse_catalog(catalog_data)
    elif suffix == ".pdf":
        try:
            from lemma.services.parsers.pdf import parse_pdf

            controls = parse_pdf(file_path)
        except ImportError as e:
            msg = (
                "PDF import requires the [ingest] extras. "
                "Install with: pip install lemma-grc[ingest]"
            )
            raise ImportError(msg) from e
    elif suffix in {".xlsx", ".csv"}:
        try:
            from lemma.services.parsers.excel import parse_excel

            controls = parse_excel(file_path)
        except ImportError as e:
            msg = (
                "Excel import requires the [ingest] extras. "
                "Install with: pip install lemma-grc[ingest]"
            )
            raise ImportError(msg) from e
    else:
        supported = ".json, .pdf, .xlsx, .csv"
        msg = f"Unsupported file format '{suffix}'. Supported: {supported}"
        raise ValueError(msg)

    indexer = ControlIndexer(index_dir=project_dir / ".lemma" / "index")
    indexer.index_controls(name, controls)

    return {
        "name": name,
        "control_count": len(controls),
        "indexed": True,
    }
