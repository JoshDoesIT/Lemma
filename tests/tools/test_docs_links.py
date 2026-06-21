"""Documentation integrity guardrail (Refs #49).

Dependency-free checks that stand in for the "documentation site build
succeeds (no broken links, missing pages)" acceptance criterion without
requiring mkdocs + material to be installed:

1. Every `.md` page referenced in `mkdocs.yml`'s `nav` exists under `docs/`.
2. Every relative markdown link between docs points at a file that exists.

External (`http(s)://`) links and pure in-page anchors (`#section`) are not
checked — only the cross-file references that a site build would break on.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_DOCS = _REPO_ROOT / "docs"
_MKDOCS = _REPO_ROOT / "mkdocs.yml"

# Markdown inline link target: the bit inside (...) of [text](target).
_LINK_RE = re.compile(r"\]\(([^)]+)\)")


def _nav_md_references() -> list[str]:
    """Pull every `.md` path out of mkdocs.yml's nav section.

    Parsed by text rather than YAML so the `!!python/name:` tags in
    `markdown_extensions` don't need a custom loader.
    """
    text = _MKDOCS.read_text(encoding="utf-8")
    _, _, nav_tail = text.partition("\nnav:")
    assert nav_tail, "mkdocs.yml has no nav: section"
    return re.findall(r"([A-Za-z0-9_./-]+\.md)", nav_tail)


def test_every_nav_page_exists():
    missing = [ref for ref in _nav_md_references() if not (_DOCS / ref).is_file()]
    assert missing == [], f"mkdocs.yml nav references missing pages: {missing}"


def test_no_broken_relative_doc_links():
    broken: list[str] = []
    for md_file in sorted(_DOCS.rglob("*.md")):
        for raw_target in _LINK_RE.findall(md_file.read_text(encoding="utf-8")):
            target = raw_target.strip()
            # Skip external links, pure anchors, mailto, and images-by-URL.
            if target.startswith(("http://", "https://", "#", "mailto:")):
                continue
            # Strip any #anchor and surrounding whitespace/title.
            path_part = target.split("#", 1)[0].split(" ", 1)[0].strip()
            if not path_part or not path_part.endswith(".md"):
                continue
            resolved = (md_file.parent / path_part).resolve()
            if not resolved.is_file():
                broken.append(f"{md_file.relative_to(_REPO_ROOT)} -> {target}")
    assert broken == [], "Broken relative doc links:\n" + "\n".join(broken)
