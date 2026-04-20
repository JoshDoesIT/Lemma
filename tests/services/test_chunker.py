"""Tests for the policy document chunker.

Follows TDD: tests written BEFORE the implementation.
"""


class TestChunker:
    """Tests for splitting policy markdown into semantic chunks."""

    def test_chunk_single_policy(self, tmp_path):
        """Chunker splits a markdown document into multiple chunks."""
        from lemma.services.chunker import chunk_policies

        policies_dir = tmp_path / "policies"
        policies_dir.mkdir()
        (policies_dir / "access-control.md").write_text(
            "# Access Control Policy\n\n"
            "## Purpose\n\n"
            "This policy establishes access control requirements for all systems. "
            "All users must authenticate via single sign-on before accessing "
            "production resources.\n\n"
            "## Scope\n\n"
            "This policy applies to all employees and contractors. "
            "Third-party vendors must comply with these requirements "
            "when accessing company systems.\n\n"
            "## Requirements\n\n"
            "All privileged access must be logged and reviewed quarterly. "
            "Multi-factor authentication is required for administrative accounts. "
            "Service accounts must be rotated every 90 days.\n"
        )

        chunks = chunk_policies(policies_dir)
        assert len(chunks) >= 2
        assert all(c.get("text") for c in chunks)

    def test_chunk_preserves_sentence_boundaries(self, tmp_path):
        """Chunks do not split mid-sentence."""
        from lemma.services.chunker import chunk_policies

        policies_dir = tmp_path / "policies"
        policies_dir.mkdir()
        (policies_dir / "test.md").write_text(
            "# Test Policy\n\n"
            "First sentence about security controls. "
            "Second sentence about compliance requirements. "
            "Third sentence about audit procedures.\n"
        )

        chunks = chunk_policies(policies_dir)
        for chunk in chunks:
            text = chunk["text"].strip()
            # Should end with sentence-terminal punctuation
            assert text[-1] in ".!?:", f"Chunk does not end at sentence boundary: {text!r}"

    def test_chunk_assigns_ids(self, tmp_path):
        """Each chunk has a source file and position-based ID."""
        from lemma.services.chunker import chunk_policies

        policies_dir = tmp_path / "policies"
        policies_dir.mkdir()
        (policies_dir / "ir.md").write_text(
            "# Incident Response\n\n"
            "Incidents must be reported within 24 hours. "
            "The security team investigates all reported incidents.\n"
        )

        chunks = chunk_policies(policies_dir)
        assert len(chunks) >= 1
        assert all("id" in c for c in chunks)
        assert all("source" in c for c in chunks)
        assert chunks[0]["source"] == "ir.md"

    def test_chunk_empty_directory(self, tmp_path):
        """Chunking an empty directory returns an empty list."""
        from lemma.services.chunker import chunk_policies

        policies_dir = tmp_path / "policies"
        policies_dir.mkdir()

        chunks = chunk_policies(policies_dir)
        assert chunks == []

    def test_chunk_skips_non_markdown(self, tmp_path):
        """Chunker ignores non-markdown files."""
        from lemma.services.chunker import chunk_policies

        policies_dir = tmp_path / "policies"
        policies_dir.mkdir()
        (policies_dir / "README.txt").write_text("Not a policy")
        (policies_dir / "policy.md").write_text("# Policy\n\nThis is a real policy document.\n")

        chunks = chunk_policies(policies_dir)
        sources = {c["source"] for c in chunks}
        assert "README.txt" not in sources
