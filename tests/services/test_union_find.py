"""Tests for Union-Find data structure.

Follows TDD: tests written BEFORE implementation.
"""

from __future__ import annotations


class TestUnionFind:
    """Tests for the Union-Find data structure."""

    def test_find_returns_self_initially(self):
        """Each element is its own representative initially."""
        from lemma.services.union_find import UnionFind

        uf = UnionFind()
        assert uf.find("a") == "a"
        assert uf.find("b") == "b"

    def test_union_merges_sets(self):
        """After union, both elements share the same representative."""
        from lemma.services.union_find import UnionFind

        uf = UnionFind()
        uf.union("a", "b")
        assert uf.find("a") == uf.find("b")

    def test_union_transitivity(self):
        """If a~b and b~c, then a~c via transitivity."""
        from lemma.services.union_find import UnionFind

        uf = UnionFind()
        uf.union("a", "b")
        uf.union("b", "c")
        assert uf.find("a") == uf.find("c")

    def test_clusters_returns_groups(self):
        """clusters() returns a dict mapping representatives to members."""
        from lemma.services.union_find import UnionFind

        uf = UnionFind()
        uf.union("a", "b")
        uf.union("c", "d")
        # "e" is standalone

        groups = uf.clusters(["a", "b", "c", "d", "e"])
        # Should have 3 groups: {a,b}, {c,d}, {e}
        assert len(groups) == 3

        # Check group membership
        found_ab = False
        found_cd = False
        found_e = False
        for members in groups.values():
            if members == {"a", "b"}:
                found_ab = True
            elif members == {"c", "d"}:
                found_cd = True
            elif members == {"e"}:
                found_e = True

        assert found_ab
        assert found_cd
        assert found_e
