"""Union-Find data structure with path compression and union by rank.

Provides efficient disjoint set operations for single-linkage
clustering of semantically equivalent controls.
"""

from __future__ import annotations


class UnionFind:
    """Disjoint set data structure for clustering.

    Supports arbitrary string keys. New elements are lazily
    initialized on first access via find() or union().
    """

    def __init__(self) -> None:
        self._parent: dict[str, str] = {}
        self._rank: dict[str, int] = {}

    def find(self, x: str) -> str:
        """Find the representative of the set containing x.

        Uses path compression for amortized near-constant time.

        Args:
            x: Element to find.

        Returns:
            Representative element of x's set.
        """
        if x not in self._parent:
            self._parent[x] = x
            self._rank[x] = 0
            return x

        if self._parent[x] != x:
            self._parent[x] = self.find(self._parent[x])
        return self._parent[x]

    def union(self, x: str, y: str) -> None:
        """Merge the sets containing x and y.

        Uses union by rank to keep trees balanced.

        Args:
            x: First element.
            y: Second element.
        """
        rx = self.find(x)
        ry = self.find(y)

        if rx == ry:
            return

        if self._rank[rx] < self._rank[ry]:
            self._parent[rx] = ry
        elif self._rank[rx] > self._rank[ry]:
            self._parent[ry] = rx
        else:
            self._parent[ry] = rx
            self._rank[rx] += 1

    def clusters(self, elements: list[str]) -> dict[str, set[str]]:
        """Return all clusters as a dict mapping representative to members.

        Args:
            elements: List of all elements to group.

        Returns:
            Dict mapping representative key to set of members.
        """
        groups: dict[str, set[str]] = {}
        for elem in elements:
            root = self.find(elem)
            if root not in groups:
                groups[root] = set()
            groups[root].add(elem)
        return groups
