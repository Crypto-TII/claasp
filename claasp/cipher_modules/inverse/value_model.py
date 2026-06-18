"""Value-class model for the inversion engine (Phase 3 scaffolding).

The engine currently reasons about "do these two bits carry the same value?" through
``all_equivalent_bits`` - an adjacency map (bit-name -> list of equivalent bit-names) that is
**not transitively closed**. Most of the engine's complexity is walking that map to decide
reachability/adjacency by hand.

This module replaces that adjacency map with a **union-find over bit identities**, so "same
value" is a single transitive relation: two bits are equivalent iff they share a root. This is
the data model that lets us eventually retire the ``output`` / ``output_updated`` bit-type
distinction (a value is a value; how it is sourced in the inverse graph is a separate, wiring
concern).

**Pure addition.** Nothing in the live ``cipher_inverse`` path depends on this yet. It exists to
be validated against the engine's own ``all_equivalent_bits`` (Phase 3b) before it takes over
(Phase 3c). Building it here changes no behaviour.
"""

from claasp.cipher_modules.inverse.equivalence import get_all_equivalent_bits


class UnionFind:
    """Disjoint-set forest with path compression and union by rank.

    Keys are arbitrary hashables (here, bit-name strings). Unknown keys are added on first use,
    so callers never have to pre-register identities.
    """

    def __init__(self):
        self._parent = {}
        self._rank = {}

    def add(self, x):
        if x not in self._parent:
            self._parent[x] = x
            self._rank[x] = 0

    def find(self, x):
        self.add(x)
        root = x
        while self._parent[root] != root:
            root = self._parent[root]
        # path compression
        while self._parent[x] != root:
            self._parent[x], x = root, self._parent[x]
        return root

    def union(self, a, b):
        root_a, root_b = self.find(a), self.find(b)
        if root_a == root_b:
            return
        if self._rank[root_a] < self._rank[root_b]:
            root_a, root_b = root_b, root_a
        self._parent[root_b] = root_a
        if self._rank[root_a] == self._rank[root_b]:
            self._rank[root_a] += 1

    def same(self, a, b):
        return self.find(a) == self.find(b)


class ValueClasses:
    """Transitive value-equivalence over bit identities ``"{component_id}_{position}_{type}"``.

    Built from the cipher's static equivalence relation (the forward wiring: an output bit and
    every input bit that reads it, plus sibling consumers, are the same value). Unlike the raw
    adjacency map, this is transitively closed - ``same(a, c)`` holds whenever ``a`` and ``c`` are
    connected through any chain, with no manual walking.
    """

    def __init__(self, cipher):
        self._uf = UnionFind()
        equivalences = get_all_equivalent_bits(cipher)
        for bit_name, neighbours in equivalences.items():
            self._uf.add(bit_name)
            for neighbour in neighbours:
                self._uf.union(bit_name, neighbour)

    def same(self, a, b):
        """Whether two bit-names are provably the same value."""
        return self._uf.same(a, b)

    def canonical(self, bit_name):
        """A stable representative for the bit's value class."""
        return self._uf.find(bit_name)
