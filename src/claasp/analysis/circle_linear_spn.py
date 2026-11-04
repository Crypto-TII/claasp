"""Exact free-subgroup search for parallel binary SPNs, independent of primitive name.

The optimized backend requires a four-element perfect S-box subgroup with
a flat/curved type flip, binary cell diffusion and a cell permutation.
It verifies these properties instead of assuming that an arbitrary S-box has
them. Outside this subgroup use the general CircleNetwork semantics.
"""

from dataclasses import dataclass, field
from fractions import Fraction
from functools import cached_property

from claasp.semantics.cryptanalysis._circle_algebra import (
    bits,
    parity,
    radical,
    reduce_equations,
)
from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace, CircleBasis
from claasp.semantics.cryptanalysis.circle_linear import (
    AffineKeyConditions,
    CircleAffineLayer,
)


@dataclass(frozen=True, slots=True)
class SubgroupTrail:
    """A canonical subgroup trail, with exact local survival conditions.

    Codes have cell-0 in bit 0, q in the low half and s in the high half,
    using this module's coordinate convention. ``input_mask`` and ``output_mask`` are ordinary packed
    character labels, with cell 0 most significant. No hull claim is made.

    EXAMPLES::

        >>> from claasp.primitives import Craft
        >>> trail = Craft(number_of_rounds=8).circle_linear_model().trail(0x01190000)
        >>> trail.cost, trail.input_code, trail.conditions.key_count == 2**120
        (8, 1918500864, True)
        >>> trail.contribution(0) in (Fraction(1, 256), Fraction(-1, 256))
        True
    """

    input_code: int
    output_code: int
    input_mask: int
    output_mask: int
    cost: int
    conditions: AffineKeyConditions
    _affine_steps: tuple = field(repr=False)
    _sbox_sign: int = field(repr=False)

    def contribution(self, key: int) -> Fraction:
        """Evaluate the signed trail product for one key in global coordinates.

        EXAMPLES::

            >>> from claasp.primitives import Craft
            >>> Craft(number_of_rounds=8).circle_linear_model().trail(0x01190000).contribution(0) != 0
            True
        """
        if not self.conditions.contains(key):
            return Fraction(0)
        result = Fraction(self._sbox_sign)
        for transition in self._affine_steps:
            result *= transition.coefficient(key)
        return result


@dataclass(frozen=True, slots=True)
class SubgroupSearchResult:
    """Certified optimum only inside a validated four-element free subgroup.

    EXAMPLES::

        >>> from claasp.primitives import Craft
        >>> result = Craft(number_of_rounds=8).circle_linear_model().search()
        >>> result.cost, result.optimal_mask_count, result.complete
        (8, 24, True)
        >>> result.scope
        'four-element perfect subgroup'
    """

    cost: int
    optimal_mask_count: int
    representative: SubgroupTrail
    complete: bool = True
    scope: str = "four-element perfect subgroup"


class FreeSubgroupSPN:
    """A supplied binary SPN with a verified free flat/curved type flip.

    Each round applies diffusion, an optional affine key/constant addition,
    ``permutation`` (output[i]=input[permutation[i]]), then the S-box. Supply
    ``affine_layers`` in encryption order, using global key coordinates.
    Omitting them describes an unkeyed SPN with the same diffusion.

    EXAMPLES::

        >>> from claasp.primitives import Craft
        >>> craft = Craft(number_of_rounds=14).circle_linear_model()
        >>> craft.gamma, craft.eta
        (9, 7)
        >>> craft.trail(0x00720000).cost
        22
    """

    def __init__(
        self,
        bibrace: BinaryBibrace,
        sbox: tuple[int, ...],
        diffusion_rows: tuple[int, ...],
        permutation: tuple[int, ...],
        rounds: int,
        *,
        affine_layers: tuple[CircleAffineLayer, ...] | None = None,
    ) -> None:
        if isinstance(rounds, bool) or not isinstance(rounds, int) or rounds < 1:
            raise ValueError("rounds must be positive")
        self.bibrace = bibrace
        self.sbox = tuple(sbox)
        self.diffusion_rows = tuple(diffusion_rows)
        self.permutation = tuple(permutation)
        self.rounds = rounds
        self.cells = len(self.diffusion_rows)
        if self.cells < 1 or sorted(self.permutation) != list(range(self.cells)):
            raise ValueError("permutation must cover the diffusion cells")
        from claasp.semantics.cryptanalysis._circle_algebra import integer

        for row in self.diffusion_rows:
            integer(row, self.cells, "diffusion row")
        if len(reduce_equations(tuple((row, 0) for row in self.diffusion_rows))) != self.cells:
            raise ValueError("the free-subgroup backend requires invertible diffusion")
        self.basis = CircleBasis((bibrace,) * self.cells)
        self.walsh = bibrace.walsh_table(self.sbox)
        size = 1 << bibrace.width
        if sorted(self.sbox) != list(range(size)):
            raise ValueError("the free-subgroup backend requires a permutation S-box")
        perfect = {a: b for a in range(size) for b in range(size) if abs(self.walsh[a][b]) == size}
        gamma = [
            a
            for a, b in perfect.items()
            if a == b and any(t.bit_count() == 2 for t in bibrace.character_polynomial(a))
        ]
        eta = [
            a
            for a in perfect
            if a and not any(t.bit_count() == 2 for t in bibrace.character_polynomial(a))
        ]
        if len(perfect) != 4 or len(gamma) != 1 or len(eta) != 1:
            raise ValueError("S-box has no four-element perfect subgroup with a free type flip")
        self.gamma, self.eta = gamma[0], eta[0]
        if (
            perfect[self.eta] != self.gamma ^ self.eta
            or perfect.get(self.gamma ^ self.eta) != self.eta
        ):
            raise ValueError("perfect S-box masks do not have the required type flip")
        # Otherwise additional diffusion branches can remain inside F, and
        # deterministic M^T propagation would not search the whole subgroup.
        gamma_radical = radical(bibrace.character_polynomial(self.gamma), bibrace.width)
        eta_linear = sum(bibrace.character_polynomial(self.eta))
        if all(not parity(eta_linear & vector) for vector in gamma_radical):
            raise ValueError(
                "perfect subgroup intersects its mask-displacement space; use CircleNetwork"
            )
        self.form_rank = bibrace.width - len(
            radical(bibrace.character_polynomial(self.gamma), bibrace.width)
        )
        rows = self.binary_rows()
        if affine_layers is None:
            affine_layers = tuple(
                CircleAffineLayer(self.basis, self.basis, rows) for _ in range(rounds)
            )
        self.affine_layers = tuple(affine_layers)
        if len(self.affine_layers) != rounds or any(
            layer.input_basis != self.basis
            or layer.output_basis != self.basis
            or layer.rows != rows
            for layer in self.affine_layers
        ):
            raise ValueError("affine layers must match the declared basis and cell diffusion")
        if len({layer.key_width for layer in self.affine_layers}) != 1:
            raise ValueError("all rounds must use the same global key coordinates")
        self.key_width = self.affine_layers[0].key_width

    def binary_rows(self) -> tuple[int, ...]:
        """Expand the cell-XOR diffusion into LSB-ordered binary rows.

        EXAMPLES::

            >>> from claasp.primitives import Craft
            >>> len(Craft(number_of_rounds=1).circle_linear_model().binary_rows())
            64
        """
        w = self.bibrace.width
        rows = [0] * (w * self.cells)
        for output_cell, row in enumerate(self.diffusion_rows):
            for bit in range(w):
                rows[w * (self.cells - 1 - output_cell) + bit] = sum(
                    1 << (w * (self.cells - 1 - source) + bit) for source in bits(row)
                )
        return tuple(rows)

    def _permute_backward(self, value: int) -> int:
        return sum(((value >> i) & 1) << self.permutation[i] for i in range(self.cells))

    def _diffuse_backward(self, value: int) -> int:
        result = 0
        for i in bits(value):
            result ^= self.diffusion_rows[i]
        return result

    def _labels(self, q: int, s: int) -> int:
        result = 0
        for i in range(self.cells):
            result = (result << self.bibrace.width) | (
                (self.gamma if q >> i & 1 else 0) ^ (self.eta if s >> i & 1 else 0)
            )
        return result

    def trail(self, output_code: int) -> SubgroupTrail:
        """Verify a canonical trail and derive its combined affine key class.

        EXAMPLES::

            >>> from claasp.primitives import Craft
            >>> t = Craft(number_of_rounds=12).circle_linear_model().trail(0x10050000)
            >>> hex(t.input_code), t.cost, t.conditions.rank
            ('0x2b8e0000', 18, 12)
        """
        from claasp.semantics.cryptanalysis._circle_algebra import integer

        integer(output_code, 2 * self.cells, "output code")
        mask = (1 << self.cells) - 1
        q, s = output_code & mask, output_code >> self.cells
        output_label = self._labels(q, s)
        conditions = AffineKeyConditions(self.key_width)
        transitions = []
        sign = 1
        cost = 0
        for layer in reversed(self.affine_layers):
            # Backward S-box: sigma is an involution on this validated F.
            before_q = q ^ s
            for i in range(self.cells):
                a = (self.gamma if before_q >> i & 1 else 0) ^ (self.eta if s >> i & 1 else 0)
                b = (self.gamma if q >> i & 1 else 0) ^ (self.eta if s >> i & 1 else 0)
                sign *= 1 if self.walsh[a][b] > 0 else -1
            q = self._permute_backward(before_q)
            s = self._permute_backward(s)
            after = self._labels(q, s)
            q, s = self._diffuse_backward(q), self._diffuse_backward(s)
            transition = layer.transition(self._labels(q, s), after)
            state_width = self.basis.width
            state_poly = frozenset(
                term for term in transition._polynomial if term < 1 << state_width
            )
            cost += (state_width - len(radical(state_poly, state_width))) // 2
            conditions = conditions.intersect(transition.conditions)
            transitions.append(transition)
        return SubgroupTrail(
            q | (s << self.cells),
            output_code,
            self._labels(q, s),
            output_label,
            cost,
            conditions,
            tuple(transitions),
            sign,
        )

    @cached_property
    def _column_costs(self) -> tuple[tuple[int, tuple[int, ...], tuple[int, ...]], ...]:
        # Factor disjoint diffusion blocks before tabulating ranks. This is
        # generic connectivity detection, not a CRAFT matrix special case.
        groups = [{i} for i in range(self.cells)]
        for row in self.diffusion_rows:
            support = set(bits(row))
            touched = [group for group in groups if group & support]
            merged = set().union(*touched)
            groups = [group for group in groups if group not in touched] + [merged]
        tables = []
        for group in groups:
            outputs = tuple(
                i for i, row in enumerate(self.diffusion_rows) if any(row >> j & 1 for j in group)
            )
            table = []
            for pattern in range(1 << len(outputs)):
                rows = [0] * self.cells
                for index in bits(pattern):
                    row_support = tuple(bits(self.diffusion_rows[outputs[index]]))
                    for a in row_support:
                        for b in row_support:
                            if a != b:
                                rows[a] ^= 1 << b
                rank = len(reduce_equations(tuple((row, 0) for row in rows)))
                table.append(rank * self.form_rank // 2)
            tables.append((sum(1 << i for i in outputs), outputs, tuple(table)))
        return tuple(tables)

    def _cost(self, value: int) -> int:
        return sum(
            table[sum(((value >> index) & 1) << i for i, index in enumerate(outputs))]
            for _, outputs, table in self._column_costs
        )

    def search(self, *, maximum_factor_states: int = 1 << 16) -> SubgroupSearchResult:
        """Certify the subgroup optimum by two independent n-cell searches.

        The spatial map commutes with sigma, so alternating round costs
        depend separately on q and q XOR s. This replaces 2**(2*n) masks by
        two searches of 2**n states. A nontrivial zero-cost kernel is handled
        explicitly. Ties prefer the largest exact key class then lowest code.
        Conflicting affine offsets are checked for every tied candidate.

        EXAMPLES::

            >>> from claasp.primitives import Craft
            >>> r = Craft(number_of_rounds=8).circle_linear_model().search()
            >>> r.cost, r.optimal_mask_count, hex(r.representative.output_code)
            (8, 24, '0x1190000')
        """
        size = 1 << self.cells
        if size > maximum_factor_states:
            raise ValueError("subgroup search exceeds maximum_factor_states")
        spatial = [0] * size
        costs = [0] * size
        for value in range(size):
            permuted = self._permute_backward(value)
            spatial[value] = self._diffuse_backward(permuted)
            costs[value] = self._cost(permuted)
        f, g = [0] * size, [0] * size
        for value in range(1, size):
            current = value
            for r in range(self.rounds):
                if r & 1:
                    f[value] += costs[current]
                else:
                    g[value] += costs[current]
                current = spatial[current]
        # Include nonzero masks in the kernels, not just nonzero codewords.
        minimum = min(min(f[1:]), min(g[1:]))
        left = [i for i, cost in enumerate(f) if cost <= minimum]
        right = [i for i, cost in enumerate(g) if cost <= minimum]
        if len(left) * len(right) > maximum_factor_states:
            raise ValueError("optimal-mask enumeration exceeds maximum_factor_states")
        codes = [
            a | ((a ^ b) << self.cells)
            for a in left
            for b in right
            if (a or b) and f[a] + g[b] == minimum
        ]
        if len(codes) > maximum_factor_states:
            raise ValueError("too many optimal masks; increase maximum_factor_states")
        trails = [self.trail(code) for code in sorted(codes)]
        valid = [trail for trail in trails if trail.conditions.consistent]
        if not valid:
            raise ValueError("no minimum-cost trail survives the supplied affine key schedule")
        representative = min(
            valid, key=lambda trail: (-trail.conditions.key_count, trail.output_code)
        )
        return SubgroupSearchResult(minimum, len(valid), representative)


__all__ = ["FreeSubgroupSPN", "SubgroupSearchResult", "SubgroupTrail"]
