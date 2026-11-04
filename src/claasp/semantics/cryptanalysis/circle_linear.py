"""Exact signed circle-linear coefficients, affine key classes and small networks.

Affine rows use LSB output order: row i is the packed input mask for output bit
i. A layer may regroup cells or be noninvertible. Dense lookup and network
operations require explicit finite budgets; binary affine transitions do not.
"""

from dataclasses import dataclass, field
from fractions import Fraction
from math import log2

from claasp.semantics.cryptanalysis._circle_algebra import (
    Polynomial,
    bits,
    evaluate,
    gauss_sum,
    integer,
    parity,
    radical,
    reduce_equations,
    solution,
    substitute,
)
from claasp.semantics.cryptanalysis.bibrace import CircleBasis


@dataclass(frozen=True, slots=True)
class AffineKeyConditions:
    """An exact affine subspace of a declared packed binary key domain.

    Equations are pairs ``(mask, rhs)`` meaning parity(mask & key) == rhs.
    Counts refer to this domain, not to master keys of an unspecified schedule.

    EXAMPLES::

        >>> keys = AffineKeyConditions(4, ((3, 1), (6, 0)))
        >>> keys.rank, keys.key_count, keys.contains(1)
        (2, 4, True)
        >>> keys.intersect(AffineKeyConditions(4, ((3, 0),))).key_count
        0
    """

    width: int
    equations: tuple[tuple[int, int], ...] = ()

    def __post_init__(self) -> None:
        if isinstance(self.width, bool) or not isinstance(self.width, int) or self.width < 0:
            raise ValueError("key width must be a nonnegative integer")
        equations = tuple((row, rhs) for row, rhs in self.equations)
        for row, rhs in equations:
            integer(row, self.width, "equation mask")
            integer(rhs, 1, "equation rhs")
        object.__setattr__(self, "equations", reduce_equations(equations))

    @property
    def rank(self) -> int:
        """Number of independent constraints (zero for an inconsistent system).

        EXAMPLES::

            >>> AffineKeyConditions(8, ((1, 0), (1, 0))).rank
            1
        """
        return len(self.equations) if self.consistent else 0

    @property
    def consistent(self) -> bool:
        """Whether at least one key satisfies the conditions.

        EXAMPLES::

            >>> AffineKeyConditions(0, ((0, 1),)).consistent
            False
        """
        return self.equations != ((0, 1),)

    @property
    def key_count(self) -> int:
        """Exact class size in the declared key domain.

        EXAMPLES::

            >>> AffineKeyConditions(128, ((1, 0),)).key_count == 2**127
            True
        """
        return (1 << (self.width - self.rank)) if self.consistent else 0

    def contains(self, key: int) -> bool:
        """Check membership without dropping inconsistent equations.

        EXAMPLES::

            >>> AffineKeyConditions(2, ((3, 1),)).contains(3)
            False
        """
        integer(key, self.width, "key")
        return all(parity(row & key) == rhs for row, rhs in self.equations)

    def intersect(self, other: "AffineKeyConditions") -> "AffineKeyConditions":
        """Combine conditions sharing the same key coordinates.

        EXAMPLES::

            >>> AffineKeyConditions(3).intersect(AffineKeyConditions(3, ((1, 1),))).rank
            1
        """
        if self.width != other.width:
            raise ValueError("key coordinate widths differ")
        return AffineKeyConditions(self.width, self.equations + other.equations)

    def pullback(
        self, rows: tuple[int, ...], master_width: int, *, offset: int = 0
    ) -> "AffineKeyConditions":
        """Express this key class through a supplied affine master-key schedule.

        Row i gives the master-key combination for bit i of this domain.
        Nonlinear key schedules require a different constraint representation;
        this method never assumes their subkeys are independent.

        EXAMPLES::

            >>> subkeys = AffineKeyConditions(2, ((3, 0),))
            >>> subkeys.pullback((1, 1), 1).key_count
            2
            >>> subkeys.pullback((1, 1), 1, offset=1).key_count
            0
        """
        AffineKeyConditions(master_width)
        if len(rows) != self.width:
            raise ValueError("one schedule row is required per subkey bit")
        integer(offset, self.width, "schedule offset")
        for row in rows:
            integer(row, master_width, "schedule row")
        equations = []
        for mask, rhs in self.equations:
            row = 0
            for i in bits(mask):
                row ^= rows[i]
            equations.append((row, rhs ^ parity(mask & offset)))
        return AffineKeyConditions(master_width, tuple(equations))

    def project(self, positions: tuple[int, ...]) -> "AffineKeyConditions":
        """Existentially eliminate other coordinates, retaining the given bit order.

        This can extract public-tweak compatibility conditions from a joint
        master-key/tweak system. Position zero in the returned domain is the
        first supplied position; discarded variables are not fixed to zero.

        EXAMPLES::

            >>> joint = AffineKeyConditions(3, ((3, 0), (6, 1)))
            >>> joint.project((0, 2)).equations
            ((3, 1),)
            >>> joint.project((1,)).key_count
            2
        """
        positions = tuple(positions)
        if len(set(positions)) != len(positions) or any(
            isinstance(i, bool) or not isinstance(i, int) or not 0 <= i < self.width
            for i in positions
        ):
            raise ValueError("projection positions must be distinct valid bit indices")
        remaining = list(self.equations)
        kept = set(positions)
        for i in range(self.width):
            if i in kept:
                continue
            pivot = next((j for j, (row, _) in enumerate(remaining) if row >> i & 1), None)
            if pivot is None:
                continue
            row, rhs = remaining.pop(pivot)
            remaining = [(a ^ row, b ^ rhs) if a >> i & 1 else (a, b) for a, b in remaining]
        return AffineKeyConditions(
            len(positions),
            tuple(
                (sum(((row >> old) & 1) << new for new, old in enumerate(positions)), rhs)
                for row, rhs in remaining
            ),
        )


@dataclass(frozen=True, slots=True)
class AffineCircleTransition:
    """One exact affine-layer transition with a key-dependent sign.

    ``magnitude`` is constant on ``conditions`` and zero outside that class.
    This describes a local coefficient, never a full endpoint correlation lower bound.

    EXAMPLES::

        >>> from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace
        >>> basis = CircleBasis((BinaryBibrace(1),))
        >>> layer = CircleAffineLayer(basis, basis, (1,), key_width=1, key_rows=(1,))
        >>> transition = layer.transition(1, 1)
        >>> transition.coefficient(0), transition.coefficient(1)
        (Fraction(1, 1), Fraction(-1, 1))
    """

    input_mask: int
    output_mask: int
    state_width: int
    conditions: AffineKeyConditions
    _polynomial: Polynomial = field(repr=False)

    def coefficient(self, key: int = 0) -> Fraction:
        """Evaluate the exact signed coefficient at one fixed key.

        EXAMPLES::

            >>> from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace
            >>> basis = CircleBasis((BinaryBibrace(1),))
            >>> CircleAffineLayer(basis, basis, (1,)).transition(0, 1).coefficient()
            Fraction(0, 1)
        """
        integer(key, self.conditions.width, "key")
        state_mask = (1 << self.state_width) - 1
        poly: set[int] = set()
        for term in self._polynomial:
            key_term = term >> self.state_width
            if key & key_term == key_term:
                poly.symmetric_difference_update((term & state_mask,))
        return gauss_sum(frozenset(poly))

    @property
    def magnitude(self) -> Fraction:
        """Absolute coefficient on the permitted key class.

        EXAMPLES::

            >>> from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace
            >>> basis = CircleBasis((BinaryBibrace(1),))
            >>> CircleAffineLayer(basis, basis, (1,)).transition(1, 1).magnitude
            Fraction(1, 1)
        """
        if not self.conditions.consistent:
            return Fraction(0)
        return abs(self.coefficient(solution(self.conditions.equations)))


@dataclass(frozen=True, slots=True)
class CircleAffineLayer:
    """A grouped binary affine map ``y = A*x ^ B*key ^ offset``.

    Key addition belongs in this same layer when analyzing its interaction
    with diffusion. All cells may use different supplied bibraces.

    EXAMPLES::

        >>> from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace
        >>> basis = CircleBasis((BinaryBibrace.craft(),))
        >>> layer = CircleAffineLayer(basis, basis, (1, 2, 4, 8), key_width=4, key_rows=(1, 2, 4, 8))
        >>> t = layer.transition(1, 1)
        >>> t.conditions.key_count, t.coefficient(0), t.coefficient(1)
        (4, Fraction(1, 1), Fraction(0, 1))
    """

    input_basis: CircleBasis
    output_basis: CircleBasis
    rows: tuple[int, ...]
    offset: int = 0
    key_width: int = 0
    key_rows: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "rows", tuple(self.rows))
        if len(self.rows) != self.output_basis.width:
            raise ValueError("one affine row is required per output bit")
        for row in self.rows:
            integer(row, self.input_basis.width, "affine row")
        integer(self.offset, self.output_basis.width, "offset")
        AffineKeyConditions(self.key_width)
        keys = tuple(self.key_rows) if self.key_rows else (0,) * len(self.rows)
        if len(keys) != len(self.rows):
            raise ValueError("one key row is required per output bit")
        for row in keys:
            integer(row, self.key_width, "key row")
        object.__setattr__(self, "key_rows", keys)

    def transition(self, input_mask: int, output_mask: int) -> AffineCircleTransition:
        """Derive a quadratic Gauss sum and exact affine weak-key conditions.

        EXAMPLES::

            >>> from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace
            >>> basis = CircleBasis((BinaryBibrace(2),))
            >>> CircleAffineLayer(basis, basis, (2, 1)).transition(1, 2).magnitude
            Fraction(1, 1)
        """
        n = self.input_basis.width
        images = []
        for i, (row, key_row) in enumerate(zip(self.rows, self.key_rows)):
            image = frozenset(1 << j for j in bits(row | (key_row << n)))
            if self.offset >> i & 1:
                image ^= frozenset((0,))
            images.append(image)
        poly = self.input_basis.character_polynomial(input_mask) ^ substitute(
            self.output_basis.character_polynomial(output_mask), tuple(images)
        )
        state_limit = (1 << n) - 1
        state_poly = frozenset(term for term in poly if term and term <= state_limit)
        equations = []
        for vector in radical(state_poly, n):
            key_row = 0
            for term in poly:
                state_part = term & state_limit
                key_part = term >> n
                if key_part and state_part and parity(state_part & vector):
                    key_row ^= key_part
            equations.append((key_row, evaluate(state_poly, vector)))
        return AffineCircleTransition(
            input_mask, output_mask, n, AffineKeyConditions(self.key_width, tuple(equations)), poly
        )

    def coefficient(self, input_mask: int, output_mask: int, key: int = 0) -> Fraction:
        """Compute one signed entry without constructing a dense matrix.

        EXAMPLES::

            >>> from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace
            >>> basis = CircleBasis((BinaryBibrace(1),))
            >>> CircleAffineLayer(basis, basis, (1,), offset=1).coefficient(1, 1)
            Fraction(-1, 1)
        """
        return self.transition(input_mask, output_mask).coefficient(key)


@dataclass(frozen=True, slots=True)
class CircleLookupLayer:
    """A bounded exact truth-table layer, including arbitrary small functions.

    EXAMPLES::

        >>> from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace
        >>> basis = CircleBasis((BinaryBibrace(1),))
        >>> CircleLookupLayer(basis, basis, (1, 0)).coefficient(1, 1)
        Fraction(-1, 1)
    """

    input_basis: CircleBasis
    output_basis: CircleBasis
    table: tuple[int, ...]
    maximum_inputs: int = 1 << 16
    key_width: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        if 1 << self.input_basis.width > self.maximum_inputs:
            raise ValueError("lookup layer exceeds maximum_inputs")
        object.__setattr__(self, "table", tuple(self.table))
        if len(self.table) != 1 << self.input_basis.width:
            raise ValueError("truth table must cover the input domain")
        for value in self.table:
            integer(value, self.output_basis.width, "table value")

    def coefficient(self, input_mask: int, output_mask: int, key: int = 0) -> Fraction:
        """Sum the complete domain using the declared input/output characters.

        EXAMPLES::

            >>> from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace
            >>> basis = CircleBasis((BinaryBibrace(1),))
            >>> CircleLookupLayer(basis, basis, (0, 0)).coefficient(1, 0)
            Fraction(0, 1)
        """
        integer(input_mask, self.input_basis.width, "input mask")
        integer(output_mask, self.output_basis.width, "output mask")
        if key:
            raise ValueError("a lookup layer has no symbolic key")
        return Fraction(
            sum(
                1
                - 2
                * (
                    self.input_basis.character(input_mask, x)
                    ^ self.output_basis.character(output_mask, y)
                )
                for x, y in enumerate(self.table)
            ),
            len(self.table),
        )


@dataclass(frozen=True, slots=True)
class CircleTrail:
    """A product of signed local coefficients, explicitly a trail contribution.

    EXAMPLES::

        >>> trail = CircleTrail((1, 1, 1), (Fraction(-1, 2), Fraction(1, 2)))
        >>> trail.coefficient, trail.weight
        (Fraction(-1, 4), 2.0)
    """

    masks: tuple[int, ...]
    coefficients: tuple[Fraction, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "masks", tuple(self.masks))
        object.__setattr__(self, "coefficients", tuple(Fraction(c) for c in self.coefficients))
        if not self.coefficients or len(self.masks) != len(self.coefficients) + 1:
            raise ValueError("a trail needs one coefficient per pair of boundary masks")
        if any(abs(c) > 1 for c in self.coefficients):
            raise ValueError("local correlation magnitudes cannot exceed one")

    @property
    def coefficient(self) -> Fraction:
        """Signed trail contribution, not an endpoint-correlation lower bound.

        EXAMPLES::

            >>> CircleTrail((0, 0), (Fraction(1),)).coefficient
            Fraction(1, 1)
        """
        result = Fraction(1)
        for coefficient in self.coefficients:
            result *= coefficient
        return result

    @property
    def weight(self) -> float:
        """Minus log2 of the absolute contribution; zero has infinite weight.

        EXAMPLES::

            >>> CircleTrail((0, 1), (Fraction(0),)).weight
            inf
        """
        return -log2(abs(self.coefficient)) if self.coefficient else float("inf")


class CircleNetwork:
    """Compose exact local layers for bounded trail search and signed hull sums.

    Adjacent character bases must match exactly. Unlike multiplying selected
    trails, ``correlation`` sums *all* intermediate masks, including signs.

    EXAMPLES::

        >>> from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace
        >>> basis = CircleBasis((BinaryBibrace(1),))
        >>> flip = CircleLookupLayer(basis, basis, (1, 0))
        >>> network = CircleNetwork((flip, flip))
        >>> network.correlation(1, 1)
        Fraction(1, 1)
        >>> network.best_trail(1, 1).masks
        (1, 1, 1)
    """

    def __init__(self, layers: tuple[CircleAffineLayer | CircleLookupLayer, ...]) -> None:
        self.layers = tuple(layers)
        if not self.layers:
            raise ValueError("a network needs at least one layer")
        if any(a.output_basis != b.input_basis for a, b in zip(self.layers, self.layers[1:])):
            raise ValueError("adjacent character bases must agree")
        widths = {layer.key_width for layer in self.layers if layer.key_width}
        if len(widths) > 1:
            raise ValueError("symbolic affine layers must share global key coordinates")
        self.key_width = next(iter(widths), 0)

    def trail(self, masks: tuple[int, ...], *, key: int = 0) -> CircleTrail:
        """Evaluate every specified local coefficient at a fixed global key.

        EXAMPLES::

            >>> from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace
            >>> b = CircleBasis((BinaryBibrace(1),))
            >>> CircleNetwork((CircleLookupLayer(b, b, (1, 0)),)).trail((1, 1)).coefficient
            Fraction(-1, 1)
        """
        integer(key, self.key_width, "key")
        if len(masks) != len(self.layers) + 1:
            raise ValueError("one mask is required at every layer boundary")
        return CircleTrail(
            tuple(masks),
            tuple(
                layer.coefficient(a, b, key if layer.key_width else 0)
                for layer, a, b in zip(self.layers, masks, masks[1:])
            ),
        )

    def _propagate(
        self, input_mask: int, output_mask: int, key: int, maximum_entries: int, best: bool
    ):
        integer(input_mask, self.layers[0].input_basis.width, "input mask")
        integer(output_mask, self.layers[-1].output_basis.width, "output mask")
        integer(key, self.key_width, "key")
        # Conservative preflight bound, before any expensive coefficient call.
        cost = sum(
            (1 if i == 0 else 1 << layer.input_basis.width)
            * (1 if i == len(self.layers) - 1 else 1 << layer.output_basis.width)
            for i, layer in enumerate(self.layers)
        )
        if cost > maximum_entries:
            raise ValueError("network propagation exceeds maximum_entries")
        values: dict[int, tuple[Fraction, tuple[int, ...]]] = {
            input_mask: (Fraction(1), (input_mask,))
        }
        for i, layer in enumerate(self.layers):
            following: dict[int, tuple[Fraction, tuple[int, ...]]] = {}
            targets = (
                (output_mask,)
                if i == len(self.layers) - 1
                else range(1 << layer.output_basis.width)
            )
            for a, (prior, path) in values.items():
                for b in targets:
                    coefficient = prior * layer.coefficient(a, b, key if layer.key_width else 0)
                    if not coefficient:
                        continue
                    old = following.get(b, (Fraction(0), ()))
                    if best:
                        if abs(coefficient) > abs(old[0]):
                            following[b] = coefficient, path + (b,)
                    else:
                        following[b] = old[0] + coefficient, ()
            values = following
        return values.get(output_mask, (Fraction(0), ()))

    def correlation(
        self, input_mask: int, output_mask: int, *, key: int = 0, maximum_entries: int = 1 << 16
    ) -> Fraction:
        """Return a complete signed hull coefficient, or reject the work budget.

        EXAMPLES::

            >>> from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace
            >>> b = CircleBasis((BinaryBibrace(1),))
            >>> CircleNetwork((CircleLookupLayer(b, b, (0, 1)),)).correlation(1, 1)
            Fraction(1, 1)
        """
        return self._propagate(input_mask, output_mask, key, maximum_entries, False)[0]

    def best_trail(
        self, input_mask: int, output_mask: int, *, key: int = 0, maximum_entries: int = 1 << 16
    ) -> CircleTrail | None:
        """Find a maximum-magnitude trail over all intermediate masks, exactly.

        Optimality is only for this declared network and fixed endpoints/key.
        A proved zero hull does not imply the absence of nonzero trails.

        EXAMPLES::

            >>> from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace
            >>> b = CircleBasis((BinaryBibrace(1),))
            >>> CircleNetwork((CircleLookupLayer(b, b, (0, 1)),)).best_trail(1, 0) is None
            True
        """
        _, path = self._propagate(input_mask, output_mask, key, maximum_entries, True)
        return self.trail(path, key=key) if path else None


__all__ = [
    "AffineCircleTransition",
    "AffineKeyConditions",
    "CircleAffineLayer",
    "CircleLookupLayer",
    "CircleNetwork",
    "CircleTrail",
]
