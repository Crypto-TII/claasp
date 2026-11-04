"""Binary bibraces and their exact, quadratic character bases.

Bit indices within a cell are least significant first. Packed multi-cell
values place the first cell in the most significant positions, like CLAASP.
The alternating products must land in their common annihilator. This is the
binary class-two family, including higher-rank products; odd-prime fields are
not silently interpreted as binary vector spaces.
"""

from dataclasses import dataclass, field

from claasp.semantics.cryptanalysis._circle_algebra import (
    Polynomial,
    bits,
    evaluate,
    integer,
    parity,
    reduce_equations,
    solution,
)


@dataclass(frozen=True, slots=True)
class BinaryBibrace:
    """An alternative sum ``x circle y = x ^ y ^ sum(psi_j(x,y)*b_j)``.

    ``forms[j][i]`` is row i of the symmetric zero-diagonal matrix of psi_j.
    The independent output vectors must lie in every form's radical. A
    quadratic refinement vanishing on their span is constructed automatically.
    Empty forms give ordinary XOR, useful as a control and identity case.

    EXAMPLES::

        >>> brace = BinaryBibrace.craft()
        >>> brace.circle(1, 8)
        12
        >>> brace.theta(9), brace.theta(brace.theta(9))
        (12, 9)
        >>> brace.character(7, 6)  # flat: parity(7 & 6)
        0
        >>> brace.annihilator_basis
        (2, 5)
        >>> BinaryBibrace(4).theta(9)
        9
    """

    width: int
    forms: tuple[tuple[int, ...], ...] = ()
    outputs: tuple[int, ...] = ()
    _refinements: tuple[Polynomial, ...] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if isinstance(self.width, bool) or not isinstance(self.width, int) or self.width < 1:
            raise ValueError("width must be a positive integer")
        forms = tuple(tuple(row for row in form) for form in self.forms)
        outputs = tuple(self.outputs)
        object.__setattr__(self, "forms", forms)
        object.__setattr__(self, "outputs", outputs)
        if len(forms) != len(outputs):
            raise ValueError("one output vector is required per bilinear form")
        for form in forms:
            if len(form) != self.width:
                raise ValueError("bilinear form has the wrong number of rows")
            for i, row in enumerate(form):
                integer(row, self.width, "form row")
                if row >> i & 1 or any(
                    (row >> j & 1) != (form[j] >> i & 1) for j in range(self.width)
                ):
                    raise ValueError("bilinear forms must be symmetric with zero diagonal")
            if not any(form):
                raise ValueError("omit zero bilinear forms")
        for output in outputs:
            integer(output, self.width, "output vector")
            if any(parity(row & output) for form in forms for row in form):
                raise ValueError("output vectors must lie in the common annihilator")
        if len(reduce_equations(tuple((b, 0) for b in outputs))) != len(outputs):
            raise ValueError("output vectors must be linearly independent")
        refinements = []
        for form in forms:
            quad = frozenset(
                (1 << i) | (1 << j)
                for i, row in enumerate(form)
                for j in range(i + 1, self.width)
                if row >> j & 1
            )
            correction = solution(tuple((b, evaluate(quad, b)) for b in outputs))
            refinements.append(quad ^ frozenset(1 << i for i in bits(correction)))
        object.__setattr__(self, "_refinements", tuple(refinements))

    @classmethod
    def craft(cls) -> "BinaryBibrace":
        """Return the paper's four-bit bibrace (b=5, Ann={0,2,5,7}).

        EXAMPLES::

            >>> BinaryBibrace.craft().forms
            ((8, 0, 8, 5),)
        """
        return cls(4, ((8, 0, 8, 5),), (5,))

    @property
    def annihilator_basis(self) -> tuple[int, ...]:
        """Return an LSB-indexed binary basis of the common radical.

        EXAMPLES::

            >>> BinaryBibrace(2).annihilator_basis
            (1, 2)
        """
        from claasp.semantics.cryptanalysis._circle_algebra import nullspace

        return tuple(
            sorted(nullspace(tuple(row for form in self.forms for row in form), self.width))
        )

    def circle(self, x: int, y: int) -> int:
        """Apply the alternative sum without table materialization.

        EXAMPLES::

            >>> BinaryBibrace.craft().circle(8, 1)
            12
        """
        integer(x, self.width, "x")
        integer(y, self.width, "y")
        result = x ^ y
        for form, output in zip(self.forms, self.outputs):
            if sum(parity(form[i] & y) for i in bits(x)) & 1:
                result ^= output
        return result

    def theta(self, value: int) -> int:
        """Map XOR coordinates to circle coordinates; this map is involutive.

        EXAMPLES::

            >>> [BinaryBibrace.craft().theta(x) for x in (0, 1, 8, 9)]
            [0, 1, 8, 12]
        """
        integer(value, self.width)
        result = value
        for poly, output in zip(self._refinements, self.outputs):
            if evaluate(poly, value):
                result ^= output
        return result

    def character(self, label: int, value: int) -> int:
        """Evaluate the Boolean exponent of the character labelled by ``label``.

        EXAMPLES::

            >>> BinaryBibrace.craft().character(9, 9)
            1
        """
        integer(label, self.width, "label")
        return parity(label & self.theta(value))

    def character_polynomial(self, label: int) -> Polynomial:
        """Return the degree-at-most-two ANF as a frozenset of monomial bitsets.

        EXAMPLES::

            >>> sorted(BinaryBibrace.craft().character_polynomial(1))
            [1, 9, 12]
        """
        integer(label, self.width, "label")
        poly = frozenset(1 << i for i in bits(label))
        for refinement, output in zip(self._refinements, self.outputs):
            if parity(label & output):
                poly ^= refinement
        return poly

    def walsh_table(
        self, table: tuple[int, ...], *, maximum_entries: int = 1 << 20
    ) -> tuple[tuple[int, ...], ...]:
        """Return exact signed full Walsh counts of theta S theta.

        Input and output cells use this same bibrace. Nonpermutations are
        allowed; their perfect input and output subgroups need not coincide.
        The dense-table budget is checked before any allocation.

        EXAMPLES::

            >>> brace = BinaryBibrace.craft()
            >>> identity = brace.walsh_table(tuple(range(16)))
            >>> identity[9][9], identity[9][7]
            (16, 0)
        """
        size = 1 << self.width
        if size * size > maximum_entries:
            raise ValueError("circle-LAT exceeds maximum_entries")
        table = tuple(table)
        if len(table) != size:
            raise ValueError("lookup table must cover the complete cell domain")
        for value in table:
            integer(value, self.width, "table value")
        from claasp.semantics.cryptanalysis.trails import SBoxTransitionSemantics

        conjugated = tuple(self.theta(table[self.theta(x)]) for x in range(size))
        return SBoxTransitionSemantics(
            conjugated, output_width=self.width
        ).walsh_correlation_table()


@dataclass(frozen=True, slots=True)
class CircleBasis:
    """A parallel character basis with an explicit cell layout, first cell MSB.

    EXAMPLES::

        >>> basis = CircleBasis((BinaryBibrace.craft(),) * 2)
        >>> basis.width, basis.character(0x77, 0x12)
        (8, 0)
        >>> basis.theta(0x99)
        204
    """

    cells: tuple[BinaryBibrace, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "cells", tuple(self.cells))
        if not self.cells or any(not isinstance(cell, BinaryBibrace) for cell in self.cells):
            raise ValueError("a basis requires one or more binary bibrace cells")

    @property
    def width(self) -> int:
        """Total encoded width of all cells.

        EXAMPLES::

            >>> CircleBasis((BinaryBibrace(3), BinaryBibrace(2))).width
            5
        """
        return sum(cell.width for cell in self.cells)

    def character(self, label: int, value: int) -> int:
        """Evaluate a parallel character on a packed value.

        EXAMPLES::

            >>> CircleBasis((BinaryBibrace(2),)).character(3, 1)
            1
        """
        integer(label, self.width, "label")
        return parity(label & self.theta(value))

    def theta(self, value: int) -> int:
        """Apply each cell's involution independently.

        EXAMPLES::

            >>> CircleBasis((BinaryBibrace.craft(),)).theta(9)
            12
        """
        integer(value, self.width)
        shift = self.width
        result = 0
        for cell in self.cells:
            shift -= cell.width
            result = (result << cell.width) | cell.theta((value >> shift) & ((1 << cell.width) - 1))
        return result

    def character_polynomial(self, label: int) -> Polynomial:
        """Return a state character ANF, using packed-state bit indices.

        EXAMPLES::

            >>> sorted(CircleBasis((BinaryBibrace(2),)).character_polynomial(3))
            [1, 2]
        """
        integer(label, self.width, "label")
        shift = self.width
        poly: Polynomial = frozenset()
        for cell in self.cells:
            shift -= cell.width
            part = (label >> shift) & ((1 << cell.width) - 1)
            poly ^= frozenset(term << shift for term in cell.character_polynomial(part))
        return poly


__all__ = ["BinaryBibrace", "CircleBasis"]
