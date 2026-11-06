"""Exact alternative-difference transitions using the shared XOR-DDT semantics."""

from dataclasses import dataclass
from fractions import Fraction

from claasp.semantics.cryptanalysis._circle_algebra import integer
from claasp.semantics.cryptanalysis.bibrace import CircleBasis
from claasp.semantics.cryptanalysis.trails import SBoxTransitionSemantics


@dataclass(frozen=True, slots=True)
class CircleDifferentialTransitionSemantics:
    """A complete small function with explicit input/output circle operations.

    Differences are packed elements in the original bit representation.
    The DDT is obtained from theta_out F theta_in using the existing XOR-DDT
    implementation, then its indices are converted back to original elements.
    Rectangular functions, mixed cell layouts and ordinary XOR are supported.

    EXAMPLES::

        >>> from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace, CircleBasis
        >>> b = CircleBasis((BinaryBibrace(2),))
        >>> s = CircleDifferentialTransitionSemantics(b, b, (0, 1, 3, 2))
        >>> s.probability(1, 1)
        Fraction(1, 1)
        >>> s.difference_distribution_table()[1]
        (0, 4, 0, 0)
    """

    input_basis: CircleBasis
    output_basis: CircleBasis
    table: tuple[int, ...]
    maximum_inputs: int = 1 << 16

    def __post_init__(self) -> None:
        if 1 << self.input_basis.width > self.maximum_inputs:
            raise ValueError("circle truth table exceeds maximum_inputs")
        object.__setattr__(self, "table", tuple(self.table))
        if len(self.table) != 1 << self.input_basis.width:
            raise ValueError("truth table must cover the complete input domain")
        for value in self.table:
            integer(value, self.output_basis.width, "table value")

    def probability(self, input_difference: int, output_difference: int) -> Fraction:
        """Count all x with F(x) circle F(x circle a) equal to b.

        No dense DDT is allocated. No independence assumption is made.

        EXAMPLES::

            >>> from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace, CircleBasis
            >>> b = CircleBasis((BinaryBibrace(1),))
            >>> CircleDifferentialTransitionSemantics(b, b, (1, 0)).probability(1, 1)
            Fraction(1, 1)
        """
        integer(input_difference, self.input_basis.width, "input difference")
        integer(output_difference, self.output_basis.width, "output difference")
        return Fraction(
            sum(
                self.output_basis.circle(
                    y, self.table[self.input_basis.circle(x, input_difference)]
                )
                == output_difference
                for x, y in enumerate(self.table)
            ),
            len(self.table),
        )

    def difference_distribution_table(
        self, *, maximum_entries: int = 1 << 20
    ) -> tuple[tuple[int, ...], ...]:
        """Return exact counts, indexed by original packed circle differences.

        Every row sums to the input-domain size. The allocation limit is
        checked before building the transformed function or the dense table.

        EXAMPLES::

            >>> from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace, CircleBasis
            >>> b = CircleBasis((BinaryBibrace(1),))
            >>> CircleDifferentialTransitionSemantics(b, b, (0, 0)).difference_distribution_table()
            ((2, 0), (2, 0))
        """
        n, m = self.input_basis.width, self.output_basis.width
        if (
            isinstance(maximum_entries, bool)
            or not isinstance(maximum_entries, int)
            or maximum_entries < max(1 << (n + m), 1 << (2 * n))
        ):
            raise ValueError("circle DDT exceeds maximum_entries")
        table = tuple(
            self.output_basis.theta(self.table[self.input_basis.theta(x)]) for x in range(1 << n)
        )
        ddt = SBoxTransitionSemantics(table, output_width=m).difference_distribution_table()
        return tuple(
            tuple(ddt[self.input_basis.theta(a)][self.output_basis.theta(b)] for b in range(1 << m))
            for a in range(1 << n)
        )


__all__ = ["CircleDifferentialTransitionSemantics"]
