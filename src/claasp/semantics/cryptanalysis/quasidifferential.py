"""Exact signed quasidifferential coefficients in the Beyne–Rijmen basis.

For a map f, Q[a,u;b,v] is E_x[ [f(x)^f(x^a)=b]
(-1)^(<u,x>+<v,f(x)>) ]. All coefficients are rational; no logarithm
or floating-point value participates in validity checks.
"""

from dataclasses import dataclass
from fractions import Fraction
from math import log2


def _mask(value, width, name):
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 1 << width:
        raise ValueError(f"{name} must fit {width} bits")


@dataclass(frozen=True, slots=True)
class QuasidifferentialTransition:
    """One exact signed transition, with differences and masks kept distinct.

    EXAMPLES::

        >>> transition = QuasidifferentialTransition((1,), 1, (0,), 0, Fraction(1, 2))
        >>> (transition.sign, transition.weight)
        (1, 1.0)
    """

    input_differences: tuple[int, ...]
    output_difference: int
    input_masks: tuple[int, ...]
    output_mask: int
    coefficient: Fraction

    @property
    def sign(self):
        """Return the sign; a zero coefficient is not a possible transition."""
        return (self.coefficient > 0) - (self.coefficient < 0)

    @property
    def weight(self):
        """Return -log2 of the absolute coefficient for presentation only."""
        return float("inf") if not self.coefficient else -log2(abs(self.coefficient))


class QuasidifferentialSemantics:
    """Compute signed local coefficients independently of solver encodings.

    EXAMPLES::

        >>> QuasidifferentialSemantics.lookup((1, 0), 0, 0, 1, 1)
        Fraction(-1, 1)
        >>> QuasidifferentialSemantics.modular_add(2, 0, 0, 0, 0, 0, 0)
        Fraction(1, 1)
    """

    @staticmethod
    def lookup(
        table, input_difference, output_difference, input_mask, output_mask, *, output_width=None
    ):
        """Compute a table coefficient by exact direct summation.

        EXAMPLES::

            >>> QuasidifferentialSemantics.lookup((0, 1, 3, 2), 1, 1, 0, 0)
            Fraction(1, 1)
        """
        table = tuple(table)
        if len(table) < 2 or len(table) & (len(table) - 1):
            raise ValueError("lookup table length must be a power of two")
        n = len(table).bit_length() - 1
        m = max(1, max(table).bit_length()) if output_width is None else output_width
        for value in table:
            _mask(value, m, "table value")
        _mask(input_difference, n, "input_difference")
        _mask(input_mask, n, "input_mask")
        _mask(output_difference, m, "output_difference")
        _mask(output_mask, m, "output_mask")
        count = 0
        for x, y in enumerate(table):
            if y ^ table[x ^ input_difference] == output_difference:
                count += (
                    -1 if ((x & input_mask).bit_count() + (y & output_mask).bit_count()) & 1 else 1
                )
        return Fraction(count, len(table))

    @staticmethod
    def modular_add(width, a, b, c, u, v, w):
        """Compute an arbitrary-width modular-addition coefficient by carry DP.

        The four states are the carries of the original and difference-paired
        evaluations. This oracle does not use the SMT validity/weight theorem.

        EXAMPLES::

            >>> QuasidifferentialSemantics.modular_add(32, 0, 0, 0, 0, 0, 0)
            Fraction(1, 1)
        """
        if not isinstance(width, int) or isinstance(width, bool) or width < 1:
            raise ValueError("width must be a positive integer")
        for name, value in zip(("a", "b", "c", "u", "v", "w"), (a, b, c, u, v, w)):
            _mask(value, width, name)
        states = {(0, 0): 1}
        for bit in range(width):
            following: dict[tuple[int, int], int] = {}
            for (carry, paired_carry), count in states.items():
                for x in (0, 1):
                    for y in (0, 1):
                        first = x + y + carry
                        second = (x ^ ((a >> bit) & 1)) + (y ^ ((b >> bit) & 1)) + paired_carry
                        if (first ^ second) & 1 != (c >> bit) & 1:
                            continue
                        sign = (
                            -1
                            if (
                                ((u >> bit) & 1) * x
                                + ((v >> bit) & 1) * y
                                + ((w >> bit) & 1) * (first & 1)
                            )
                            & 1
                            else 1
                        )
                        key = (first >> 1, second >> 1)
                        following[key] = following.get(key, 0) + sign * count
            states = following
        return Fraction(sum(states.values()), 1 << (2 * width))

    @staticmethod
    def modular_subtract(width, a, b, c, u, v, w):
        """Reduce z=x-y exactly to x=z+y, including mask roles.

        EXAMPLES::

            >>> QuasidifferentialSemantics.modular_subtract(4, 0, 0, 0, 0, 0, 0)
            Fraction(1, 1)
        """
        return QuasidifferentialSemantics.modular_add(width, c, b, a, w, v, u)


__all__ = ["QuasidifferentialTransition", "QuasidifferentialSemantics"]
