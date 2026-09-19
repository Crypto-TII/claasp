"""Exact independent-bit AND differences and signed linear correlations."""

from claasp_next.semantics.cryptanalysis.trails import TrailKind, Transition, XorDifference, XorMask


class BitwiseAndSemantics:
    """Two-input word AND factors into exhaustive one-bit DDT/LAT entries.

    EXAMPLES::

        >>> from claasp_next.semantics.cryptanalysis import BitwiseAndSemantics
        >>> semantics = BitwiseAndSemantics(2)
        >>> transition = semantics.xor_differential(1, 0, 1)
        >>> (transition.is_possible, transition.weight, semantics.check(transition))
        (True, 1.0, True)
    """

    def __init__(self, width):
        if not isinstance(width, int) or isinstance(width, bool) or width <= 0:
            raise ValueError("width must be a positive integer")
        self.width = width

    def _validate(self, *patterns):
        for value in patterns:
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or not 0 <= value < 1 << self.width
            ):
                raise ValueError("patterns must fit the AND word width")

    def xor_differential(self, left, right, output):
        """Return the exact XOR-differential transition for two AND inputs."""
        self._validate(left, right, output)
        active = left | right
        numerator = 0 if output & ~active else 1 << (2 * self.width - active.bit_count())
        return Transition(
            TrailKind.XOR_DIFFERENTIAL,
            XorDifference((left << self.width) | right, 2 * self.width),
            XorDifference(output, self.width),
            numerator,
            1 << (2 * self.width),
        )

    def xor_linear(self, left, right, output):
        """Return the exact signed XOR-linear transition for two AND inputs."""
        self._validate(left, right, output)
        numerator = 0 if (left | right) & ~output else 1 << (2 * self.width - output.bit_count())
        sign = -1 if numerator and (left & right & output).bit_count() % 2 else 1
        return Transition(
            TrailKind.XOR_LINEAR,
            XorMask((left << self.width) | right, 2 * self.width),
            XorMask(output, self.width),
            numerator,
            1 << (2 * self.width),
            sign,
        )

    def check(self, transition):
        """Recompute and compare an AND transition independently."""
        left, right = divmod(transition.input_pattern.value, 1 << self.width)
        expected = (
            self.xor_linear(left, right, transition.output_pattern.value)
            if transition.kind is TrailKind.XOR_LINEAR
            else self.xor_differential(left, right, transition.output_pattern.value)
        )
        return transition == expected
