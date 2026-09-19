"""Feedback-register realization of Spongent-pi."""

from .primitive import SpongentPi


class SpongentPiFSR(SpongentPi):
    """Spongent-pi with its counter register represented by equivalent wiring.

    EXAMPLES::

        >>> primitive = SpongentPiFSR()
        >>> inputs = {name: 0 for name in primitive.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0xcaed745fb9d13ede', 160)
    """

__all__ = ["SpongentPiFSR"]
