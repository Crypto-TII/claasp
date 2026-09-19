"""The two-element bit domain."""

from dataclasses import dataclass

from claasp_next.domains.base import Domain


@dataclass(frozen=True, slots=True)
class Bit(Domain):
    """Represent one element of the set ``{0, 1}``.

    Boolean objects are deliberately rejected even though ``bool`` subclasses
    ``int`` in Python.

    EXAMPLES::

        >>> from claasp_next import Bit
        >>> (Bit().contains(0), Bit().contains(1), Bit().contains(True))
        (True, True, False)
    """

    @property
    def encoded_bit_size(self) -> int:
        """Return the one-bit canonical encoding width."""

        return 1

    def contains(self, value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and value in (0, 1)
