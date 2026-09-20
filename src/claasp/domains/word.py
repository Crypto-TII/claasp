"""Fixed-width unsigned machine-word domain."""

from dataclasses import dataclass

from claasp.domains.base import Domain


@dataclass(frozen=True, slots=True)
class Word(Domain):
    """Unsigned integers represented by exactly ``width`` bits.

    A word is a logical unit, not an array of individual graph bits.

    EXAMPLES::

        >>> Word(8).contains(255)
        True
        >>> Word(8).contains(256)
        False
    """

    width: int

    def __post_init__(self) -> None:
        if not isinstance(self.width, int) or isinstance(self.width, bool):
            raise TypeError("word width must be an integer")
        if self.width <= 0:
            raise ValueError("word width must be positive")

    @property
    def encoded_bit_size(self) -> int:
        """Return the declared fixed word width."""

        return self.width

    def contains(self, value: object) -> bool:
        return (
            isinstance(value, int)
            and not isinstance(value, bool)
            and 0 <= value < (1 << self.width)
        )
