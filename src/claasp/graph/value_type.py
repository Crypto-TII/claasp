"""Types carried by ports in a CLAASP graph."""

from dataclasses import dataclass
from functools import reduce
from operator import mul

from claasp.domains.base import Domain


@dataclass(frozen=True, slots=True)
class ValueType:
    """A homogeneous shape over one scalar domain.

    The logical size is deliberately distinct from its binary encoding size.

    EXAMPLES::

        >>> from claasp import PrimeField, ValueType
        >>> state_type = ValueType(PrimeField(17), (3,))
        >>> state_type.unit_count
        3
        >>> state_type.encoded_bit_size
        15
    """

    domain: Domain
    shape: tuple[int, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.domain, Domain):
            raise TypeError("domain must be a Domain")
        if not self.shape:
            raise ValueError("shape must contain at least one dimension")
        if any(
            not isinstance(size, int) or isinstance(size, bool) or size <= 0 for size in self.shape
        ):
            raise ValueError("every shape dimension must be a positive integer")

    @property
    def unit_count(self) -> int:
        """Number of logical scalar units in the value."""

        return reduce(mul, self.shape, 1)

    @property
    def encoded_bit_size(self) -> int | None:
        """Canonical encoded size when the domain defines one."""

        scalar_size = self.domain.encoded_bit_size
        return None if scalar_size is None else self.unit_count * scalar_size


def BitWord(bit_size: int) -> ValueType:
    """Return the boundary type for one packed string of individual bits.

    ``BitWord(128)`` is the concise authoring form of
    ``ValueType(domain=Bit(), shape=(128,))``. Use ``Word`` instead when
    the value is one arithmetic word with rotation or modular-add semantics.

    EXAMPLES::

        >>> from claasp import BitWord
        >>> value_type = BitWord(128)
        >>> (value_type.unit_count, value_type.encoded_bit_size)
        (128, 128)
    """

    from claasp.domains import Bit

    if not isinstance(bit_size, int) or isinstance(bit_size, bool):
        raise TypeError("bit_size must be an integer")
    if bit_size <= 0:
        raise ValueError("bit_size must be positive")
    return ValueType(Bit(), (bit_size,))
