"""Types carried by ports in a CLAASP graph."""

from dataclasses import dataclass
from functools import reduce
from operator import mul

from claasp_next.domains.base import Domain


@dataclass(frozen=True, slots=True)
class ValueType:
    """A homogeneous shape over one scalar domain."""

    domain: Domain
    shape: tuple[int, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.domain, Domain):
            raise TypeError("domain must be a Domain")
        if not self.shape:
            raise ValueError("shape must contain at least one dimension")
        if any(not isinstance(size, int) or isinstance(size, bool) or size <= 0 for size in self.shape):
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
