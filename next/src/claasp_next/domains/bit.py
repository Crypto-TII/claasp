"""The two-element bit domain."""

from dataclasses import dataclass

from claasp_next.domains.base import Domain


@dataclass(frozen=True, slots=True)
class Bit(Domain):
    """A single element of the set ``{0, 1}``."""

    @property
    def encoded_bit_size(self) -> int:
        return 1

    def contains(self, value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and value in (0, 1)
