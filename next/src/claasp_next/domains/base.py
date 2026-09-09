"""Base definitions for mathematical scalar domains."""

from abc import ABC, abstractmethod


class Domain(ABC):
    """Immutable description of a scalar's mathematical semantics."""

    @property
    @abstractmethod
    def encoded_bit_size(self) -> int | None:
        """Return the canonical scalar encoding size, if one is defined."""

    @abstractmethod
    def contains(self, value: object) -> bool:
        """Return whether *value* is a canonical runtime representative."""

    def validate(self, value: object) -> None:
        """Raise ``ValueError`` when *value* is outside this domain."""

        if not self.contains(value):
            raise ValueError(f"{value!r} is not a canonical element of {self!r}")
