"""Prime-field domain descriptors."""

from dataclasses import dataclass

from claasp_next.domains.base import Domain
from claasp_next.domains.validation import is_probable_prime


@dataclass(frozen=True, slots=True)
class PrimeField(Domain):
    """Canonical integer representatives of the field ``GF(modulus)``.

    The constructor applies a deterministic Miller--Rabin test below
    ``2**64`` and strong probable-prime screening above it. Provenance remains
    necessary for cryptographic parameter sets.

    EXAMPLES::

        >>> from claasp_next import PrimeField
        >>> field = PrimeField(17)
        >>> field.contains(16)
        True
        >>> field.contains(17)
        False
        >>> field.encoded_bit_size
        5
    """

    modulus: int

    def __post_init__(self) -> None:
        if not isinstance(self.modulus, int) or isinstance(self.modulus, bool):
            raise TypeError("modulus must be an integer")
        if self.modulus < 2:
            raise ValueError("modulus must be at least 2")
        if not is_probable_prime(self.modulus):
            raise ValueError("modulus must be prime")

    @property
    def encoded_bit_size(self) -> int:
        """Return the unsigned encoding width of canonical representatives."""

        return self.modulus.bit_length()

    def contains(self, value: object) -> bool:
        return (
            isinstance(value, int)
            and not isinstance(value, bool)
            and 0 <= value < self.modulus
        )
