"""Prime-field domain descriptors."""

from dataclasses import dataclass

from claasp_next.domains.base import Domain


@dataclass(frozen=True, slots=True)
class PrimeField(Domain):
    """Canonical integer representatives of the field ``GF(modulus)``.

    Primality verification is deliberately outside this first descriptor. A
    dedicated parameter-validation service will be added before cipher
    parameters can be accepted from untrusted sources.
    """

    modulus: int

    def __post_init__(self) -> None:
        if not isinstance(self.modulus, int) or isinstance(self.modulus, bool):
            raise TypeError("modulus must be an integer")
        if self.modulus < 2:
            raise ValueError("modulus must be at least 2")

    @property
    def encoded_bit_size(self) -> int:
        return self.modulus.bit_length()

    def contains(self, value: object) -> bool:
        return (
            isinstance(value, int)
            and not isinstance(value, bool)
            and 0 <= value < self.modulus
        )
