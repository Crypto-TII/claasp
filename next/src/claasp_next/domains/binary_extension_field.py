"""Binary extension-field domain descriptors."""

from dataclasses import dataclass

from claasp_next.domains.base import Domain
from claasp_next.domains.validation import is_irreducible_binary_polynomial


@dataclass(frozen=True, slots=True)
class BinaryExtensionField(Domain):
    """Polynomial-basis representation of ``GF(2^degree)``.

    ``modulus`` stores the coefficients of the degree-``degree`` defining
    polynomial as bits, including its leading coefficient.

    EXAMPLES::

        >>> from claasp_next import BinaryExtensionField
        >>> aes_field = BinaryExtensionField(8, 0x11B)
        >>> aes_field.contains(0xFF)
        True
        >>> aes_field.encoded_bit_size
        8
    """

    degree: int
    modulus: int
    basis: str = "polynomial"

    def __post_init__(self) -> None:
        if not isinstance(self.degree, int) or isinstance(self.degree, bool):
            raise TypeError("degree must be an integer")
        if self.degree <= 0:
            raise ValueError("degree must be positive")
        if not isinstance(self.modulus, int) or isinstance(self.modulus, bool):
            raise TypeError("modulus must be an integer")
        if self.modulus.bit_length() != self.degree + 1:
            raise ValueError("modulus must be a monic polynomial of the declared degree")
        if self.modulus & 1 == 0:
            raise ValueError("modulus must have a nonzero constant coefficient")
        if self.basis != "polynomial":
            raise ValueError("only polynomial basis is currently supported")
        if not is_irreducible_binary_polynomial(self.modulus, self.degree):
            raise ValueError("modulus must be irreducible over GF(2)")

    @property
    def encoded_bit_size(self) -> int:
        """Return the polynomial-basis encoding width in bits."""

        return self.degree

    def contains(self, value: object) -> bool:
        return (
            isinstance(value, int)
            and not isinstance(value, bool)
            and 0 <= value < 1 << self.degree
        )
