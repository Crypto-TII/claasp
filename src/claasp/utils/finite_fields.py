"""Small dependency-free finite-field reference operations."""

from claasp.domains import BinaryExtensionField
from claasp.domains.validation import is_irreducible_binary_polynomial


def first_irreducible_polynomial(degree: int) -> int:
    """Return the smallest monic irreducible binary polynomial of ``degree``.

    EXAMPLES::

        >>> from claasp.utils import first_irreducible_polynomial
        >>> bin(first_irreducible_polynomial(4))
        '0b10011'
    """

    if not isinstance(degree, int) or isinstance(degree, bool) or degree <= 0:
        raise ValueError("degree must be a positive integer")
    for polynomial in range((1 << degree) | 1, 1 << (degree + 1), 2):
        if is_irreducible_binary_polynomial(polynomial, degree):
            return polynomial
    raise ValueError(f"no irreducible polynomial found for degree {degree}")


def binary_field_multiply(field: BinaryExtensionField, left: int, right: int) -> int:
    """Multiply two canonical elements of a binary extension field.

    EXAMPLES::

        >>> from claasp.domains import BinaryExtensionField
        >>> from claasp.utils import binary_field_multiply
        >>> binary_field_multiply(BinaryExtensionField(8, 0x11B), 0x57, 0x13)
        254
    """

    if not isinstance(field, BinaryExtensionField):
        raise TypeError("field must be a BinaryExtensionField")
    field.validate(left)
    field.validate(right)
    result = 0
    multiplicand = left
    multiplier = right
    reduction = field.modulus ^ (1 << field.degree)
    for _ in range(field.degree):
        if multiplier & 1:
            result ^= multiplicand
        multiplier >>= 1
        carry = multiplicand & (1 << (field.degree - 1))
        multiplicand = (multiplicand << 1) & ((1 << field.degree) - 1)
        if carry:
            multiplicand ^= reduction
    return result


def binary_field_power(field: BinaryExtensionField, value: int, exponent: int) -> int:
    """Raise a binary-field element to a non-negative integer exponent.

    EXAMPLES::

        >>> from claasp.domains import BinaryExtensionField
        >>> from claasp.utils import binary_field_power
        >>> binary_field_power(BinaryExtensionField(8, 0x11B), 0x53, 254)
        202
    """

    if not isinstance(exponent, int) or isinstance(exponent, bool):
        raise TypeError("exponent must be an integer")
    if exponent < 0:
        raise ValueError("exponent must be non-negative")
    field.validate(value)
    result = 1
    base = value
    remaining = exponent
    while remaining:
        if remaining & 1:
            result = binary_field_multiply(field, result, base)
        base = binary_field_multiply(field, base, base)
        remaining >>= 1
    return result
