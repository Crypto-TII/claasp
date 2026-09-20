"""Dependency-free validation of finite-field defining parameters."""


def is_probable_prime(value: int) -> bool:
    """Return whether *value* passes strong Miller--Rabin primality tests.

    The selected witnesses are deterministic for values below ``2**64``. For
    larger values this is a strong probable-prime test, intended to catch
    malformed inputs rather than replace provenance for cryptographic
    parameters.

    EXAMPLES::

        >>> from claasp.domains.validation import is_probable_prime
        >>> is_probable_prime(17)
        True
        >>> is_probable_prime(15)
        False
    """

    if not isinstance(value, int) or isinstance(value, bool):
        return False
    if value < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    if value in small_primes:
        return True
    if any(value % prime == 0 for prime in small_primes):
        return False

    odd_part = value - 1
    power_of_two = 0
    while odd_part % 2 == 0:
        power_of_two += 1
        odd_part //= 2

    if value < 1 << 64:
        witnesses = (2, 325, 9375, 28178, 450775, 9780504, 1795265022)
    else:
        witnesses = small_primes

    for witness in witnesses:
        base = witness % value
        if base in (0, 1):
            continue
        residue = pow(base, odd_part, value)
        if residue in (1, value - 1):
            continue
        for _ in range(power_of_two - 1):
            residue = residue * residue % value
            if residue == value - 1:
                break
        else:
            return False
    return True


def is_irreducible_binary_polynomial(polynomial: int, degree: int) -> bool:
    """Test irreducibility of a monic polynomial over ``GF(2)``.

    Polynomials use the conventional integer bit representation.

    EXAMPLES::

        >>> from claasp.domains.validation import is_irreducible_binary_polynomial
        >>> is_irreducible_binary_polynomial(0x11B, 8)
        True
        >>> is_irreducible_binary_polynomial(0b10101, 4)
        False
    """

    if degree <= 0 or polynomial.bit_length() != degree + 1 or polynomial & 1 == 0:
        return False
    if degree == 1:
        return polynomial == 0b11

    x = 0b10
    power = x
    for iteration in range(1, degree + 1):
        power = _binary_polynomial_multiply_mod(power, power, polynomial)
        if iteration <= degree // 2 and _binary_polynomial_gcd(power ^ x, polynomial) != 1:
            return False
    return power == x


def _binary_polynomial_multiply_mod(left: int, right: int, modulus: int) -> int:
    result = 0
    modulus_degree = modulus.bit_length() - 1
    while right:
        if right & 1:
            result ^= left
        right >>= 1
        left <<= 1
        if left.bit_length() - 1 >= modulus_degree:
            left ^= modulus
    return result


def _binary_polynomial_gcd(left: int, right: int) -> int:
    while right:
        left, right = right, _binary_polynomial_remainder(left, right)
    return left


def _binary_polynomial_remainder(dividend: int, divisor: int) -> int:
    divisor_degree = divisor.bit_length() - 1
    while dividend and dividend.bit_length() - 1 >= divisor_degree:
        dividend ^= divisor << (dividend.bit_length() - 1 - divisor_degree)
    return dividend
