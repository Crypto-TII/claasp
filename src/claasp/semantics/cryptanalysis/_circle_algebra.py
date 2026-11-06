"""Small exact GF(2) and quadratic-form kernels for circle-linear semantics."""

from fractions import Fraction


def integer(value: int, width: int, name: str = "value") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 1 << width:
        raise ValueError(f"{name} must be an unsigned {width}-bit integer")
    return value


def parity(value: int) -> int:
    return value.bit_count() & 1


def bits(value: int):
    while value:
        bit = value & -value
        yield bit.bit_length() - 1
        value ^= bit


def reduce_equations(equations: tuple[tuple[int, int], ...]) -> tuple[tuple[int, int], ...]:
    basis: dict[int, tuple[int, int]] = {}
    for row, rhs in equations:
        while row:
            pivot = row.bit_length() - 1
            if pivot in basis:
                other, value = basis[pivot]
                row ^= other
                rhs ^= value
            else:
                basis[pivot] = row, rhs
                break
        if not row and rhs:
            return ((0, 1),)
    for pivot in sorted(basis):
        row, rhs = basis[pivot]
        for other in tuple(basis):
            if other != pivot and basis[other][0] >> pivot & 1:
                a, b = basis[other]
                basis[other] = a ^ row, b ^ rhs
    return tuple(basis[pivot] for pivot in sorted(basis, reverse=True))


def nullspace(rows: tuple[int, ...], width: int) -> tuple[int, ...]:
    reduced = reduce_equations(tuple((row, 0) for row in rows))
    pivots = {row.bit_length() - 1 for row, _ in reduced}
    return tuple(
        (1 << free) | sum((1 << (row.bit_length() - 1)) for row, _ in reduced if row >> free & 1)
        for free in range(width)
        if free not in pivots
    )


def solution(equations: tuple[tuple[int, int], ...]) -> int:
    reduced = reduce_equations(equations)
    if reduced == ((0, 1),):
        raise ValueError("inconsistent binary equations")
    return sum(rhs << (row.bit_length() - 1) for row, rhs in reduced)


# A monomial is the bitset of its variables; 0 is the constant monomial.
Polynomial = frozenset[int]


def evaluate(poly: Polynomial, value: int) -> int:
    return sum(value & term == term for term in poly) & 1


def product(left: Polynomial, right: Polynomial) -> Polynomial:
    result: set[int] = set()
    for a in left:
        for b in right:
            term = a | b
            result.symmetric_difference_update((term,))
    return frozenset(result)


def substitute(poly: Polynomial, images: tuple[Polynomial, ...]) -> Polynomial:
    result: Polynomial = frozenset()
    for term in poly:
        image: Polynomial = frozenset((0,))
        for bit in bits(term):
            image = product(image, images[bit])
        result ^= image
    return result


def gauss_sum(poly: Polynomial) -> Fraction:
    """Normalized signed sum of a quadratic Boolean polynomial, by elimination."""
    factor = Fraction(1)
    while True:
        pair = next((term for term in poly if term.bit_count() == 2), None)
        if pair is None:
            return Fraction(0) if any(poly) else (-factor if 0 in poly else factor)
        i = pair & -pair
        j = pair ^ i
        left = frozenset(term ^ i for term in poly if term & i and term != pair)
        right = frozenset(term ^ j for term in poly if term & j and term != pair)
        poly = frozenset(term for term in poly if not term & pair) ^ product(left, right)
        factor /= 2


def radical(poly: Polynomial, width: int) -> tuple[int, ...]:
    rows = [0] * width
    for term in poly:
        if term.bit_count() == 2:
            i, j = bits(term)
            rows[i] ^= 1 << j
            rows[j] ^= 1 << i
    return nullspace(tuple(rows), width)
