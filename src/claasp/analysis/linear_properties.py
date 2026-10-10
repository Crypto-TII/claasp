"""Exact small-matrix properties for typed linear component semantics."""

from itertools import combinations, product
from math import gcd

from claasp.domains import BinaryExtensionField, Bit, PrimeField
from claasp.utils.finite_fields import binary_field_multiply, binary_field_power
from claasp.utils.matrices import identity_matrix, normalize_matrix, transpose_matrix


def matrix_rank(matrix, domain) -> int:
    """Return exact row rank over the supplied scalar field.

    EXAMPLES::

        >>> try:
        ...     matrix_rank()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    rows = [list(row) for row in normalize_matrix(matrix)]
    _validate_matrix_domain(rows, domain)
    rank = 0
    for column in range(len(rows[0])):
        pivot = next((index for index in range(rank, len(rows)) if rows[index][column]), None)
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        inverse = _inverse(domain, rows[rank][column])
        rows[rank] = [_multiply(domain, value, inverse) for value in rows[rank]]
        for index, row in enumerate(rows):
            if index == rank or not row[column]:
                continue
            factor = row[column]
            rows[index] = [
                _subtract(domain, left, _multiply(domain, factor, right))
                for left, right in zip(row, rows[rank])
            ]
        rank += 1
        if rank == len(rows):
            break
    return rank


def matrix_is_mds(matrix, domain) -> bool:
    """Return whether every square minor of a square matrix is nonsingular.

    EXAMPLES::

        >>> try:
        ...     matrix_is_mds()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    frozen = normalize_matrix(matrix)
    if len(frozen) != len(frozen[0]):
        return False
    size = len(frozen)
    for order in range(1, size + 1):
        for row_indices in combinations(range(size), order):
            for column_indices in combinations(range(size), order):
                minor = tuple(
                    tuple(frozen[row][column] for column in column_indices) for row in row_indices
                )
                if matrix_rank(minor, domain) != order:
                    return False
    return True


def exact_branch_number(
    matrix, domain, *, linear: bool = False, maximum_vectors: int = 65536
) -> int | None:
    """Return an exact unit branch number, or ``None`` above the safe budget.

    Differential propagation uses ``M``. Linear-mask propagation uses
    ``M**T`` explicitly. An MDS proof avoids enumerating the full input space.


    EXAMPLES::

        >>> try:
        ...     exact_branch_number()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    frozen = normalize_matrix(matrix)
    _validate_matrix_domain(frozen, domain)
    selected = transpose_matrix(frozen) if linear else frozen
    if len(selected) == len(selected[0]) and matrix_is_mds(selected, domain):
        return len(selected) + 1
    cardinality = _cardinality(domain)
    vector_count = cardinality ** len(selected[0])
    if vector_count - 1 > maximum_vectors:
        return None
    best = len(selected) + len(selected[0]) + 1
    for vector in product(range(cardinality), repeat=len(selected[0])):
        if not any(vector):
            continue
        output = apply_matrix(selected, vector, domain)
        best = min(best, _weight(vector) + _weight(output))
        if best == 1 or (best == 2 and matrix_rank(selected, domain) == len(selected[0])):
            break
    return best


def exact_matrix_order(matrix, domain, *, maximum_steps: int = 65536, offset=None) -> int | None:
    """Return the exact linear/affine order when found within ``maximum_steps``.

    EXAMPLES::

        >>> try:
        ...     exact_matrix_order()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    frozen = normalize_matrix(matrix)
    if len(frozen) != len(frozen[0]) or matrix_rank(frozen, domain) != len(frozen):
        return None
    size = len(frozen)
    identity = identity_matrix(size)
    current_matrix = identity
    zero = (0,) * size
    affine_offset = zero if offset is None else tuple(offset)
    if len(affine_offset) != size:
        raise ValueError("affine offset length must match matrix size")
    _validate_matrix_domain((affine_offset,), domain)
    current_offset = zero
    for order in range(1, maximum_steps + 1):
        current_offset = tuple(
            _add(domain, value, constant)
            for value, constant in zip(apply_matrix(frozen, current_offset, domain), affine_offset)
        )
        current_matrix = multiply_matrices(frozen, current_matrix, domain)
        if current_matrix == identity and current_offset == zero:
            return order
    return None


def permutation_order(mapping) -> int:
    """Return the least positive order of ``output[i] = input[mapping[i]]``.

    EXAMPLES::

        >>> try:
        ...     permutation_order()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    mapping = tuple(mapping)
    if set(mapping) != set(range(len(mapping))):
        raise ValueError("mapping must be a permutation")
    seen = set()
    order = 1
    for start in range(len(mapping)):
        if start in seen:
            continue
        length, position = 0, start
        while position not in seen:
            seen.add(position)
            position = mapping[position]
            length += 1
        order = order * length // gcd(order, length)
    return order


def expand_binary_field_matrix(matrix, field: BinaryExtensionField):
    """Expand a polynomial-basis field matrix to its explicit MSB-first bit map.

    EXAMPLES::

        >>> try:
        ...     expand_binary_field_matrix()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    frozen = normalize_matrix(matrix)
    _validate_matrix_domain(frozen, field)
    rows = len(frozen) * field.degree
    columns = len(frozen[0]) * field.degree
    expanded = [[0] * columns for _ in range(rows)]
    for word_column in range(len(frozen[0])):
        for bit_column in range(field.degree):
            basis = 1 << (field.degree - 1 - bit_column)
            vector = [0] * len(frozen[0])
            vector[word_column] = basis
            output = apply_matrix(frozen, vector, field)
            column = word_column * field.degree + bit_column
            for word_row, value in enumerate(output):
                for bit_row in range(field.degree):
                    expanded[word_row * field.degree + bit_row][column] = (
                        value >> (field.degree - 1 - bit_row)
                    ) & 1
    return tuple(tuple(row) for row in expanded)


def apply_matrix(matrix, vector, domain):
    """Apply a finite-field matrix to one compatible vector.

    EXAMPLES::

        >>> from claasp.domains import Bit
        >>> from claasp.analysis.linear_properties import apply_matrix
        >>> apply_matrix(((1, 1), (1, 0)), (1, 0), Bit())
        (1, 1)
    """

    frozen = normalize_matrix(matrix)
    vector = tuple(vector)
    if len(vector) != len(frozen[0]):
        raise ValueError("vector length must match matrix column count")
    _validate_matrix_domain((vector,), domain)
    return tuple(
        _sum(
            domain,
            (_multiply(domain, coefficient, value) for coefficient, value in zip(row, vector)),
        )
        for row in frozen
    )


def multiply_matrices(left, right, domain):
    """Multiply two dimension-compatible finite-field matrices.

    EXAMPLES::

        >>> from claasp.domains import Bit
        >>> from claasp.analysis.linear_properties import multiply_matrices
        >>> multiply_matrices(((1, 1),), ((1,), (1,)), Bit())
        ((0,),)
    """

    left, right = normalize_matrix(left), normalize_matrix(right)
    if len(left[0]) != len(right):
        raise ValueError("matrix dimensions do not compose")
    columns = transpose_matrix(right)
    return tuple(
        tuple(
            _sum(domain, (_multiply(domain, x, y) for x, y in zip(row, column)))
            for column in columns
        )
        for row in left
    )


def _weight(vector):
    return sum(value != 0 for value in vector)


def _cardinality(domain):
    if isinstance(domain, Bit):
        return 2
    if isinstance(domain, BinaryExtensionField):
        return 1 << domain.degree
    if isinstance(domain, PrimeField):
        return domain.modulus
    raise TypeError("matrix analysis requires a finite field domain")


def _validate_matrix_domain(matrix, domain):
    if not isinstance(domain, (Bit, BinaryExtensionField, PrimeField)):
        raise TypeError("matrix analysis requires Bit, BinaryExtensionField, or PrimeField")
    for row in matrix:
        for value in row:
            domain.validate(value)


def _add(domain, left, right):
    if isinstance(domain, PrimeField):
        return (left + right) % domain.modulus
    return left ^ right


def _subtract(domain, left, right):
    if isinstance(domain, PrimeField):
        return (left - right) % domain.modulus
    return left ^ right


def _multiply(domain, left, right):
    if isinstance(domain, Bit):
        return left & right
    if isinstance(domain, BinaryExtensionField):
        return binary_field_multiply(domain, left, right)
    return (left * right) % domain.modulus


def _inverse(domain, value):
    if not value:
        raise ZeroDivisionError("zero has no field inverse")
    if isinstance(domain, Bit):
        return 1
    if isinstance(domain, BinaryExtensionField):
        return binary_field_power(domain, value, (1 << domain.degree) - 2)
    return pow(value, domain.modulus - 2, domain.modulus)


def _sum(domain, values):
    result = 0
    for value in values:
        result = _add(domain, result, value)
    return result


__all__ = [
    "apply_matrix",
    "exact_branch_number",
    "exact_matrix_order",
    "expand_binary_field_matrix",
    "matrix_is_mds",
    "matrix_rank",
    "multiply_matrices",
    "permutation_order",
]
