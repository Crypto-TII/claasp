"""Matrix construction helpers."""

from collections.abc import Iterable

from claasp_next.domains import BinaryExtensionField, Bit
from claasp_next.utils.finite_fields import binary_field_multiply, binary_field_power


def identity_matrix(size: int) -> tuple[tuple[int, ...], ...]:
    """Return the square identity matrix of ``size``.

    EXAMPLES::

        >>> from claasp_next.utils import identity_matrix
        >>> identity_matrix(2)
        ((1, 0), (0, 1))
    """

    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise ValueError("matrix size must be a positive integer")
    return tuple(tuple(int(row == column) for column in range(size)) for row in range(size))


def normalize_matrix(matrix: Iterable[Iterable[int]]) -> tuple[tuple[int, ...], ...]:
    """Validate matrix shape and return a stable row-major representation.

    EXAMPLES::

        >>> from claasp_next.utils import normalize_matrix
        >>> normalize_matrix([[1, 2], [3, 4]])
        ((1, 2), (3, 4))
    """

    frozen = tuple(tuple(row) for row in matrix)
    if not frozen or not frozen[0]:
        raise ValueError("matrix must be non-empty")
    if any(len(row) != len(frozen[0]) for row in frozen):
        raise ValueError("matrix rows must have equal length")
    return frozen


def transpose_matrix(matrix: Iterable[Iterable[int]]) -> tuple[tuple[int, ...], ...]:
    """Return a validated rectangular matrix with rows and columns exchanged.

    EXAMPLES::

        >>> from claasp_next.utils import transpose_matrix
        >>> transpose_matrix(((1, 2, 3), (4, 5, 6)))
        ((1, 4), (2, 5), (3, 6))
    """

    frozen = normalize_matrix(matrix)
    return tuple(tuple(column) for column in zip(*frozen))


def matrix_is_invertible(
    matrix: Iterable[Iterable[int]],
    domain: Bit | BinaryExtensionField,
) -> bool:
    """Return whether a square matrix is invertible over a binary domain.

    EXAMPLES::

        >>> from claasp_next import Bit
        >>> from claasp_next.utils import matrix_is_invertible
        >>> matrix_is_invertible(((1, 1), (1, 0)), Bit())
        True
    """

    frozen = [list(row) for row in normalize_matrix(matrix)]
    if (
        not frozen
        or len(frozen) != len(frozen[0])
        or any(len(row) != len(frozen) for row in frozen)
    ):
        return False
    if not isinstance(domain, (Bit, BinaryExtensionField)):
        raise TypeError("domain must be Bit or BinaryExtensionField")
    for row in frozen:
        for coefficient in row:
            domain.validate(coefficient)

    rank = 0
    for column in range(len(frozen)):
        pivot = next(
            (row for row in range(rank, len(frozen)) if frozen[row][column]),
            None,
        )
        if pivot is None:
            continue
        frozen[rank], frozen[pivot] = frozen[pivot], frozen[rank]
        if isinstance(domain, BinaryExtensionField):
            inverse = binary_field_power(
                domain,
                frozen[rank][column],
                (1 << domain.degree) - 2,
            )
            frozen[rank] = [binary_field_multiply(domain, value, inverse) for value in frozen[rank]]
        for row in range(len(frozen)):
            factor = frozen[row][column]
            if row == rank or not factor:
                continue
            if isinstance(domain, Bit):
                frozen[row] = [left ^ right for left, right in zip(frozen[row], frozen[rank])]
            else:
                frozen[row] = [
                    left ^ binary_field_multiply(domain, factor, right)
                    for left, right in zip(frozen[row], frozen[rank])
                ]
        rank += 1
    return rank == len(frozen)


def repeat_block_diagonal(
    block: Iterable[Iterable[int]], copies: int
) -> tuple[tuple[int, ...], ...]:
    """Repeat a square matrix along the diagonal of a larger zero matrix.

    EXAMPLES::

        >>> from claasp_next.utils import repeat_block_diagonal
        >>> repeat_block_diagonal(((1,),), 2)
        ((1, 0), (0, 1))
    """

    frozen = tuple(tuple(row) for row in block)
    if not frozen or any(len(row) != len(frozen) for row in frozen):
        raise ValueError("block must be a non-empty square matrix")
    if not isinstance(copies, int) or isinstance(copies, bool) or copies <= 0:
        raise ValueError("copies must be a positive integer")
    size = len(frozen)
    result = []
    for copy_number in range(copies):
        for block_row in frozen:
            row = [0] * (size * copies)
            start = copy_number * size
            row[start : start + size] = block_row
            result.append(tuple(row))
    return tuple(result)
