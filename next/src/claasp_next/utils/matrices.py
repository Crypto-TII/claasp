"""Matrix construction helpers."""

from collections.abc import Iterable


def repeat_block_diagonal(
    block: Iterable[Iterable[int]], copies: int
) -> tuple[tuple[int, ...], ...]:
    """Repeat a square matrix along the diagonal of a larger zero matrix."""

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
            row[start:start + size] = block_row
            result.append(tuple(row))
    return tuple(result)
