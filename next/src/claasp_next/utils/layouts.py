"""Small deterministic layout transformations used by primitive authors."""

from collections.abc import Sequence


def reverse_bytes_in_words(
    positions: Sequence[int], *, word_bit_size: int = 32, byte_bit_size: int = 8
) -> tuple[int, ...]:
    """Reverse byte groups inside each fixed-width word.

    This preserves the legacy 32-bit layout result while accepting any whole
    number of equally sized words.

    >>> from claasp_next.utils import reverse_bytes_in_words
    >>> reverse_bytes_in_words(range(32))[:10]
    (24, 25, 26, 27, 28, 29, 30, 31, 16, 17)
    """

    if not isinstance(word_bit_size, int) or isinstance(word_bit_size, bool) or word_bit_size <= 0:
        raise ValueError("word_bit_size must be a positive integer")
    if not isinstance(byte_bit_size, int) or isinstance(byte_bit_size, bool) or byte_bit_size <= 0:
        raise ValueError("byte_bit_size must be a positive integer")
    if word_bit_size % byte_bit_size:
        raise ValueError("word_bit_size must be a multiple of byte_bit_size")
    normalized = tuple(positions)
    if len(normalized) % word_bit_size:
        raise ValueError("positions must contain a whole number of words")
    output: list[int] = []
    byte_count = word_bit_size // byte_bit_size
    for word_start in range(0, len(normalized), word_bit_size):
        word = normalized[word_start : word_start + word_bit_size]
        for byte_index in reversed(range(byte_count)):
            start = byte_index * byte_bit_size
            output.extend(word[start : start + byte_bit_size])
    return tuple(output)
