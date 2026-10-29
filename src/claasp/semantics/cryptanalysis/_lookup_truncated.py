"""Exact bitwise abstractions of finite lookup-table difference supports."""

from functools import lru_cache
from itertools import product

from claasp.semantics.cryptanalysis.truncated import TruncatedXorDifference


@lru_cache(maxsize=128)
def _difference_extrema(table, output_width):
    width = len(table).bit_length() - 1
    if len(table) != 1 << width or not 1 <= width <= 8:
        raise NotImplementedError("truncated lookup relations support at most eight input bits")
    if any(type(value) is not int or not 0 <= value < 1 << output_width for value in table):
        raise ValueError("lookup entries must fit output_width")
    result = []
    for difference in range(len(table)):
        lower, upper = (1 << output_width) - 1, 0
        for x, value in enumerate(table):
            output = value ^ table[x ^ difference]
            lower &= output
            upper |= output
        result.append((lower, upper))
    return tuple(result)


def _truncated_lookup(table, pattern, output_width):
    extrema = _difference_extrema(tuple(table), output_width)
    choices = tuple((0, 1) if symbol == "?" else (int(symbol),) for symbol in str(pattern))
    if 1 << len(choices) != len(table):
        raise ValueError("lookup input pattern has the wrong width")
    lower, upper = (1 << output_width) - 1, 0
    for bits in product(*choices):
        difference = sum(bit << (len(bits) - 1 - index) for index, bit in enumerate(bits))
        local_lower, local_upper = extrema[difference]
        lower &= local_lower
        upper |= local_upper
    return TruncatedXorDifference.parse(
        "".join(
            "?" if ((lower ^ upper) >> bit) & 1 else str((lower >> bit) & 1)
            for bit in reversed(range(output_width))
        )
    )
