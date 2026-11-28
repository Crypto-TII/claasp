"""Exact local boomerang counts and MiniZinc tables for bijective S-boxes.

The BCT is defined by Cid et al., EUROCRYPT 2018,
https://doi.org/10.1007/978-3-319-78375-8_22. Table entries count local
quartets, while their rounded negative logarithms are search weights.
"""

import hashlib
import math
from collections import Counter
from functools import lru_cache

_DIFFERENCES = {
    "bct": ("upper_input", "lower_output"),
    "ubct": ("upper_input", "upper_output", "lower_output"),
    "lbct": ("upper_input", "lower_input", "lower_output"),
    "ebct": ("upper_input", "upper_output", "lower_input", "lower_output"),
}


def _validated_permutation(mapping):
    """Return a square S-box permutation or explain why BCT is unavailable."""
    values = tuple(mapping)
    size = len(values)
    if size < 2 or size & (size - 1) or size > 256 or set(values) != set(range(size)):
        raise NotImplementedError(
            "Local S-box switch tables require a bijective S-box of at most eight bits"
        )
    return values


def sbox_switch_counts(mapping, kind):
    """Count nonzero local boomerang transitions for a bijective S-box.

    ``kind`` selects BCT, UBCT, LBCT, or EBCT. Counts are numerators; divide
    by the S-box domain size for local probabilities. The extended tables
    retain the upper output and/or lower input difference of each quartet.

    EXAMPLES::

        sage: from claasp.cipher_modules.models.cp.minizinc_utils.mzn_sbox_switch_tables import sbox_switch_counts
        sage: present = (12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2)
        sage: sbox_switch_counts(present, 'bct')[1, 5]
        16
    """
    values = _validated_permutation(mapping)
    if kind not in _DIFFERENCES:
        raise ValueError(f"Unknown S-box switch table: {kind}")
    return _all_sbox_switch_counts(values)[kind]


@lru_cache(maxsize=16)
def _all_sbox_switch_counts(values):
    """Project the same valid quartets into all four switch tables."""
    size = len(values)
    inverse = [0] * size
    for x, value in enumerate(values):
        inverse[value] = x
    counts = {kind: Counter() for kind in _DIFFERENCES}
    for upper_input in range(size):
        for lower_output in range(size):
            for x in range(size):
                y0 = values[x]
                y1 = values[x ^ upper_input]
                x2 = inverse[y0 ^ lower_output]
                x3 = inverse[y1 ^ lower_output]
                if x2 ^ x3 == upper_input:
                    upper_output = y0 ^ y1
                    lower_input = x ^ x2
                    counts["bct"][upper_input, lower_output] += 1
                    counts["ubct"][upper_input, upper_output, lower_output] += 1
                    counts["lbct"][upper_input, lower_input, lower_output] += 1
                    counts["ebct"][
                        upper_input, upper_output, lower_input, lower_output
                    ] += 1
    return {kind: dict(table) for kind, table in counts.items()}


def minizinc_sbox_switch_table(mapping, kind):
    """Return a deterministic MiniZinc table of differences and centibit weights."""
    values = _validated_permutation(mapping)
    counts = sbox_switch_counts(values, kind)
    width = len(values).bit_length() - 1
    columns = width * len(_DIFFERENCES[kind]) + 1
    name = f"sbox_{kind}_{hashlib.sha256(bytes(values)).hexdigest()[:12]}"
    entries = []
    for differences, count in sorted(counts.items()):
        entries.extend(
            int(bit) for difference in differences for bit in f"{difference:0{width}b}"
        )
        entries.append(round(100 * math.log2(len(values) / count)))
    rows = len(counts)
    declaration = (
        f"array[1..{rows}, 1..{columns}] of int: {name} = "
        f"array2d(1..{rows}, 1..{columns}, [{','.join(map(str, entries))}]);"
    )
    return name, declaration
