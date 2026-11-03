"""Legacy restricted large-switch automaton, translated to Boolean gates.

Table ported from CLAASP minizinc_utils/mzn_bct_predicates.py at
1136c49f8b68fdc1839eb9df04132c99a2e05387 (GPL-3.0-or-later).
The unused legacy halfSize column is retained in the source table for review.
"""

from claasp.representations.constraints.sat.quasidifferential import _negate

_TABLE = [
    [
        [0, 0, 0, 0, 1, 0, 0, 0, 0],
        [1, 0, 0, 0, 1, 1, 0, 0, 1],
        [0, 1, 0, 0, 1, 1, 0, 0, 1],
        [1, 1, 0, 0, 1, 1, 0, 0, 1],
        [0, 0, 1, 0, 1, 0, 1, 0, 1],
        [1, 0, 1, 0, 1, 0, 0, 1, 1],
        [0, 1, 1, 0, 0, 0, 0, 0, 0],
        [1, 1, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 1, 1, 0, 1, 0, 1],
        [1, 0, 0, 1, 0, 0, 0, 0, 0],
        [0, 1, 0, 1, 0, 0, 0, 0, 0],
        [1, 1, 0, 1, 1, 0, 0, 1, 1],
        [0, 0, 1, 1, 1, 0, 1, 0, 1],
        [1, 0, 1, 1, 0, 0, 0, 0, 0],
        [0, 1, 1, 1, 1, 0, 0, 1, 1],
        [1, 1, 1, 1, 0, 0, 0, 0, 0],
    ],
    [
        [0, 0, 0, 0, 1, 1, 0, 0, 1],
        [1, 0, 0, 0, 1, 1, 0, 0, 1],
        [0, 1, 0, 0, 1, 1, 0, 0, 1],
        [1, 1, 0, 0, 0, 1, 0, 0, 0],
        [0, 0, 1, 0, 0, 0, 0, 0, 0],
        [1, 0, 1, 0, 0, 0, 0, 0, 0],
        [0, 1, 1, 0, 0, 1, 1, 0, 1],
        [1, 1, 1, 0, 0, 1, 0, 1, 1],
        [0, 0, 0, 1, 0, 1, 1, 0, 1],
        [1, 0, 0, 1, 0, 0, 0, 0, 0],
        [0, 1, 0, 1, 0, 0, 0, 0, 0],
        [1, 1, 0, 1, 0, 1, 0, 1, 1],
        [0, 0, 1, 1, 0, 0, 0, 0, 0],
        [1, 0, 1, 1, 0, 1, 1, 0, 1],
        [0, 1, 1, 1, 0, 0, 0, 0, 0],
        [1, 1, 1, 1, 0, 1, 0, 1, 1],
    ],
    [
        [0, 0, 0, 0, 1, 0, 1, 0, 1],
        [1, 0, 0, 0, 0, 0, 0, 0, 0],
        [0, 1, 0, 0, 0, 1, 1, 0, 1],
        [1, 1, 0, 0, 0, 0, 0, 0, 0],
        [0, 0, 1, 0, 1, 0, 1, 0, 1],
        [1, 0, 1, 0, 0, 0, 0, 0, 0],
        [0, 1, 1, 0, 0, 0, 0, 0, 0],
        [1, 1, 1, 0, 0, 1, 1, 0, 1],
        [0, 0, 0, 1, 1, 0, 1, 0, 1],
        [1, 0, 0, 1, 0, 1, 1, 0, 1],
        [0, 1, 0, 1, 0, 0, 0, 0, 0],
        [1, 1, 0, 1, 0, 0, 0, 0, 0],
        [0, 0, 1, 1, 0, 0, 1, 0, 0],
        [1, 0, 1, 1, 0, 0, 1, 1, 1],
        [0, 1, 1, 1, 0, 0, 1, 1, 1],
        [1, 1, 1, 1, 0, 0, 1, 1, 1],
    ],
    [
        [0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 1, 0, 0, 1, 1],
        [0, 1, 0, 0, 0, 0, 0, 0, 0],
        [1, 1, 0, 0, 0, 1, 0, 1, 1],
        [0, 0, 1, 0, 1, 0, 0, 1, 1],
        [1, 0, 1, 0, 0, 0, 0, 0, 0],
        [0, 1, 1, 0, 0, 0, 0, 0, 0],
        [1, 1, 1, 0, 0, 1, 0, 1, 1],
        [0, 0, 0, 1, 0, 0, 0, 0, 0],
        [1, 0, 0, 1, 0, 0, 0, 0, 0],
        [0, 1, 0, 1, 1, 0, 0, 1, 1],
        [1, 1, 0, 1, 0, 1, 0, 1, 1],
        [0, 0, 1, 1, 0, 0, 1, 1, 1],
        [1, 0, 1, 1, 0, 0, 1, 1, 1],
        [0, 1, 1, 1, 0, 0, 1, 1, 1],
        [1, 1, 1, 1, 0, 0, 0, 1, 0],
    ],
]


def add_large_switch(builder, d_left, d_right, n_left, n_right, *, half_limit=1):
    """Constrain the original large-switch search subset (LSB first)."""
    state = (True, False, False, False)
    halves = []
    for bits in zip(
        reversed(d_left[1:]), reversed(d_right[1:]), reversed(n_left[1:]), reversed(n_right[1:])
    ):
        matrix = [[builder.fresh("bct") for _ in range(4)] for _ in range(4)]
        for column, rows in enumerate(_TABLE):
            for row in rows:
                mismatch = tuple(
                    _negate(value) if fixed else value for value, fixed in zip(bits, row[:4])
                )
                for index, fixed in enumerate(row[4:8]):
                    builder.add(
                        (*mismatch, matrix[index][column] if fixed else -matrix[index][column]),
                        "legacy_bct_table",
                    )
        following = tuple(
            builder.or_(builder.and_((matrix[r][c], state[c])) for c in range(4)) for r in range(4)
        )
        builder.require(builder.or_(following), "nonempty_bct_state")
        half = builder.or_(builder.and_((state[j], -matrix[j][j])) for j in range(4))
        halves.append(half)
        for j in range(4):
            builder.add((half, _negate(state[j]), matrix[j][j]), "legacy_large_switch")
            builder.add((half, _negate(state[j]), following[j]), "legacy_large_switch")
        state = following
    # The legacy algorithm permits at most one halving position per switch.
    if half_limit != 1:
        raise ValueError("the legacy large-switch model supports half_limit=1 only")
    for index, left in enumerate(halves):
        for right in halves[index + 1 :]:
            builder.add((_negate(left), _negate(right)), "at_most_one_bct_half")
