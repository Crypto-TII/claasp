# Copyright 2026 Technology Innovation Institute
# SPDX-License-Identifier: GPL-3.0-or-later

"""Private quadratic character-sum helpers for fixed-key Feistel windows."""

from fractions import Fraction


def _pivot_column(work, column, rank):
    selected = next((j for j in range(rank, len(work)) if work[j] >> column & 1), None)
    if selected is None:
        return False
    work[rank], work[selected] = work[selected], work[rank]
    for j, row in enumerate(work):
        if j != rank and row >> column & 1:
            work[j] ^= work[rank]
    return True


def _kernel_basis(rows, pivots, width):
    kernel = []
    for column in range(width):
        if column in pivots:
            continue
        vector = 1 << column
        for (row, _), pivot in zip(rows, pivots):
            vector |= ((row >> column) & 1) << pivot
        kernel.append(vector)
    return kernel


def _affine_space(rows, width):
    """Reduce a system already certified consistent by the rank analyzer."""
    work = [mask | (rhs << width) for mask, rhs in rows]
    pivots = []
    for column in range(width):
        if _pivot_column(work, column, len(pivots)):
            pivots.append(column)
    mask = (1 << width) - 1
    basis_rows = [(row & mask, row >> width) for row in work[: len(pivots)]]
    particular = sum(rhs << column for (_, rhs), column in zip(basis_rows, pivots))
    return basis_rows, particular, _kernel_basis(basis_rows, pivots, width)


def _eliminate_pair(rows, active, constant, linear, first, second):
    remaining = active & ~(1 << first | 1 << second)
    a, b = rows[first] & remaining, rows[second] & remaining
    u, v = linear >> first & 1, linear >> second & 1
    constant ^= u & v
    linear ^= (b if u else 0) ^ (a if v else 0) ^ (a & b)
    for i in range(len(rows)):
        if remaining >> i & 1:
            rows[i] ^= (b if a >> i & 1 else 0) ^ (a if b >> i & 1 else 0)
            rows[i] &= remaining
    return remaining, constant, linear & remaining


def _quadratic_character_sum(constant, linear, adjacency):
    """Eliminate pairs using sum(-1)^(xy+xA+yB)=2*(-1)^(AB)."""
    rows = list(adjacency)
    active = (1 << len(rows)) - 1
    multiplier = 1
    while True:
        first = next(
            (i for i, row in enumerate(rows) if active >> i & 1 and row & active), None
        )
        if first is None:
            if linear & active:
                return 0
            return (-1 if constant else 1) * multiplier * (1 << active.bit_count())
        adjacent = rows[first] & active
        second = (adjacent & -adjacent).bit_length() - 1
        active, constant, linear = _eliminate_pair(
            rows, active, constant, linear, first, second
        )
        multiplier *= 2


def _quadratic_coefficients(function, particular, kernel):
    constant = function(particular)
    singleton = [function(particular ^ vector) for vector in kernel]
    linear = [value ^ constant for value in singleton]
    pairs = [
        (i, j, function(particular ^ a ^ b) ^ singleton[i] ^ singleton[j] ^ constant)
        for i, a in enumerate(kernel)
        for j, b in enumerate(kernel)
        if i < j
    ]
    return constant, linear, pairs


def _scalar_anf(selector, constant, linear, pairs):
    constant_bit = (constant & selector).bit_count() & 1
    linear_mask = sum(
        ((value & selector).bit_count() & 1) << i for i, value in enumerate(linear)
    )
    adjacency = [0] * len(linear)
    for i, j, value in pairs:
        if (value & selector).bit_count() & 1:
            adjacency[i] |= 1 << j
            adjacency[j] |= 1 << i
    return constant_bit, linear_mask, adjacency


def _walsh_inversion(spectrum):
    stride = 1
    while stride < len(spectrum):
        for block in range(0, len(spectrum), 2 * stride):
            for j in range(block, block + stride):
                a, b = spectrum[j], spectrum[j + stride]
                spectrum[j], spectrum[j + stride] = a + b, a - b
        stride *= 2
    return [value // len(spectrum) for value in spectrum]


def _fiber_counts(function, particular, kernel, output_bits):
    coefficients = _quadratic_coefficients(function, particular, kernel)
    spectrum = [
        _quadratic_character_sum(*_scalar_anf(selector, *coefficients))
        for selector in range(1 << output_bits)
    ]
    return _walsh_inversion(spectrum)


def _relation_word(relation, upper, lower):
    word = rhs = 0
    for j, (row, value) in enumerate(upper + lower):
        if relation >> j & 1:
            rhs ^= value
            if j < len(upper):
                word ^= row
    return word, rhs


def _intersection_rows(upper, lower, width):
    rows = upper + lower
    transposed = [
        (sum(((row >> bit) & 1) << j for j, (row, _) in enumerate(rows)), 0)
        for bit in range(width)
    ]
    relations = _affine_space(transposed, len(rows))[2]
    return [_relation_word(relation, upper, lower) for relation in relations]


def _fixed_key_distribution(function, width, systems, middle_key, max_overlap):
    upper, lower, joint = [
        _affine_space(systems[name]["rows"], width)
        for name in ("upper", "lower", "joint")
    ]
    intersection = _intersection_rows(upper[0], lower[0], width)
    overlap = len(intersection)
    if overlap > max_overlap:
        raise ValueError(
            f"Row-space overlap {overlap} exceeds max_overlap {max_overlap}"
        )

    def projected(value):
        output = function(value)
        return sum(
            ((row & output).bit_count() & 1) << j
            for j, (row, _) in enumerate(intersection)
        )

    counts = (
        _fiber_counts(projected, joint[1], joint[2], overlap)
        if overlap
        else [1 << len(joint[2])]
    )
    target = sum(
        (rhs ^ ((row & middle_key).bit_count() & 1)) << j
        for j, (row, rhs) in enumerate(intersection)
    )
    stacked_rank = len(upper[0]) + len(lower[0]) - overlap
    probability = Fraction(counts[target], 1 << (width + stacked_rank))
    return dict(
        compatible=probability > 0,
        key_independent=len(set(counts)) == 1,
        probability=probability,
        overlap_rank=overlap,
        stacked_rank=stacked_rank,
        joint_affine_dimension=len(joint[2]),
        key_target=target,
        common_rows=[row for row, _ in intersection],
        target_constants=[rhs for _, rhs in intersection],
        fiber_counts=counts,
    )
