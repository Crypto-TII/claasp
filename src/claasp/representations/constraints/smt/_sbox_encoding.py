"""Exact CNF relations for differential and linear lookup-table transitions."""

from fractions import Fraction
from functools import lru_cache

from claasp.semantics.cryptanalysis import SBoxTransitionSemantics, TrailKind


class _NonIntegralTransitionWeightError(NotImplementedError):
    """A lookup table has exact probabilities not representable by integer weights."""


@lru_cache(maxsize=None)
def _weighted_transitions(table: tuple[int, ...], kind: TrailKind, output_width: int | None = None):
    semantics = SBoxTransitionSemantics(table, output_width)
    if kind is TrailKind.XOR_DIFFERENTIAL:
        counts: dict[tuple[int, int], int] = {}
        for source in range(1 << semantics.width):
            for value, output in enumerate(table):
                target = output ^ table[value ^ source]
                counts[source, target] = counts.get((source, target), 0) + 1
        transitions = tuple(
            (source, target, count) for (source, target), count in sorted(counts.items())
        )
    else:
        rows = semantics.walsh_correlation_table()
        transitions = tuple(
            (source, target, abs(count))
            for source, row in enumerate(rows)
            for target, count in enumerate(row)
            if count
        )
    weighted: list[tuple[int, int, int]] = []
    for source, target, count in transitions:
        ratio = Fraction(len(table), count)
        if ratio.denominator != 1 or ratio.numerator & (ratio.numerator - 1):
            raise _NonIntegralTransitionWeightError(
                f"{kind.value} lookup transition count {count}/{len(table)} "
                "has a non-integral exact weight"
            )
        weighted.append((source, target, ratio.numerator.bit_length() - 1))
    return semantics, tuple(weighted)


def _require_integral_sbox_weights(table, kind, output_width=None):
    """Validate that every possible transition has an exact integer weight."""

    _weighted_transitions(tuple(table), kind, output_width)


def _add_sbox_relation(
    table,
    kind,
    input_names,
    output_names,
    prefix,
    allocate,
    indices,
    add,
):
    """Add support and exact unary-weight functions for one lookup application."""

    semantics, assignments = _weighted_transitions(tuple(table), kind, len(output_names))
    if len(input_names) != semantics.width or len(output_names) != semantics.output_width:
        raise ValueError("lookup relation variables do not match its encoded widths")

    maximum = max(weight for _, _, weight in assignments)
    signatures: dict[tuple[bool, ...], str] = {}
    threshold_names: list[str] = []
    for threshold in range(maximum):
        signature = tuple(weight > threshold for _, _, weight in assignments)
        name = signatures.get(signature)
        if name is None:
            name = allocate(f"weight_{prefix}_{len(signatures)}")
            signatures[signature] = name
        threshold_names.append(name)

    if kind is TrailKind.XOR_DIFFERENTIAL:
        _add_differential_support(
            tuple(table), input_names, output_names, prefix, allocate, indices, add
        )
    else:
        supported = {(source, target) for source, target, _ in assignments}
        for source in range(1 << semantics.width):
            for target in range(1 << semantics.output_width):
                if (source, target) in supported:
                    continue
                encoded = tuple(
                    (source >> (semantics.width - 1 - bit)) & 1 for bit in range(semantics.width)
                ) + tuple(
                    (target >> (semantics.output_width - 1 - bit)) & 1
                    for bit in range(semantics.output_width)
                )
                add(
                    tuple(
                        -indices[name] if value else indices[name]
                        for name, value in zip(input_names + output_names, encoded)
                    ),
                    f"{kind.value}_lookup_support",
                )

    possible = (True,) * len(assignments)
    encoded_assignments = []
    for source, target, _ in assignments:
        encoded = tuple(
            (source >> (semantics.width - 1 - bit)) & 1 for bit in range(semantics.width)
        ) + tuple(
            (target >> (semantics.output_width - 1 - bit)) & 1
            for bit in range(semantics.output_width)
        )
        encoded_assignments.append(encoded)

    if kind is TrailKind.XOR_DIFFERENTIAL:
        for number, (signature, name) in enumerate(signatures.items()):
            _encode_partial_predicate(
                encoded_assignments,
                possible,
                signature,
                input_names + output_names,
                name,
                f"{prefix}_{number}",
                allocate,
                indices,
                add,
            )
        return tuple(threshold_names)

    for position, (_, _, _weight) in enumerate(assignments):
        encoded = encoded_assignments[position]
        forbid = tuple(
            -indices[name] if value else indices[name]
            for name, value in zip(input_names + output_names, encoded)
        )
        for signature, name in signatures.items():
            expected = signature[position]
            add(
                forbid + ((indices[name] if expected else -indices[name]),),
                f"{kind.value}_lookup_weight",
            )
    return tuple(threshold_names)


def _add_differential_support(
    table, differences, output_differences, prefix, allocate, indices, add
):
    """Encode ``S(x) xor S(x xor difference)`` with existential concrete values."""

    input_width = len(differences)
    output_width = len(output_differences)
    left = tuple(allocate(f"{prefix}_witness_left_{bit}") for bit in range(input_width))
    right = tuple(allocate(f"{prefix}_witness_right_{bit}") for bit in range(input_width))
    left_output = tuple(
        allocate(f"{prefix}_witness_left_output_{bit}") for bit in range(output_width)
    )
    right_output = tuple(
        allocate(f"{prefix}_witness_right_output_{bit}") for bit in range(output_width)
    )
    for first, difference, second in zip(left, differences, right):
        a, b, c = indices[first], indices[difference], indices[second]
        add((-a, -b, -c), "lookup_witness_xor")
        add((a, b, -c), "lookup_witness_xor")
        add((a, -b, c), "lookup_witness_xor")
        add((-a, b, c), "lookup_witness_xor")
    for first, second, difference in zip(left_output, right_output, output_differences):
        a, b, c = indices[first], indices[second], indices[difference]
        add((-a, -b, -c), "lookup_witness_xor")
        add((a, b, -c), "lookup_witness_xor")
        add((a, -b, c), "lookup_witness_xor")
        add((-a, b, c), "lookup_witness_xor")

    for concrete, value in enumerate(table):
        bits = tuple((concrete >> (input_width - 1 - bit)) & 1 for bit in range(input_width))
        for names, outputs in ((left, left_output), (right, right_output)):
            forbid = tuple(
                -indices[name] if encoded else indices[name] for name, encoded in zip(names, bits)
            )
            for bit, name in enumerate(outputs):
                expected = (value >> (output_width - 1 - bit)) & 1
                add(
                    forbid + ((indices[name] if expected else -indices[name]),),
                    "lookup_witness_value",
                )


def _encode_partial_predicate(
    assignments,
    possible,
    signature,
    variable_names,
    result_name,
    prefix,
    allocate,
    indices,
    add,
):
    """Encode a predicate only on supported transitions using its sparse polarity."""

    true_positions = tuple(
        position for position, value in enumerate(signature) if possible[position] and value
    )
    false_positions = tuple(
        position for position, value in enumerate(signature) if possible[position] and not value
    )
    selected, complement = (
        (true_positions, False)
        if len(true_positions) <= len(false_positions)
        else (false_positions, True)
    )
    selectors = []
    for number, position in enumerate(selected):
        selector = allocate(f"predicate_{prefix}_{number}")
        selectors.append(selector)
        expected_literals = tuple(
            indices[name] if value else -indices[name]
            for name, value in zip(variable_names, assignments[position])
        )
        for literal in expected_literals:
            add((-indices[selector], literal), "lookup_weight_predicate")
        add(
            (indices[selector], *(-literal for literal in expected_literals)),
            "lookup_weight_predicate",
        )
    predicate = allocate(f"predicate_{prefix}_sparse")
    for selector in selectors:
        add((-indices[selector], indices[predicate]), "lookup_weight_predicate")
    add(
        (-indices[predicate], *(indices[selector] for selector in selectors)),
        "lookup_weight_predicate",
    )
    if complement:
        add((indices[result_name], indices[predicate]), "lookup_weight_predicate")
        add((-indices[result_name], -indices[predicate]), "lookup_weight_predicate")
    else:
        add((-indices[result_name], indices[predicate]), "lookup_weight_predicate")
        add((indices[result_name], -indices[predicate]), "lookup_weight_predicate")
