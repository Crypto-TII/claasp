"""Exhaustive arithmetic checks independent of trail-search witnesses."""

from itertools import product

from claasp.representations.constraints.sat import CNFFormula
from claasp.representations.constraints.smt._probability_encoding import (
    _comparison_clauses,
    _encode_probability_product,
)


def test_unsigned_comparison_including_constant_bits_and_out_of_range_bounds():
    for value in range(16):
        bits = tuple(bool(value & (1 << bit)) for bit in range(4))
        for minimum in range(-1, 18):
            clauses = _comparison_clauses(bits, minimum)
            assert all(any(clause) for clause in clauses) == (value >= minimum)


def _circuit(factors, weights, variables):
    variables = list(variables)
    indices = {name: number for number, name in enumerate(variables, 1)}
    clauses, labels = [], []

    def allocate(name):
        if name not in indices:
            variables.append(name)
            indices[name] = len(variables)
        return name

    def add(clause, label):
        clauses.append(tuple(clause))
        labels.append(label)

    bits, denominator = _encode_probability_product(factors, weights, allocate, indices, add)
    return CNFFormula(tuple(variables), tuple(clauses), tuple(labels)), bits, denominator


def _value(bits, values):
    return sum(
        (int(bit) if isinstance(bit, bool) else int(bool(values[abs(bit) - 1]) == (bit > 0)))
        << position
        for position, bit in enumerate(bits)
    )


def test_every_satisfying_two_factor_assignment_is_the_exact_integer_product():
    formula, bits, denominator = _circuit([(2, (1, 2)), (2, (3, 4))], [], ("a0", "a1", "b0", "b1"))
    witnesses: dict[tuple[int, int], set[int]] = {}
    for values in product((0, 1), repeat=formula.variable_count):
        assignment = dict(zip(formula.variables, values))
        if formula.is_satisfied(assignment):
            left, right = values[0] + 2 * values[1], values[2] + 2 * values[3]
            actual = _value(bits, values)
            assert actual == left * right
            witnesses.setdefault((left, right), set()).add(actual)
    assert denominator == 16
    assert witnesses == {(a, b): {a * b} for a in range(4) for b in range(4)}


def test_fractional_factor_and_integer_weight_bits_share_one_exact_objective():
    formula, bits, denominator = _circuit([(2, (True, True, False))], ["weight"], ("weight",))
    found = set()
    for values in product((0, 1), repeat=formula.variable_count):
        if formula.is_satisfied(dict(zip(formula.variables, values))):
            actual = _value(bits, values)
            assert actual == (3 if values[0] else 6)
            found.add((values[0], actual))
    assert denominator == 8
    assert found == {(0, 6), (1, 3)}


def test_comparison_handles_signed_literals_mixed_with_constant_bits():
    bits = (1, -2, True, False)
    for a, b in product((0, 1), repeat=2):
        values = (a, b)
        actual = a + 2 * (1 - b) + 4
        for minimum in range(18):
            clauses = _comparison_clauses(bits, minimum)
            accepted = all(
                any(bool(values[abs(literal) - 1]) == (literal > 0) for literal in clause)
                for clause in clauses
            )
            assert accepted == (actual >= minimum)
