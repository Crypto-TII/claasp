"""Exhaustive independent truth-table check of the carry relation."""

from itertools import product

import pytest

from claasp_next.representations.constraints.sat import CNFFormula
from claasp_next.representations.constraints.smt.transitions import ModularAddDifferentialSMTModel


@pytest.mark.parametrize("width", [1, 2, 3])
def test_all_small_modadd_ddt_entries_and_weights(width):
    model = ModularAddDifferentialSMTModel(width)
    formula = model.smt_formula()
    cnf = CNFFormula(formula.variables, formula.assertions, formula.provenance)
    mask = (1 << width) - 1
    for alpha, beta, gamma in product(range(1 << width), repeat=3):
        count = sum((((x + y) & mask) ^ (((x ^ alpha) + (y ^ beta)) & mask)) == gamma
                    for x, y in product(range(1 << width), repeat=2))
        assignment = {f"{prefix}_{bit}": (value >> (width - 1 - bit)) & 1
                      for prefix, value in zip(("left", "right", "output"), (alpha, beta, gamma))
                      for bit in range(width)}
        accepted = []
        for weights in product((0, 1), repeat=width - 1):
            candidate = assignment | {f"weight_{bit}": value for bit, value in enumerate(weights)}
            if cnf.is_satisfied(candidate):
                accepted.append(candidate)
        assert len(accepted) == int(count != 0)
        if accepted:
            transition = model.decode_transition(accepted[0])
            assert transition.numerator == count
            assert transition.denominator == 1 << (2 * width)
