import shutil

import pytest

from claasp_next import Bit, Primitive, ValueType
from claasp_next.representations.constraints.sat import BooleanCNFModel
from claasp_next.drivers.solvers import MinisatSolver, SatStatus
from claasp_next.primitives import Present80, Speck
from claasp_next.components import Add


pytestmark = pytest.mark.external


def test_minisat_solves_and_refutes_named_present_constraints():
    assert shutil.which("minisat") is not None, "the external test job must install MiniSat"
    primitive = Present80(number_of_rounds=1)
    formula = BooleanCNFModel(primitive).cnf_formula()
    fixed_inputs = {
        **{f"plaintext_{position}": 0 for position in range(64)},
        **{f"key_{position}": 0 for position in range(80)},
    }
    solver = MinisatSolver(timeout_seconds=30)
    result = solver.solve(formula, fixed_inputs)
    assert result.status is SatStatus.SATISFIABLE
    assert formula.is_satisfied(result.assignment)

    contradictory = {**fixed_inputs, "add_round_key_1_0": 1}
    result = solver.solve(formula, contradictory)
    assert result.status is SatStatus.UNSATISFIABLE
    assert result.assignment is None


def test_high_level_analysis_recovers_an_unknown_input():
    primitive = Primitive("xor", {"plaintext": ValueType(Bit(), (1,)), "key": ValueType(Bit(), (1,))})
    primitive.add_round()
    output = primitive.add_component(Add((primitive.input("plaintext"), primitive.input("key"))))
    primitive.set_output(output)

    result = primitive.analyze().recover_input(
        "key",
        known_inputs={"plaintext": 1},
        output=0,
        solver=MinisatSolver(timeout_seconds=10),
    )
    assert result.is_satisfiable
    assert result.value("key") == 1
    assert result.backend == "MinisatSolver"
    assert result.statistics == {"variables": 3, "clauses": 6}
    assert len(result.reproducibility["formula_sha256"]) == 64


def test_word_level_sat_recovers_a_reduced_speck_key():
    primitive = Speck(number_of_rounds=1)
    plaintext = 0x6574694C
    expected = primitive.evaluate(plaintext, 0x1918111009080100)

    result = primitive.analyze().recover_input(
        "key",
        known_inputs={"plaintext": plaintext},
        output=expected,
        solver=MinisatSolver(timeout_seconds=30),
    )

    assert result.is_satisfiable
    assert primitive.evaluate(plaintext, result.value("key")) == expected
    assert result.statistics["variables"] > 64
