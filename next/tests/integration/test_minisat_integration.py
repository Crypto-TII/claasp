import shutil

import pytest

from claasp_next import Bit, Cipher, ValueType
from claasp_next.boolean import BooleanCNFModel
from claasp_next.boolean.solvers import MinisatSolver, SatStatus
from claasp_next.ciphers import Present80BlockCipher
from claasp_next.components import Add


pytestmark = pytest.mark.external


def test_minisat_solves_and_refutes_named_present_constraints():
    assert shutil.which("minisat") is not None, "the external test job must install MiniSat"
    cipher = Present80BlockCipher(number_of_rounds=1)
    formula = BooleanCNFModel(cipher).cnf_formula()
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
    cipher = Cipher("xor", {"plaintext": ValueType(Bit(), (1,)), "key": ValueType(Bit(), (1,))})
    cipher.add_round()
    output = cipher.add_component(Add((cipher.input("plaintext"), cipher.input("key"))))
    cipher.set_output(output)

    result = cipher.analyze().recover_input(
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
