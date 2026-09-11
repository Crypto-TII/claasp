import shutil

import pytest

from claasp_next.boolean import BooleanCNFModel
from claasp_next.boolean.solvers import MinisatSolver, SatStatus
from claasp_next.ciphers import Present80BlockCipher


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
