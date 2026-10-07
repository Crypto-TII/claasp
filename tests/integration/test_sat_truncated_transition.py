"""Recovered deterministic-truncated SAT transition through canonical solvers."""

import pytest

from claasp.drivers.solvers import (
    CryptoMiniSatSolver,
    KissatSolver,
    MinisatSolver,
    SatStatus,
)
from claasp.representations.constraints.sat import ModularAddDeterministicTruncatedSATModel

pytestmark = pytest.mark.external


def _fixed(model, prefix, pattern):
    return {
        f"{prefix}_{bit}_{field}": value
        for bit, encoded in enumerate(model.encode_pattern(pattern))
        for field, value in zip(("unknown", "value"), encoded)
    }


@pytest.mark.parametrize("solver_type", (MinisatSolver, KissatSolver, CryptoMiniSatSolver))
def test_deterministic_truncated_modadd_accepts_only_the_semantic_output(solver_type):
    model = ModularAddDeterministicTruncatedSATModel(4)
    formula = model.cnf_formula()
    boundary = _fixed(model, "left", "0001") | _fixed(model, "right", "0001")
    accepted = solver_type(timeout_seconds=10).solve(
        formula, boundary | _fixed(model, "output", "???0")
    )
    assert accepted.status is SatStatus.SATISFIABLE
    left, right, output = model.decode_transition(accepted.assignment)
    assert tuple(map(str, (left, right, output))) == ("0001", "0001", "???0")

    rejected = solver_type(timeout_seconds=10).solve(
        formula, boundary | _fixed(model, "output", "0000")
    )
    assert rejected.status is SatStatus.UNSATISFIABLE
