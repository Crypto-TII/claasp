import io
import json

import pytest

from claasp.drivers.solvers import GLPKSolver, MILPProgressLog, MILPStatus
from claasp.representations.constraints.milp import XorParityMILPModel

pytestmark = pytest.mark.external


def test_live_logging_preserves_the_solution_and_final_proof_status():
    model = XorParityMILPModel(3).milp_model(inputs=(1, 0, 1), output=0)
    stream = io.StringIO()
    logged = GLPKSolver(progress_log=MILPProgressLog(stream)).solve(model)
    plain = GLPKSolver().solve(model)
    assert logged.status == plain.status == MILPStatus.OPTIMAL
    assert logged.objective_value == plain.objective_value
    records = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert records[-1]["status"] == "optimal"
    assert records[-2]["event"] == "solution"
    assert model.is_feasible(records[-2]["assignment"])
