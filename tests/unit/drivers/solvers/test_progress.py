"""Bounds are informational; only independently checked witnesses are recorded."""

import io
import json
import subprocess
import sys

import pytest

from claasp.drivers.solvers import GLPKSolver, MILPProgressLog
from claasp.representations.constraints.milp import XorParityMILPModel


def test_log_scales_bounds_and_never_calls_them_optimal():
    stream = io.StringIO()
    log = MILPProgressLog(stream, objective_scale=100)
    log.feed("+ 1: mip = 300 >= 200 33.3% (1; 0)")
    event = json.loads(stream.getvalue())
    assert event["dual_bound"] == 2
    assert event["incumbent"] == 3
    assert "optimal" not in stream.getvalue()
    assert log.feed("unrelated solver output") is None


def test_invalid_intermediate_assignment_is_rejected():
    model = XorParityMILPModel(2).milp_model(inputs=(1, 0), output=1)
    stream = io.StringIO()
    with pytest.raises(ValueError, match="violates"):
        MILPProgressLog(stream).record_solution(model, {})
    assert not stream.getvalue()


def test_streaming_driver_drains_both_streams_and_keeps_output():
    log = MILPProgressLog(io.StringIO())
    solver = GLPKSolver(progress_log=log, timeout_seconds=10)
    code = "import sys; print('x'*100000, file=sys.stderr); print('+ 1: mip = 3 >= 2 33% (1; 0)')"
    completed = solver._run_with_progress([sys.executable, "-c", code])
    assert completed.returncode == 0
    assert len(completed.stderr) == 100001
    assert log.snapshots[-1].dual_bound == 2


def test_streaming_timeout_applies_to_a_silent_process():
    solver = GLPKSolver(progress_log=MILPProgressLog(io.StringIO()), timeout_seconds=0.1)
    with pytest.raises(subprocess.TimeoutExpired):
        solver._run_with_progress([sys.executable, "-c", "import time; time.sleep(10)"])


def test_gurobi_callback_records_only_checked_solutions():
    from types import SimpleNamespace

    from claasp.drivers.solvers import GurobiSolver

    codes = SimpleNamespace(MIP=1, MIPSOL=2, MIP_OBJBND=3, MIP_OBJBST=4)
    gp = SimpleNamespace(GRB=SimpleNamespace(Callback=codes))
    model = XorParityMILPModel(2).milp_model(inputs=(1, 0), output=1)
    stream = io.StringIO()
    log = MILPProgressLog(stream)
    callback = GurobiSolver(progress_log=log)._progress_callback(gp, model, {})
    native = SimpleNamespace(cbGet=lambda code: {3: 0, 4: 1}[code])
    callback(native, codes.MIP)
    assert log.snapshots[-1].incumbent == 1
    with pytest.raises(ValueError, match="violates"):
        callback(native, codes.MIPSOL)
    assert all(json.loads(line)["event"] == "bounds" for line in stream.getvalue().splitlines())
