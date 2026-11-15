"""The portable bound strategy preserves solver-proved trail optima."""

import json

import pytest

from claasp.drivers.solvers import KissatSolver
from claasp.primitives import ToySpeck

pytestmark = pytest.mark.external


@pytest.mark.parametrize("kind", ["xor_differential", "xor_linear"])
def test_matsui_matches_unbounded_optimum_and_logs_proof(kind, tmp_path):
    primitive = ToySpeck(3)
    method = getattr(primitive.analysis, f"find_lowest_weight_{kind}_trail")
    solver = KissatSolver()
    ordinary = method(solver=solver)
    log = tmp_path / "search.jsonl"
    bounded = method(solver=solver, matsui_bounds=[0, 0], log_file=log)
    assert bounded.trail.total_weight == ordinary.trail.total_weight
    assert bounded.is_optimal
    records = [json.loads(line) for line in log.read_text().splitlines()]
    assert records
    assert records[0]["bound"] is None
    assert all(item["runtime_seconds"] >= 0 for item in records)
    if bounded.trail.total_weight > 0:
        assert any(item["status"] == "unsatisfiable" for item in records)
    for item in records:
        if "proved_minimum_weight" in item:
            assert item["status"] == "unsatisfiable"
            assert item["proved_minimum_weight"] == item["bound"] + 1
