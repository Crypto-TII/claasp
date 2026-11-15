"""Search telemetry distinguishes proofs from empirical runtime estimates."""

import json
from types import SimpleNamespace

from claasp.analysis._search_progress import _SearchLog
from claasp.drivers.solvers import SatStatus


def test_append_log_proof_and_estimate_semantics(tmp_path):
    path = tmp_path / "progress.jsonl"
    log = _SearchLog(path, "fixture", "xor_differential")
    for bound, seconds in ((1, 2.0), (2, 4.0)):
        log.record(bound, SimpleNamespace(status=SatStatus.UNSATISFIABLE, runtime_seconds=seconds))
    log.record(3, SimpleNamespace(status=SimpleNamespace(value="unknown"), runtime_seconds=1.0))
    log.record(
        5,
        SimpleNamespace(status=SatStatus.UNSATISFIABLE, runtime_seconds=1.0),
        objective="probability_numerator_at_least",
    )
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert rows[0]["proved_minimum_weight"] == 2
    assert rows[1]["estimated_seconds_at_next_weight"] == 8.0
    assert rows[1]["estimate_is_proof"] is False
    assert "proved_minimum_weight" not in rows[2]
    assert "proved_minimum_weight" not in rows[3]
    assert "estimated_seconds_at_next_weight" not in rows[3]
    _SearchLog(path, "fixture", "xor_linear").record(
        0, SimpleNamespace(status=SatStatus.SATISFIABLE, runtime_seconds=0.0)
    )
    assert len(path.read_text().splitlines()) == 5


def test_disabled_log_does_not_touch_solver_result():
    _SearchLog(None, "fixture", "xor_linear").record(None, object())
