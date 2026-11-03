"""Mask optimization, solver-witness replay and retained partial results."""

from dataclasses import replace
from math import isinf

import pytest

from claasp.analysis.continuous_differential import ContinuousDifferentialAnalysis
from claasp.drivers.solvers import CPResult, CPStatus
from claasp.primitives import ModularAdd


def test_fixed_input_mask_optimization_needs_no_external_solver():
    analysis = ContinuousDifferentialAnalysis(ModularAdd(2))
    result = analysis.find_best_correlation(1)
    assert result.output_values == (0.0, 1.0)
    assert result.output_mask == 1 and result.correlation == 1
    assert result.model_complete and result.claim_kind == "heuristic"
    zero = analysis.find_best_correlation(1, output_mask=2)
    assert zero.correlation == 0 and isinf(zero.weight)


def test_mask_constraints_are_retained_when_selecting_a_best_mask():
    result = ContinuousDifferentialAnalysis(ModularAdd(2)).find_best_correlation(
        1, output_mask="1?"
    )
    assert result.output_mask == 2


class _Solver:
    def __init__(
        self, *, output=(0.0, 1.0), mask=(False, True), correlation=1.0, status=CPStatus.SATISFIED
    ):
        self.output, self.mask, self.correlation, self.status = output, mask, correlation, status

    def solve(self, model):
        assert "0.25*" in model.source()
        return CPResult(
            self.status,
            {
                "input_0": [-1.0, 1.0],
                "input_1": [-1.0, -1.0],
                "output_values": self.output,
                "output_mask": self.mask,
                "correlation": self.correlation,
            },
            0.01,
            "checked_fake",
            "----------\n"
            + ("==========" if self.status is CPStatus.SATISFIED else "=====UNKNOWN====="),
            "",
        )


def test_free_input_search_replays_the_heuristic_on_returned_inputs():
    result = ContinuousDifferentialAnalysis(ModularAdd(2)).find_best_correlation(
        "0?", solver=_Solver()
    )
    assert result.correlation == 1 and result.model_complete


def test_unknown_search_preserves_a_checked_candidate_without_claiming_completion():
    result = ContinuousDifferentialAnalysis(ModularAdd(2)).find_best_correlation(
        "0?", solver=_Solver(status=CPStatus.UNKNOWN)
    )
    assert result.correlation == 1 and not result.model_complete


@pytest.mark.parametrize(
    "solver", [_Solver(output=(0.5, 0.5)), _Solver(mask=(False, False)), _Solver(correlation=0.3)]
)
def test_malformed_solver_witnesses_are_rejected(solver):
    with pytest.raises(RuntimeError):
        ContinuousDifferentialAnalysis(ModularAdd(2)).find_best_correlation("0?", solver=solver)


def test_result_does_not_accept_a_proof_status_label():
    result = ContinuousDifferentialAnalysis(ModularAdd(2)).find_one_correlation(1)
    with pytest.raises(ValueError, match="heuristic"):
        replace(result, claim_kind="optimal")


def test_timeout_retains_only_a_complete_checked_incumbent():
    import json
    from subprocess import TimeoutExpired

    class TimedSolver(_Solver):
        def solve(self, model):
            candidate = super().solve(model).values
            output = json.dumps(candidate) + '\n----------\n{"truncated":'
            raise TimeoutExpired("minizinc", 30, output=output)

    result = ContinuousDifferentialAnalysis(ModularAdd(2)).find_best_correlation(
        "0?", solver=TimedSolver()
    )
    assert result.correlation == 1 and not result.model_complete
