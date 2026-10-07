"""Exhaustive one-bit AND MILP parity through the open-source GLPK solver."""

import pytest

from claasp.drivers.solvers import GLPKSolver, MILPStatus
from claasp.representations.constraints.milp import (
    BitwiseAndOneHotMILPModel,
    BitwiseAndXorDifferentialMILPModel,
    BitwiseAndXorLinearMILPModel,
)
from claasp.semantics.cryptanalysis import BitwiseAndSemantics, TrailKind

pytestmark = pytest.mark.external


@pytest.mark.parametrize(
    ("kind", "model_types"),
    (
        (
            TrailKind.XOR_DIFFERENTIAL,
            (BitwiseAndOneHotMILPModel, BitwiseAndXorDifferentialMILPModel),
        ),
        (TrailKind.XOR_LINEAR, (BitwiseAndOneHotMILPModel, BitwiseAndXorLinearMILPModel)),
    ),
)
def test_bitwise_and_milp_models_match_exact_one_bit_semantics(kind, model_types):
    semantics = BitwiseAndSemantics(1)
    solver = GLPKSolver(timeout_seconds=10)
    for left in range(2):
        for right in range(2):
            for output in range(2):
                expected = (
                    semantics.xor_differential(left, right, output)
                    if kind is TrailKind.XOR_DIFFERENTIAL
                    else semantics.xor_linear(left, right, output)
                )
                objectives = []
                for model_type in model_types:
                    model = (
                        model_type(1, kind)
                        if model_type is BitwiseAndOneHotMILPModel
                        else model_type(1)
                    )
                    formulation = model.milp_model(
                        left_pattern=left, right_pattern=right, output_pattern=output
                    )
                    result = solver.solve(formulation)
                    if not expected.is_possible:
                        assert result.status is MILPStatus.INFEASIBLE
                        continue
                    assert result.status is MILPStatus.OPTIMAL
                    transition = model.decode_transition(result.assignment)
                    assert transition == expected
                    objectives.append(result.objective_value)
                if expected.is_possible:
                    assert objectives == [expected.weight, expected.weight]
