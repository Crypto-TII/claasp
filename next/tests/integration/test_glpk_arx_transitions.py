import pytest

from claasp_next.representations.constraints.milp import ModularAddLinearMILPModel
from claasp_next.drivers.solvers import GLPKSolver, MILPStatus


pytestmark = pytest.mark.external


def test_glpk_restores_speck_linear_modular_add_reference_transitions():
    lowering = ModularAddLinearMILPModel(16)
    reference = (
        (0x6081, 0x40C1, 0x4081),
        (0x0001, 0x0001, 0x0001),
        (0x0000, 0x0000, 0x0000),
        (0x0800, 0x0800, 0x0C00),
    )
    transitions = []
    for masks in reference:
        model = lowering.milp_model(left_mask=masks[0], right_mask=masks[1], output_mask=masks[2])
        solved = GLPKSolver(timeout_seconds=10).solve(model)
        assert solved.status is MILPStatus.OPTIMAL
        transitions.append(lowering.decode_transition(solved.assignment))

    assert [item.weight for item in transitions] == [2, 0, 0, 1]
    assert [item.sign for item in transitions] == [1, 1, 1, -1]
    assert sum(item.weight for item in transitions) == 3
