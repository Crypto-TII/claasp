"""Fast structural and scope checks for Speck linear SMT composition."""

from dataclasses import replace

import pytest

from claasp_next.analysis.arx import check_speck_linear_trail, find_four_round_speck_xor_linear
from claasp_next.primitives import Present, Speck
from claasp_next.representations.constraints.smt import SpeckLinearSMTModel


def test_speck_linear_formula_is_deterministic_and_bounded():
    primitive = Speck(number_of_rounds=3)
    first = SpeckLinearSMTModel(primitive, maximum_weight=1).smt_formula()
    assert first == SpeckLinearSMTModel(primitive, maximum_weight=1).smt_formula()
    assert len(first.variables) < 400
    assert first.assertion_count < 3000
    assert "nonzero_linear_input" in first.provenance
    assert "weight_bound" in first.provenance


@pytest.mark.parametrize("options", [{"fixed_weight": -1}, {"maximum_weight": True},
                                    {"fixed_weight": 1.5}, {"maximum_weight": 1, "fixed_weight": 1}])
def test_speck_linear_model_rejects_invalid_weights(options):
    with pytest.raises(ValueError):
        SpeckLinearSMTModel(Speck(number_of_rounds=3), **options)


def test_speck_linear_model_checks_scope_and_build_boundary():
    with pytest.raises(NotImplementedError):
        SpeckLinearSMTModel(Present(number_of_rounds=1))
    with pytest.raises(ValueError, match="build"):
        SpeckLinearSMTModel(Speck(number_of_rounds=3)).decode_trail({})
    formula = SpeckLinearSMTModel(Speck(number_of_rounds=1), fixed_weight=17).smt_formula()
    assert formula.provenance.count("impossible_fixed_weight") == 2


def test_speck_linear_checker_rejects_wrong_component_provenance():
    primitive = Speck(number_of_rounds=4)
    trail = find_four_round_speck_xor_linear(primitive).trail
    assert check_speck_linear_trail(primitive, trail)
    bad_step = replace(trail.steps[0], component_id="wrong")
    assert not check_speck_linear_trail(primitive, replace(trail, steps=(bad_step,) + trail.steps[1:]))
