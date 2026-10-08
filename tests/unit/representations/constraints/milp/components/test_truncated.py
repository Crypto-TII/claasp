"""Legacy four-state wordwise impossible-boundary constraints."""

import pytest

from claasp.representations.constraints.milp import WordwiseImpossibleBoundaryMILPModel
from claasp.semantics.cryptanalysis import legacy_wordwise_impossible_fixture


def test_wordwise_impossible_boundary_preserves_legacy_pairs_and_single_selector():
    fixture = legacy_wordwise_impossible_fixture()
    model = WordwiseImpossibleBoundaryMILPModel(
        fixture.forward_middle, fixture.backward_middle
    ).milp_model()
    assert model.constraints[-1].name == "wordwise_contradiction_exists"
    assert model.constraints[-1].sense.value == "="
    assert model.constraint_models[0].model == WordwiseImpossibleBoundaryMILPModel.model_provenance


def test_wordwise_unknown_state_does_not_itself_prove_incompatibility():
    model = WordwiseImpossibleBoundaryMILPModel("3", "0").milp_model()
    assignment = {variable.name: 0 for variable in model.variables}
    assignment["forward_0_state_3"] = 1
    assignment["backward_0_state_0"] = 1
    assert not model.is_feasible(assignment)


@pytest.mark.parametrize("patterns", (("", ""), ("0", "00"), ("4", "0")))
def test_wordwise_boundary_rejects_invalid_patterns(patterns):
    with pytest.raises(ValueError):
        WordwiseImpossibleBoundaryMILPModel(*patterns)
