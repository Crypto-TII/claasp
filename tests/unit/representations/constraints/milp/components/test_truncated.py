"""Legacy four-state wordwise impossible-boundary constraints."""

from itertools import product

import pytest

from claasp.representations.constraints.milp import (
    WordwiseImpossibleBoundaryMILPModel,
    WordwiseTruncatedMDSEspressoMILPModel,
    WordwiseTruncatedMDSMILPModel,
    WordwiseXorEspressoMILPModel,
    WordwiseXorMILPModel,
)
from claasp.semantics.cryptanalysis import (
    WordwiseDifferenceKind,
    WordwiseXorDifference,
    legacy_wordwise_impossible_fixture,
)


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


@pytest.mark.parametrize(
    "portable_type,espresso_type",
    (
        (WordwiseXorMILPModel, WordwiseXorEspressoMILPModel),
        (WordwiseTruncatedMDSMILPModel, WordwiseTruncatedMDSEspressoMILPModel),
    ),
)
def test_wordwise_espresso_relations_accept_exactly_the_portable_rows(portable_type, espresso_type):
    portable = (
        portable_type(4) if portable_type is WordwiseXorMILPModel else portable_type(4, (4, 4))
    )
    espresso = espresso_type()
    compact = espresso.milp_model()
    expected = set(portable.rows)
    accepted = {
        values
        for values in product((0, 1), repeat=len(espresso.columns))
        if compact.is_feasible(dict(zip(espresso.columns, values)))
    }
    assert accepted == expected


@pytest.mark.parametrize("model_type", (WordwiseXorMILPModel, WordwiseXorEspressoMILPModel))
def test_wordwise_xor_decodes_known_cancellation(model_type):
    relation = model_type(4) if model_type is WordwiseXorMILPModel else model_type()
    known = WordwiseXorDifference.known(4, 5)
    zero = WordwiseXorDifference(4, WordwiseDifferenceKind.ZERO)
    model = relation.milp_model(inputs=(known, known), output=zero)
    row = next(
        row for row in relation.rows if row[:6] == (0, 1, 0, 1, 0, 1) and row[6:12] == row[:6]
    )
    witness = (
        relation.relation.witness(row)
        if model_type is WordwiseXorMILPModel
        else dict(zip(relation.columns, row))
    )
    inputs, output = relation.decode_transition(witness)
    assert inputs == (known, known) and output == zero
    assert model.is_feasible(witness)


@pytest.mark.parametrize(
    "model_type", (WordwiseTruncatedMDSMILPModel, WordwiseTruncatedMDSEspressoMILPModel)
)
def test_wordwise_mds_decodes_single_active_input(model_type):
    relation = (
        model_type(4, (4, 4)) if model_type is WordwiseTruncatedMDSMILPModel else model_type()
    )
    zero = WordwiseXorDifference(4, WordwiseDifferenceKind.ZERO)
    nonzero = WordwiseXorDifference(4, WordwiseDifferenceKind.NONZERO)
    inputs, outputs = (nonzero, zero, zero, zero), (nonzero,) * 4
    model = relation.milp_model(inputs=inputs, outputs=outputs)
    row = next(
        row for row in relation.rows if row == (1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0)
    )
    witness = (
        relation.relation.witness(row)
        if model_type is WordwiseTruncatedMDSMILPModel
        else dict(zip(relation.columns, row))
    )
    assert relation.decode_transition(witness) == (inputs, outputs)
    assert model.is_feasible(witness)
