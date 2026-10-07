"""Recovered small-S-box convex-hull strategy parity."""

from typing import Any, cast

import pytest

from claasp.representations.constraints import ConstraintReferenceStatus
from claasp.representations.constraints.milp import (
    SBoxMILPInequalityGroup,
    SBoxMILPInequalityStrategy,
    SBoxMILPInequalitySystem,
    SBoxXorDifferentialConvexHullMILPModel,
    SBoxXorDifferentialGreedyMILPModel,
    SBoxXorDifferentialMinimumMILPModel,
    SBoxXorLinearConvexHullMILPModel,
    SBoxXorLinearGreedyMILPModel,
    SBoxXorLinearMinimumMILPModel,
    load_bundled_sbox_milp_inequalities,
)
from claasp.semantics.cryptanalysis import TrailKind

CASES = (
    (
        TrailKind.XOR_DIFFERENTIAL,
        SBoxMILPInequalityStrategy.CONVEX_HULL,
        SBoxXorDifferentialConvexHullMILPModel,
        498,
    ),
    (
        TrailKind.XOR_DIFFERENTIAL,
        SBoxMILPInequalityStrategy.GREEDY,
        SBoxXorDifferentialGreedyMILPModel,
        30,
    ),
    (
        TrailKind.XOR_DIFFERENTIAL,
        SBoxMILPInequalityStrategy.MINIMUM,
        SBoxXorDifferentialMinimumMILPModel,
        25,
    ),
    (
        TrailKind.XOR_LINEAR,
        SBoxMILPInequalityStrategy.CONVEX_HULL,
        SBoxXorLinearConvexHullMILPModel,
        1057,
    ),
    (
        TrailKind.XOR_LINEAR,
        SBoxMILPInequalityStrategy.GREEDY,
        SBoxXorLinearGreedyMILPModel,
        47,
    ),
    (
        TrailKind.XOR_LINEAR,
        SBoxMILPInequalityStrategy.MINIMUM,
        SBoxXorLinearMinimumMILPModel,
        39,
    ),
)


@pytest.mark.parametrize(("kind", "strategy", "model_type", "inequality_count"), CASES)
def test_every_present_transition_matches_exact_semantics(
    kind, strategy, model_type, inequality_count
):
    system = load_bundled_sbox_milp_inequalities("present", kind, strategy)
    relation = model_type(system)
    model = relation.milp_model()
    assert relation.inequality_count == inequality_count
    assert relation.model_provenance.reference_status is ConstraintReferenceStatus.TO_BE_DETERMINED
    for source in range(16):
        for target in range(16):
            transition = relation._transition(source, target)
            if transition.is_possible:
                witness = relation.witness(source, target)
                assert model.is_feasible(witness)
                decoded = relation.decode_transition(witness)
                assert decoded == transition
                assert model.objective_value(witness) == transition.weight
            else:
                with pytest.raises(ValueError, match="impossible"):
                    relation.witness(source, target)


@pytest.mark.parametrize(("kind", "strategy", "model_type", "_"), CASES)
def test_fixed_patterns_reject_another_transition(kind, strategy, model_type, _):
    system = load_bundled_sbox_milp_inequalities("present", kind, strategy)
    relation = model_type(system)
    supported = next(
        (source, target)
        for source in range(1, 16)
        for target in range(16)
        if relation._transition(source, target).is_possible
    )
    other = next(
        (source, target)
        for source in range(1, 16)
        for target in range(16)
        if relation._transition(source, target).is_possible and (source, target) != supported
    )
    model = relation.milp_model(input_pattern=supported[0], output_pattern=supported[1])
    assert model.is_feasible(relation.witness(*supported))
    assert not model.is_feasible(relation.witness(*other))


def test_loader_and_system_validation_fail_explicitly():
    with pytest.raises(ValueError, match="no bundled"):
        load_bundled_sbox_milp_inequalities(
            "missing", TrailKind.XOR_DIFFERENTIAL, SBoxMILPInequalityStrategy.GREEDY
        )
    with pytest.raises(TypeError, match="strategy"):
        load_bundled_sbox_milp_inequalities(
            "present", TrailKind.XOR_DIFFERENTIAL, cast(Any, "greedy")
        )
    with pytest.raises(ValueError, match="disagree"):
        SBoxMILPInequalitySystem(
            "invalid",
            (0, 1),
            TrailKind.XOR_DIFFERENTIAL,
            SBoxMILPInequalityStrategy.GREEDY,
            (SBoxMILPInequalityGroup(1, ((-1, 1, 1),)),),
            "commit",
            "path",
        )


def test_model_rejects_a_system_for_another_strategy_or_kind():
    differential = load_bundled_sbox_milp_inequalities(
        "present", TrailKind.XOR_DIFFERENTIAL, SBoxMILPInequalityStrategy.GREEDY
    )
    linear = load_bundled_sbox_milp_inequalities(
        "present", TrailKind.XOR_LINEAR, SBoxMILPInequalityStrategy.CONVEX_HULL
    )
    with pytest.raises(ValueError, match="minimum"):
        SBoxXorDifferentialMinimumMILPModel(differential)
    with pytest.raises(ValueError, match="xor_differential"):
        SBoxXorDifferentialConvexHullMILPModel(linear)
