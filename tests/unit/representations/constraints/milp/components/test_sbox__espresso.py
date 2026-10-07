"""Recovered large-S-box Espresso strategy parity."""

import pytest

from claasp.composites.aes import AES_SBOX
from claasp.representations.constraints import ConstraintReferenceStatus
from claasp.representations.constraints.milp import (
    SBoxMILPInequalityStrategy,
    SBoxXorDifferentialEspressoMILPModel,
    SBoxXorLinearEspressoMILPModel,
    load_bundled_sbox_milp_inequalities,
)
from claasp.semantics.cryptanalysis import SBoxTransitionSemantics, TrailKind


@pytest.fixture(scope="module")
def differential():
    system = load_bundled_sbox_milp_inequalities(
        "aes", TrailKind.XOR_DIFFERENTIAL, SBoxMILPInequalityStrategy.ESPRESSO
    )
    return SBoxXorDifferentialEspressoMILPModel(system)


@pytest.fixture(scope="module")
def linear():
    system = load_bundled_sbox_milp_inequalities(
        "aes", TrailKind.XOR_LINEAR, SBoxMILPInequalityStrategy.ESPRESSO
    )
    return SBoxXorLinearEspressoMILPModel(system)


def test_espresso_bundle_is_exact_for_every_aes_pair(differential, linear):
    semantics = SBoxTransitionSemantics(AES_SBOX)
    assert differential.system.table == AES_SBOX
    assert linear.system.table == AES_SBOX
    assert differential.inequality_count == 8661
    assert linear.inequality_count == 38472
    assert {group.transition_count for group in differential.system.groups} == {2, 4}
    assert {group.transition_count for group in linear.system.groups} == {
        -32,
        -28,
        -24,
        -20,
        -16,
        -12,
        -8,
        -4,
        4,
        8,
        12,
        16,
        20,
        24,
        28,
        32,
    }
    ddt = semantics.difference_distribution_table()
    walsh = semantics.walsh_correlation_table()
    differential_counts = {
        count: sum(value == count for row in ddt for value in row) for count in (2, 4)
    }
    linear_counts = {
        count: sum(value == count for row in walsh for value in row)
        for count in {group.transition_count for group in linear.system.groups}
    }
    assert differential_counts == {2: 32130, 4: 255}
    assert linear_counts == {
        -32: 640,
        -28: 2040,
        -24: 4592,
        -20: 3064,
        -16: 4334,
        -12: 5096,
        -8: 4592,
        -4: 6112,
        4: 6128,
        8: 4588,
        12: 5104,
        16: 4336,
        20: 3056,
        24: 4588,
        28: 2040,
        32: 635,
    }


@pytest.mark.parametrize(
    "fixture_name,source,target,numerator,sign",
    [
        ("differential", 1, 31, 4, 1),
        ("differential", 1, 1, 2, 1),
        ("linear", 1, 72, 32, -1),
        ("linear", 1, 1, 24, 1),
    ],
)
def test_espresso_models_build_educational_witnesses(
    request, fixture_name, source, target, numerator, sign
):
    relation = request.getfixturevalue(fixture_name)
    model = relation.milp_model(input_pattern=source, output_pattern=target)
    transition = relation.decode_transition(relation.witness(source, target))
    assert model.is_feasible(relation.witness(source, target))
    assert (transition.numerator, transition.sign) == (numerator, sign)


def test_espresso_models_reject_impossible_transitions(differential, linear):
    with pytest.raises(ValueError, match="impossible"):
        differential.witness(1, 0)
    with pytest.raises(ValueError, match="impossible"):
        linear.witness(1, 0)


def test_espresso_provenance_remains_explicitly_unaudited(differential, linear):
    assert (
        differential.model_provenance.reference_status is ConstraintReferenceStatus.TO_BE_DETERMINED
    )
    assert linear.model_provenance.reference_status is ConstraintReferenceStatus.TO_BE_DETERMINED
    assert "3aacc275" in (differential.model_provenance.rationale or "")
