"""External-solver regressions for the generic optimal-trail facade."""

from io import StringIO

import pytest

from claasp.drivers.solvers import MinisatSolver
from claasp.primitives import AES, CHAM, Ascon, ChaCha, Present, Simeck, Simon, Speck
from claasp.primitives.single_component_primitives import (
    BitwiseNot,
    BitwiseOr,
    ModularSubtract,
    Permutation,
    Shift,
)
from claasp.semantics.cryptanalysis import TrailKind

pytestmark = pytest.mark.external


@pytest.mark.parametrize("primitive_type", (Simon, Simeck))
def test_three_round_andrx_optima_and_reporting(primitive_type):
    primitive = primitive_type(number_of_rounds=3)
    differential = primitive.analysis.find_optimal_trail()
    linear = primitive.analysis.find_optimal_trail(kind="xor_linear")

    assert differential.trail.kind is TrailKind.XOR_DIFFERENTIAL
    assert differential.trail.total_weight == differential.lower_bound == 4
    assert linear.trail.total_weight == linear.lower_bound == 2
    assert len(differential.round_transitions) == 3
    assert len(linear.round_transitions) == 3
    assert differential.constraint_models
    assert linear.constraint_models

    summary, details = StringIO(), StringIO()
    differential.show(file=summary)
    differential.show(details=True, file=details)
    assert "round 3" in summary.getvalue()
    assert "BitwiseAnd" in details.getvalue()


def test_typed_kind_custom_solver_and_input_policy_overrides():
    primitive = Simon(number_of_rounds=3)
    linear = primitive.analysis.find_optimal_trail(
        TrailKind.XOR_LINEAR,
        backend="sat",
        solver=MinisatSolver(),
        nonzero_input="plaintext",
        fixed_inputs={"key": 0},
    )
    differential = primitive.analysis.find_optimal_trail(
        TrailKind.XOR_DIFFERENTIAL,
        backend="sat",
        solver=MinisatSolver(),
        nonzero_input="plaintext",
        fixed_input_differences={"key": 0},
    )
    assert linear.trail.total_weight == 2
    assert differential.trail.total_weight == 4
    assert linear.metadata.solver == differential.metadata.solver == "MinisatSolver"


def test_other_modadd_family_and_state_input_permutation():
    cham = CHAM(number_of_rounds=1).analysis.find_optimal_trail(backend="sat")
    chacha = ChaCha(number_of_rounds=1).analysis.find_optimal_trail(backend="sat")
    assert cham.is_optimal and chacha.is_optimal
    assert chacha.trail.input_pattern.width == 512


def test_bit_and_binary_field_catalogue_regressions():
    ascon_differential = Ascon(number_of_rounds=1).analysis.find_optimal_trail(backend="sat")
    ascon_linear = Ascon(number_of_rounds=1).analysis.find_optimal_trail(
        kind="xor_linear", backend="sat"
    )
    aes = AES(number_of_rounds=1).analysis.find_optimal_trail(backend="sat")

    assert ascon_differential.trail.total_weight == 2
    assert ascon_linear.trail.total_weight == 1
    assert aes.trail.total_weight == aes.lower_bound == 6
    assert all(result.is_optimal for result in (ascon_differential, ascon_linear, aes))


def test_specialized_results_remain_available():
    assert Present(number_of_rounds=2).analysis.find_optimal_trail().trail.total_weight == 4
    assert (
        Speck(number_of_rounds=2)
        .analysis.find_optimal_trail(backend="dependency_free")
        .trail.total_weight
        == 1
    )


@pytest.mark.parametrize(
    "primitive",
    (Shift(), ModularSubtract(), Permutation(word_size=4), BitwiseNot(), BitwiseOr()),
)
@pytest.mark.parametrize("kind", tuple(TrailKind))
def test_recovered_basic_word_component_semantics(primitive, kind):
    active = next(iter(primitive.input_ports))
    fixed = {name: 0 for name in primitive.input_ports if name != active}
    options = (
        {"fixed_input_differences": fixed}
        if kind is TrailKind.XOR_DIFFERENTIAL
        else {"fixed_inputs": fixed}
    )
    result = primitive.analysis.find_optimal_trail(
        kind,
        backend="sat",
        nonzero_input=active,
        **options,
    )
    assert result.is_optimal
