"""Capability and dispatch contracts that do not execute an external solver."""

import pytest

from claasp.analysis.facade import TrailSearchBackend
from claasp.analysis.trail_search import require_word_sat_capability
from claasp.primitives import (
    AES,
    CHAM,
    SPARX,
    Ascon,
    ChaChaPermutation,
    Present,
    SalsaPermutation,
    Simeck,
    Simon,
    Speck,
    Threefish,
    VariableShift,
)
from claasp.representations.constraints.sat import WordDifferentialSATModel, WordLinearSATModel
from claasp.semantics.cryptanalysis import TrailKind


@pytest.mark.parametrize(
    "primitive",
    (
        Simon(number_of_rounds=1),
        Simeck(number_of_rounds=1),
        CHAM(number_of_rounds=1),
        Speck(number_of_rounds=1),
        SPARX(number_of_rounds=1),
        Threefish(number_of_rounds=1),
        ChaChaPermutation(number_of_rounds=1),
        SalsaPermutation(number_of_rounds=1),
    ),
)
@pytest.mark.parametrize("kind", tuple(TrailKind))
def test_confirmed_word_catalogue_graphs_construct_for_both_kinds(primitive, kind):
    require_word_sat_capability(primitive, kind)
    model = (
        WordDifferentialSATModel(primitive)
        if kind is TrailKind.XOR_DIFFERENTIAL
        else WordLinearSATModel(primitive, maximum_weight=None)
    )
    assert model.cnf_formula().variable_count


def test_bit_and_binary_field_graphs_construct_exact_differential_models():
    for primitive in (Ascon(number_of_rounds=1), AES(number_of_rounds=1)):
        require_word_sat_capability(primitive, TrailKind.XOR_DIFFERENTIAL)
        assert WordDifferentialSATModel(primitive).cnf_formula().variable_count


def test_unsupported_error_names_actual_primitive_kind_backend_and_component():
    with pytest.raises(NotImplementedError) as error:
        VariableShift().analysis.find_optimal_trail(backend="sat")
    message = str(error.value)
    assert "variable_shift" in message
    assert "xor_differential" in message
    assert "backend 'sat'" in message
    assert "VariableShift" in message
    assert "present" not in message.lower()
    assert "speck" not in message.lower()

    with pytest.raises(NotImplementedError, match="backend 'smt'.*VariableShift"):
        VariableShift().analysis.find_optimal_trail(kind="xor_linear", backend="smt")


def test_dependency_free_never_falls_back_to_an_unrelated_validator():
    with pytest.raises(NotImplementedError, match="simon.*xor_differential.*dependency_free"):
        Simon(number_of_rounds=3).analysis.find_optimal_trail(backend="dependency_free")


def test_public_enums_and_default_kind_are_exposed():
    assert {item.value for item in TrailSearchBackend} == {
        "auto",
        "sat",
        "smt",
        "milp",
        "cp",
        "dependency_free",
    }
    assert (
        Present(number_of_rounds=2)
        .analysis.find_optimal_trail(backend="dependency_free")
        .trail.kind
        is TrailKind.XOR_DIFFERENTIAL
    )


@pytest.mark.parametrize("kind", tuple(TrailKind))
def test_fractional_sbox_capability_builds_both_exact_graph_relations(kind):
    from claasp.primitives import Heys

    primitive = Heys(number_of_rounds=1)
    require_word_sat_capability(primitive, kind)
    model = (
        WordDifferentialSATModel(primitive)
        if kind is TrailKind.XOR_DIFFERENTIAL
        else WordLinearSATModel(primitive, maximum_weight=None)
    )
    formula = model.cnf_formula()
    assert "exact_lookup_numerator" in formula.provenance
    assert model._shared._probability_denominator > 1


def test_fractional_optimizer_does_not_turn_unknown_into_an_optimal_result():
    from claasp.drivers.solvers import CPResult, CPStatus
    from claasp.primitives import Heys

    class Solver:
        def solve(self, formula):
            return CPResult(CPStatus.UNKNOWN, None, 0, "test", "", "")

    with pytest.raises(RuntimeError, match="did not complete exact probability"):
        Heys(number_of_rounds=1).analysis.find_optimal_trail(kind="xor_linear", solver=Solver())


def test_fractional_optimizer_rejects_a_solver_witness_outside_its_bound():
    from claasp.drivers.solvers import SatResult, SatStatus
    from claasp.primitives import Heys

    class Solver:
        def solve(self, formula):
            return SatResult(SatStatus.SATISFIABLE, dict.fromkeys(formula.variables, 0), 0, "", "")

    with pytest.raises(RuntimeError, match="invalid probability-bound witness"):
        Heys(number_of_rounds=1).analysis.find_optimal_trail(kind="xor_linear", solver=Solver())


def test_active_input_may_be_fixed_to_a_nonzero_mask_or_difference():
    from claasp.analysis.trail_search import resolve_input_policy
    from claasp.primitives import Heys

    primitive = Heys(number_of_rounds=1)
    for single_key in (False, True):
        policy = resolve_input_policy(
            primitive,
            "plaintext",
            {"plaintext": 1},
            add_key_tweak_defaults=single_key,
        )
        assert policy.fixed_patterns["plaintext"] == 1
        assert policy.nonzero_input == "plaintext"
        with pytest.raises(ValueError, match="cannot be fixed to zero"):
            resolve_input_policy(primitive, "plaintext", {"plaintext": 0})


def test_fractional_support_preserves_the_dense_walsh_table_capability_limit():
    from claasp.primitives import BitVectorSBox

    primitive = BitVectorSBox(11, tuple(range(2048)))
    with pytest.raises(NotImplementedError, match="dense Walsh-table materialization"):
        primitive.analysis.find_optimal_trail(kind="xor_linear")
