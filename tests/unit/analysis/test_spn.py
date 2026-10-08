import pytest

from claasp.analysis import TrailKind, TrailSearchBackend
from claasp.analysis.spn import check_spn_linear_trail, check_spn_trail
from claasp.primitives import Present, Speck


def test_two_round_present_finds_exact_optimum_and_checks_every_step():
    primitive = Present(number_of_rounds=2)

    result = primitive.analyze().find_lowest_weight_xor_differential_trail()

    assert result.trail.total_weight == 4.0
    assert result.lower_bound == 4.0
    assert result.is_optimal
    assert result.trail.input_pattern.value != 0
    assert check_spn_trail(primitive, result.trail)
    assert result.provenance == (
        "single-active-nibble enumeration with exact S-box DDT transitions"
    )
    assert len(result.component_transitions) == 37
    assert result.component_transitions[-1].component_id == "final_add_round_key"
    assert not any(item.component_id.startswith("key_") for item in result.component_transitions)


def test_find_trail_accepts_typed_and_string_kinds_with_explicit_backend_selection():
    differential = Present(number_of_rounds=2).analysis.find_trail(
        "xor_differential", backend=TrailSearchBackend.DEPENDENCY_FREE
    )
    linear = Present(number_of_rounds=3).analysis.find_trail(TrailKind.XOR_LINEAR)

    assert differential.trail.kind is TrailKind.XOR_DIFFERENTIAL
    assert differential.trail.total_weight == 4
    assert linear.trail.kind is TrailKind.XOR_LINEAR
    assert linear.trail.total_weight == 4


def test_find_trail_rejects_unsupported_advanced_combinations_explicitly():
    analysis = Present(number_of_rounds=2).analysis

    with pytest.raises(ValueError, match="unsupported trail kind"):
        analysis.find_trail("boomerang")
    with pytest.raises(ValueError, match="unsupported trail-search backend"):
        analysis.find_trail("xor_differential", backend="gurobi")
    with pytest.raises(NotImplementedError, match="SAT optimization"):
        analysis.find_trail("xor_differential", backend="sat")
    with pytest.raises(TypeError, match="does not accept a solver"):
        analysis.find_trail("xor_differential", backend="dependency_free", solver=object())


def test_analyze_remains_a_supported_compatibility_alias():
    primitive = Present(number_of_rounds=2)

    assert primitive.analyze().primitive is primitive
    assert primitive.analysis.primitive is primitive


def test_spn_search_rejects_unreviewed_graphs_explicitly():
    with pytest.raises(NotImplementedError, match="two-round Speck32/64"):
        Speck(number_of_rounds=3).analyze().find_lowest_weight_xor_differential_trail()


def test_three_round_present_reproduces_preserved_linear_weight_and_signs():
    primitive = Present(number_of_rounds=3)

    result = primitive.analyze().find_lowest_weight_xor_linear_trail()

    assert result.trail.total_weight == 4.0
    assert result.is_optimal
    assert result.trail.input_pattern.value != 0
    assert result.provenance == (
        "single-active-nibble enumeration with exact S-box LAT transitions"
    )
    assert any(step.transition.sign == -1 for step in result.trail.steps)
    assert check_spn_linear_trail(primitive, result.trail)
