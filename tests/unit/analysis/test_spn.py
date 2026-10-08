from claasp.analysis.spn import check_spn_linear_trail, check_spn_trail
from claasp.primitives import Present, Speck


def test_two_round_present_reproduces_legacy_optimum_and_checks_every_step():
    primitive = Present(number_of_rounds=2)

    result = primitive.analyze().find_lowest_weight_xor_differential_trail()

    assert result.trail.total_weight == 4.0
    assert result.lower_bound == 4.0
    assert result.is_optimal
    assert result.trail.input_pattern.value != 0
    assert check_spn_trail(primitive, result.trail)
    assert "legacy CLAASP" in result.provenance


def test_non_present_word_graph_is_not_dispatched_to_the_spn_validator():
    from claasp.analysis.trail_search import require_word_sat_capability
    from claasp.semantics.cryptanalysis import TrailKind

    require_word_sat_capability(Speck(number_of_rounds=3), TrailKind.XOR_DIFFERENTIAL)


def test_three_round_present_reproduces_preserved_linear_weight_and_signs():
    primitive = Present(number_of_rounds=3)

    result = primitive.analyze().find_lowest_weight_xor_linear_trail()

    assert result.trail.total_weight == 4.0
    assert result.is_optimal
    assert result.trail.input_pattern.value != 0
    assert any(step.transition.sign == -1 for step in result.trail.steps)
    assert check_spn_linear_trail(primitive, result.trail)
