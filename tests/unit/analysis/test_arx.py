from io import StringIO

import pytest

from claasp.analysis._trail_propagation import xor_differential_component_transitions
from claasp.analysis.arx import check_speck_linear_trail, check_speck_trail
from claasp.primitives import Speck
from claasp.semantics.cryptanalysis import (
    ModularAddLinearSemantics,
    ModularAddTransitionSemantics,
    Trail,
    TrailKind,
    TrailStep,
    XorDifference,
)


def test_modular_add_transition_counts_are_exact():
    semantics = ModularAddTransitionSemantics(4)

    deterministic = semantics.xor_differential(0x8, 0, 0x8)
    impossible = semantics.xor_differential(0x8, 0, 0x1)
    assert (deterministic.numerator, deterministic.denominator, deterministic.weight) == (
        256,
        256,
        0.0,
    )
    assert not impossible.is_possible
    assert semantics.check(deterministic)


@pytest.mark.external
def test_two_round_speck_finds_exact_optimum_and_checks_wiring():
    primitive = Speck(number_of_rounds=2)

    result = primitive.analysis.find_optimal_trail(kind="xor_differential")

    assert result.trail.total_weight == 1.0
    assert result.lower_bound == 1.0
    assert result.is_optimal
    assert result.provenance == (
        "SAT optimization by binary search over the differential-weight bound"
    )
    assert result.metadata.solver == "Kissat"
    assert result.metadata.solver_version is not None
    assert result.metadata.runtime_seconds is not None
    assert result.metadata.runtime_seconds >= 0
    assert result.metadata.peak_memory_bytes is not None
    assert result.metadata.peak_memory_bytes > 0
    assert len(result.component_transitions) == 10
    assert [item.component for item in result.component_transitions] == [
        "rotate right 7",
        "modular addition",
        "XOR",
        "rotate left 2",
        "XOR",
    ] * 2
    assert {
        "constant_0_5",
        "rotate_0_6",
        "modular_add_0_7",
        "xor_0_8",
        "rotate_0_9",
        "xor_0_10",
    }.isdisjoint(item.component_id for item in result.component_transitions)
    assert check_speck_trail(primitive, result.trail)

    output = StringIO()
    result.show(file=output)
    rendered = output.getvalue()
    assert f"0x{result.trail.input_pattern.value:08x}" in rendered
    assert f"0x{result.trail.output_pattern.value:08x}" in rendered
    assert "Round trail" in rendered
    assert "Relative probability" in rendered
    assert "Cumulative probability" in rendered
    assert "Kissat" not in rendered
    assert "rotate_0_0" not in rendered

    output = StringIO()
    result.show(details=True, file=output)
    rendered = output.getvalue()
    assert "solver" in rendered and "Kissat" in rendered
    assert "runtime" in rendered and "peak memory" in rendered
    assert "rotate_0_0" in rendered
    assert "xor_1_4" in rendered
    assert "modular_add_0_1" in rendered
    assert "Graph locations are evidence references" not in rendered


def test_modular_add_linear_correlation_retains_exact_sign():
    transition = ModularAddLinearSemantics(16).xor_linear(0x0800, 0x0800, 0x0C00)

    assert (transition.numerator, transition.denominator, transition.weight) == (
        1 << 31,
        1 << 32,
        1.0,
    )
    assert transition.sign == -1


def test_related_key_component_propagation_retains_the_key_schedule():
    primitive = Speck(number_of_rounds=2)
    semantics = ModularAddTransitionSemantics(16)
    trail = Trail(
        TrailKind.XOR_DIFFERENTIAL,
        XorDifference(0, 32),
        XorDifference(0x02040200, 32),
        (
            TrailStep("modular_add_0_1", semantics.xor_differential(0, 0, 0)),
            TrailStep("modular_add_0_7", semantics.xor_differential(0, 1, 1)),
            TrailStep(
                "modular_add_1_1",
                semantics.xor_differential(0x0200, 1, 0x0201),
            ),
        ),
    )

    components = xor_differential_component_transitions(
        primitive,
        trail,
        input_differences={"plaintext": 0, "key": 1},
    )

    assert len(components) == 16
    assert "modular_add_0_7" in {item.component_id for item in components}


def test_four_round_speck_returns_verified_linear_optimum():
    primitive = Speck(number_of_rounds=4)

    result = primitive.analysis.find_lowest_weight_xor_linear_trail()

    assert result.trail.total_weight == 3.0
    assert result.is_optimal
    assert result.trail.input_pattern.value == 0x40B010C1
    assert result.trail.output_pattern.value == 0x2C102010
    assert result.provenance == (
        "fixed-trail verification with exact modular-addition correlations"
    )
    assert check_speck_linear_trail(primitive, result.trail)


def test_dependency_free_speck_search_uses_exact_matsui_branch_and_bound():
    primitive = Speck(number_of_rounds=2)

    result = primitive.analysis.find_optimal_trail("xor_differential", backend="dependency_free")

    assert result.trail.total_weight == result.lower_bound == 1
    assert result.is_optimal
    assert "Matsui branch-and-bound" in result.metadata.technique
    assert result.metadata.solver is None
    assert [item.output_pattern.value for item in result.round_transitions] == [
        0x80008000,
        result.trail.output_pattern.value,
    ]
    assert [(item.numerator, item.denominator) for item in result.round_transitions] == [
        (1, 1),
        (1, 2),
    ]
    assert check_speck_trail(primitive, result.trail)
