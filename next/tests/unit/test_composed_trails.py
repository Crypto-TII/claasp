from math import isclose, log2

import pytest

from claasp_next.analysis import (
    check_speck32_differential_linear_fixture,
    run_chacha_differential_linear_experiment,
    run_speck32_boomerang_experiment,
    run_speck32_differential_linear_experiment,
    speck32_differential_linear_legacy_fixture,
)
from claasp_next.primitives import Present
from claasp_next.semantics.cryptanalysis import (
    BoomerangSwitchBoundary,
    BoomerangTrail,
    DifferentialLinearTrail,
    ModularAddBoomerangAutomaton,
    ModularAddBoomerangSemantics,
    ProbabilisticTruncatedTrail,
    SBoxBoomerangSemantics,
    Trail,
    TrailKind,
    TruncatedXorDifference,
    XorDifference,
    XorMask,
)


def _trail(kind, source, target, width=4):
    pattern = XorDifference if kind is TrailKind.XOR_DIFFERENTIAL else XorMask
    return Trail(kind, pattern(source, width), pattern(target, width), ())


def test_boomerang_composition_checks_typed_boundaries_and_weight():
    upper = _trail(TrailKind.XOR_DIFFERENTIAL, 1, 2)
    lower = _trail(TrailKind.XOR_DIFFERENTIAL, 4, 8)
    switch = BoomerangSwitchBoundary(
        XorDifference(2, 4),
        XorDifference(3, 4),
        XorDifference(5, 4),
        XorDifference(4, 4),
        1.5,
    )

    assert BoomerangTrail(upper, switch, lower).total_weight == 1.5
    with pytest.raises(ValueError, match="upper trail"):
        BoomerangTrail(_trail(TrailKind.XOR_DIFFERENTIAL, 1, 3), switch, lower)


def test_differential_linear_composition_uses_exact_legacy_formula():
    connector = ProbabilisticTruncatedTrail(
        TruncatedXorDifference.parse("0000"),
        TruncatedXorDifference.parse("????"),
        (),
    )
    composed = DifferentialLinearTrail(
        _trail(TrailKind.XOR_DIFFERENTIAL, 1, 2),
        connector,
        _trail(TrailKind.XOR_LINEAR, 4, 8),
    )

    assert isclose(composed.total_weight, 0.0)
    with pytest.raises(TypeError, match="prefix"):
        DifferentialLinearTrail(
            _trail(TrailKind.XOR_LINEAR, 1, 2), connector, _trail(TrailKind.XOR_LINEAR, 4, 8)
        )


def test_present_boomerang_connectivity_is_counted_exhaustively():
    primitive = Present(number_of_rounds=1)
    component = next(item for item in primitive.components if item.component_id == "sbox_1_0")
    semantics = SBoxBoomerangSemantics(component.table)

    possible = semantics.connectivity(1, 2)
    impossible = semantics.connectivity(1, 1)

    assert possible.count == 4
    assert possible.weight == 2
    assert impossible.count == 0
    assert not impossible.is_possible


def test_boomerang_connectivity_rejects_non_bijections():
    with pytest.raises(ValueError, match="bijective"):
        SBoxBoomerangSemantics((0, 0, 1, 2))


def test_modular_add_boomerang_oracle_counts_full_quartets():
    semantics = ModularAddBoomerangSemantics(4)

    certain = semantics.connectivity(0, 0, 0, 0)
    half = semantics.connectivity(1, 0, 1, 0)
    impossible = semantics.connectivity(3, 5, 7, 9)

    assert (certain.count, certain.weight) == (256, 0)
    assert (half.count, half.weight) == (128, 1)
    assert not impossible.is_possible


def test_modular_add_boomerang_oracle_rejects_unreviewable_widths():
    with pytest.raises(ValueError, match="widths 1 through 8"):
        ModularAddBoomerangSemantics(16)


def test_modular_add_automaton_matches_every_three_bit_exhaustive_entry():
    exhaustive = ModularAddBoomerangSemantics(3)
    automaton = ModularAddBoomerangAutomaton(3)

    for delta_left in range(8):
        for delta_right in range(8):
            for nabla_output in range(8):
                for nabla_right in range(8):
                    values = (delta_left, delta_right, nabla_output, nabla_right)
                    assert (
                        automaton.connectivity(*values).count
                        == exhaustive.connectivity(*values).count
                    )


def test_modular_add_automaton_scales_to_speck_words():
    entry = ModularAddBoomerangAutomaton(16).connectivity(1, 0, 1, 0)

    assert entry.count == 1 << 31
    assert entry.weight == 1


def test_legacy_restricted_speck_switch_is_checked_by_exact_automaton():
    # Fixed by reproducing the legacy MiniZinc/Chuffed model. The old
    # onlyLargeSwitch predicate accepted this entry but did not assign a
    # switch weight; v5 counts all exact quartets independently.
    entry = ModularAddBoomerangAutomaton(16).connectivity(0x0100, 0x840A, 0x0040, 0x0010)

    assert entry.count == 2_818_572_288
    assert isclose(entry.weight, 0.6076825772212398)


def test_legacy_speck_boomerang_empirical_fixture_is_seeded_and_fixed():
    result = run_speck32_boomerang_experiment(
        0x28000010, 0x8000840A, rounds=8, samples=1 << 16, seed=0xC1AA5
    )

    assert result.successes == 11
    assert result.rate == 11 / (1 << 16)
    assert result.rate > 0.0001


def test_fixed_speck_differential_linear_fixture_separates_search_and_exact_weights():
    fixture = speck32_differential_linear_legacy_fixture()

    assert check_speck32_differential_linear_fixture(fixture)
    assert fixture.trail.differential.total_weight == 1
    assert fixture.trail.connector.weight == 7
    assert fixture.trail.linear.total_weight == 3
    assert fixture.legacy_search_weight == 14
    assert isclose(fixture.exact_weight, 14.994353436858859)


@pytest.mark.parametrize(
    "input_difference,output_mask,rounds,samples,maximum_weight,even_parities",
    (
        (
            int(
                "8000000080000000000000000000000080000000000000000000000000000000"
                "8080000080000000000000000000000000000080800080000000000000000000",
                16,
            ),
            int(
                "0000000100000000000000010000000004000000000800800000000000000000"
                "000000010008008000001000000000000000000000000101000000c000000001",
                16,
            ),
            4,
            8192,
            4,
            4528,
        ),
        (
            int(
                "0000000000000000000000000000000000000000000000000000000000000000"
                "0000000000000000000000000000000000000008000000000000000000000000",
                16,
            ),
            int(
                "0001000000010001000000010003000300000080000000800000000000000180"
                "0000000000000001000000010000000201000101010000000000010103000101",
                16,
            ),
            3,
            8192,
            3,
            5204,
        ),
        (
            int(
                "0000000000000000000000000000000000000000000000000000000000000000"
                "0000000000000000000000000000000000000000000000000000000040000000",
                16,
            ),
            int(
                "0000000100000000000000010101018100008080000000000000000000080080"
                "0000100000000101000000010000000000000000000000010100000100000101",
                16,
            ),
            4,
            1024,
            8,
            618,
        ),
    ),
)
def test_fixed_chacha_differential_linear_pairs_remain_seeded_empirical_evidence(
    input_difference, output_mask, rounds, samples, maximum_weight, even_parities
):
    result = run_chacha_differential_linear_experiment(
        input_difference, output_mask, rounds=rounds, samples=samples, seed=42
    )

    assert result.even_parities == even_parities
    assert -log2(abs(result.correlation)) < maximum_weight
    assert result.claim_kind == "empirical"


def test_fixed_speck_differential_linear_pair_remains_seeded_empirical_evidence():
    result = run_speck32_differential_linear_experiment(
        0x02110A04, 0x02000201, rounds=6, samples=1 << 15, seed=42
    )

    assert result.even_parities == 16589
    assert -log2(abs(result.correlation)) <= 8
    assert result.claim_kind == "empirical"
