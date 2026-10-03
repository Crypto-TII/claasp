from claasp.primitives import AES, Present, Speck
from claasp.semantics.cryptanalysis import (
    ImpossiblePropagationBoundary,
    ProbabilisticTruncatedModularAddTransition,
    ProbabilisticTruncatedTrail,
    TruncatedXorDifference,
    WordwiseDifferenceKind,
    WordwiseXorDifference,
    check_probabilistic_truncated_modular_add,
    legacy_wordwise_impossible_fixture,
    propagate_single_active_aes_byte,
    propagate_two_word_simon_inverse_round,
    propagate_two_word_simon_round,
    propagate_two_word_speck_inverse_round,
    propagate_two_word_speck_round,
    truncated_modular_add,
)


def test_truncated_modular_add_preserves_only_universal_output_bits():
    left = TruncatedXorDifference.parse("1000")
    right = TruncatedXorDifference.parse("0000")
    assert str(truncated_modular_add(left, right)) == "1000"

    varied = truncated_modular_add(
        TruncatedXorDifference.parse("0001"),
        TruncatedXorDifference.parse("0001"),
    )
    assert str(varied).endswith("0")


def test_speck_truncated_round_reproduces_legacy_sat_fixture():
    primitive = Speck(number_of_rounds=2)
    input_difference = TruncatedXorDifference.parse("00000000011111001110000000000000")

    output = propagate_two_word_speck_round(primitive, input_difference)

    assert str(output) == "????100000000000????100000000011"


def test_speck_three_round_truncated_output_reproduces_legacy_sat_fixture():
    primitive = Speck(number_of_rounds=3)
    difference = TruncatedXorDifference.parse("00000000011000000000000000000000")
    for round_number in range(3):
        difference = propagate_two_word_speck_round(primitive, difference, round_number)

    assert str(difference) == "???????????????0????????????????"


def test_speck_mixed_exact_truncated_sat_boundaries_are_preserved():
    start = "00000000011000000000000000000000"
    expected = {
        4: "????????10000000????????100000?1",
        5: "???????????????0????????????????",
    }
    for rounds, output in expected.items():
        primitive = Speck(number_of_rounds=rounds)
        difference = TruncatedXorDifference.parse(start)
        for round_number in range(2, rounds):
            difference = propagate_two_word_speck_round(primitive, difference, round_number)
        assert str(difference) == output


def test_graph_level_impossible_sbox_transition_is_exhaustively_refuted():
    primitive = Present(number_of_rounds=1)

    assert not primitive.analyze().is_xor_differential_transition_possible("sbox_1_0", 0x1, 0x1)
    assert primitive.analyze().is_xor_differential_transition_possible("sbox_1_0", 0x1, 0x3)


def test_probabilistic_truncated_transition_rejects_an_invalid_carry_boundary():
    transition = ProbabilisticTruncatedModularAddTransition(
        TruncatedXorDifference.parse("0000"),
        TruncatedXorDifference.parse("0000"),
        TruncatedXorDifference.parse("000?"),
        TruncatedXorDifference.parse("000?"),
        (0, 0, 0, 0),
    )

    assert transition.weight == 0
    assert not check_probabilistic_truncated_modular_add(transition)


def test_probabilistic_truncated_trail_sums_exact_scaled_costs():
    zero = TruncatedXorDifference.parse("0000")
    transition = ProbabilisticTruncatedModularAddTransition(
        zero,
        zero,
        zero,
        zero,
        (41, 19, 0, 0),
    )
    trail = ProbabilisticTruncatedTrail(zero, zero, (transition, transition))

    assert trail.scaled_weight == 120
    assert trail.weight == 1.2


def test_wordwise_difference_preserves_values_and_sound_activity():
    zero = WordwiseXorDifference(8, WordwiseDifferenceKind.ZERO)
    known = WordwiseXorDifference.known(8, 0x53)

    assert zero.xor(known) == known
    assert known.xor(known).kind is WordwiseDifferenceKind.ZERO
    assert known.through_bijection() == WordwiseXorDifference(8, WordwiseDifferenceKind.NONZERO)
    assert (
        WordwiseXorDifference(8, WordwiseDifferenceKind.UNKNOWN).through_bijection().kind
        is WordwiseDifferenceKind.UNKNOWN
    )


def test_wordwise_aes_single_byte_diffuses_to_one_column():
    output = propagate_single_active_aes_byte(AES(number_of_rounds=1), 0)

    assert tuple(word.kind for word in output[:4]) == (WordwiseDifferenceKind.NONZERO,) * 4
    assert all(word.kind is WordwiseDifferenceKind.ZERO for word in output[4:])


def test_legacy_wordwise_impossible_fixture_preserves_every_fixed_boundary():
    fixture = legacy_wordwise_impossible_fixture()

    assert fixture.input_pattern == "1003000000000000"
    assert fixture.key_pattern == "0000000000000000"
    assert fixture.output_pattern == "1000000000000000"
    assert fixture.forward_middle == "2222333300000000"
    assert fixture.backward_middle == "2000000000000000"
    assert fixture.claim_kind == "abstract-incompatibility-witness"


def test_inverse_speck_truncated_propagation_preserves_zero_difference():
    primitive = Speck(number_of_rounds=2)
    zero = TruncatedXorDifference.parse("0" * 32)

    assert propagate_two_word_speck_inverse_round(primitive, zero, 1) == zero


def test_impossible_boundary_reports_only_fixed_contradictions():
    boundary = ImpossiblePropagationBoundary(
        TruncatedXorDifference.parse("01??0"),
        TruncatedXorDifference.parse("00?11"),
    )

    assert boundary.contradictory_positions == (1, 4)
    assert boundary.is_impossible


def test_simon_truncated_propagation_preserves_legacy_middle_patterns():
    forward = TruncatedXorDifference.parse("0" * 31 + "1")
    backward = TruncatedXorDifference.parse("000000?0?" + "0" * 23)

    for _ in range(6):
        forward = propagate_two_word_simon_round(forward)
    for _ in range(5):
        backward = propagate_two_word_simon_inverse_round(backward)

    assert str(forward).replace("?", "2") == "22222222222222220222222122222202"
    assert str(backward).replace("?", "2") == "22222222002222202222222022222222"
    assert ImpossiblePropagationBoundary(forward, backward).contradictory_positions == (23,)
