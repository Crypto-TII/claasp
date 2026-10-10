import pytest

from claasp.primitives import Present, Simon, Speck


def test_public_deterministic_truncated_speck_propagates_every_round():
    primitive = Speck(number_of_rounds=3)

    result = primitive.analysis.propagate_truncated_xor_difference(
        "00000000011000000000000000000000"
    )

    assert result.primitive == "speck"
    assert result.independently_valid
    assert len(result.boundaries) == 4
    assert str(result.boundaries[-1]) == "???????????????0????????????????"


def test_public_deterministic_truncated_simon_propagates_every_round():
    result = Simon(number_of_rounds=3).analysis.propagate_truncated_xor_difference(
        "00000000000000000000000000000001"
    )

    assert len(result.boundaries) == 4
    assert all(len(boundary.bits) == 32 for boundary in result.boundaries)


def test_public_advanced_search_error_names_actual_primitive_and_capability():
    primitive = Present(number_of_rounds=2)

    with pytest.raises(
        NotImplementedError,
        match="present.*deterministic_truncated_xor.*three-valued",
    ):
        primitive.analysis.propagate_truncated_xor_difference("0" * 64)
    with pytest.raises(
        NotImplementedError,
        match="present.*impossible_xor_differential.*inverse",
    ):
        primitive.analysis.find_impossible_xor_differential(1)
