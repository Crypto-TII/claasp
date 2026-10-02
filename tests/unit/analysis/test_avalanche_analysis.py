import pytest

from claasp.analysis.avalanche import avalanche_probabilities
from claasp.primitives import Speck


def test_one_round_speck_avalanche_fixture_is_reproducible():
    primitive = Speck(number_of_rounds=1)
    result = avalanche_probabilities(primitive, "plaintext", 4, seed=9, fixed_inputs={"key": 0})

    assert result.input_bit_count == 32
    assert result.output_bit_count == 32
    assert result.probabilities[0] == (
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.5,
        1.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.5,
        1.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
    )
    assert result.complete is False
    assert result.method == "empirical_paired_evaluation"


def test_avalanche_summary_and_input_validation():
    primitive = Speck(number_of_rounds=1)
    result = avalanche_probabilities(primitive, "plaintext", 2, seed=0)

    assert result.mean_changed_output_bits[0] == sum(result.probabilities[0])
    assert 0 <= result.maximum_sac_bias <= 0.5
    with pytest.raises(KeyError, match="nonce"):
        avalanche_probabilities(primitive, "nonce", 1)


def test_primitive_analysis_facade_exposes_avalanche():
    result = (
        Speck(number_of_rounds=1)
        .analyze()
        .avalanche("plaintext", 2, seed=9, fixed_inputs={"key": 0})
    )
    assert result.sample_count == 2
    assert result.input_name == "plaintext"
