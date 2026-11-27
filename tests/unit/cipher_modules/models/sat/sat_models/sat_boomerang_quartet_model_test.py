"""Independent small-domain checks for four-execution boomerang counting."""

import pytest

from claasp.cipher import Cipher
from claasp.cipher_modules.models.candidate_validation import validate_boomerang_trail
from claasp.cipher_modules.models.cp.mzn_models.mzn_hadipour_boomerang_model import (
    MznHadipourBoomerangModel,
)
from claasp.cipher_modules.models.sat.sat_models.sat_boomerang_quartet_model import (
    SatBoomerangQuartetModel,
)


def _sbox_example():
    cipher = Cipher("two_sboxes", "permutation", ["plaintext"], [4], 4)
    table = [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2]
    cipher.add_round()
    first = cipher.add_sbox_component(["plaintext"], [list(range(4))], 4, table)
    cipher.add_round_output_component([first.id], [list(range(4))], 4)
    cipher.add_round()
    second = cipher.add_sbox_component([first.id], [list(range(4))], 4, table)
    cipher.add_cipher_output_component([second.id], [list(range(4))], 4)
    trail = {"model_type": "boomerang", "components_values": {
        "upper_plaintext": {"value": "0x1"},
        "upper_sbox_0_0": {"value": "0x7"},
        "upper_intermediate_output_0_1": {"value": "0x7"},
        "lower_intermediate_output_0_1": {"value": "0x7"},
        "lower_sbox_1_0": {"value": "0x1"},
        "lower_cipher_output_1_1": {"value": "0x1"},
    }}
    return cipher, trail


def test_four_execution_count_matches_exhaustive_trail():
    pytest.importorskip("pyapproxmc")
    cipher, trail = _sbox_example()
    exact = validate_boomerang_trail(cipher, trail, "exhaustive")
    result = SatBoomerangQuartetModel(cipher).count(trail)

    assert exact["trail"]["successes"] == result["approximate_count"] == 2
    assert result["probability"] == 2 / 16
    assert result["probability_interval_at_confidence"][0] <= 2 / 16
    assert result["probability_interval_at_confidence"][1] >= 2 / 16


def test_nonreturning_count_matches_exhaustive_trail():
    pytest.importorskip("pyapproxmc")
    cipher, trail = _sbox_example()
    exact = validate_boomerang_trail(cipher, trail, "exhaustive",
                                      exclude_returning_quartets=True)
    result = SatBoomerangQuartetModel(cipher).count(
        trail, exclude_returning_quartets=True,
    )

    assert exact["trail"]["successes"] == result["approximate_count"] == 0


def test_fixed_input_bits_change_denominator_consistently():
    pytest.importorskip("pyapproxmc")
    cipher, trail = _sbox_example()
    fixed = {"mask": 0x8, "value": 0x8, "scope": "initial_pair"}
    exact = validate_boomerang_trail(cipher, trail, "exhaustive",
                                      fixed_input_bits=fixed)
    result = SatBoomerangQuartetModel(cipher).count(trail, fixed_input_bits=fixed)

    assert exact["trail"]["successes"] == result["approximate_count"] == 2
    assert result["input_space_size"] == 8


def test_missing_endpoint_difference_rejected():
    cipher, trail = _sbox_example()
    del trail["components_values"]["lower_cipher_output_1_1"]
    with pytest.raises(ValueError, match="lower output"):
        SatBoomerangQuartetModel(cipher).build(trail)


def test_public_keyed_count_agrees_across_keys():
    pytest.importorskip("pyapproxmc")
    cipher = Cipher("xor_key", "block_cipher", ["plaintext", "key"], [4, 4], 4)
    cipher.add_round()
    mixed = cipher.add_xor_component(
        ["plaintext", "key"], [list(range(4)), list(range(4))], 4,
    )
    cipher.add_cipher_output_component([mixed.id], [list(range(4))], 4)
    model = MznHadipourBoomerangModel(cipher, {
        "top_part_number_of_rounds": 0,
        "middle_part_number_of_rounds": 1,
        "bottom_part_number_of_rounds": 0,
    })
    trail = {"model_type": "boomerang", "components_values": {
        "upper_plaintext": {"value": "0x1"},
        "lower_cipher_output_0_1": {"value": "0x1"},
    }}
    result = model.estimate_boomerang_trail_probability_over_keys(trail, [0, 3])

    assert result["mean_probability_over_supplied_keys"] == 1
    assert [item["approximate_count"] for item in result["per_key"]] == [16, 16]
