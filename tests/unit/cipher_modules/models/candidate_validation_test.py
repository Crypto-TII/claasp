"""End-to-end candidate measurements, independent of solver trail weights."""

import math
from itertools import permutations

import numpy as np
import pytest

from claasp.cipher import Cipher
from claasp.cipher_modules.models.candidate_validation import validate_candidate
from claasp.cipher_modules.models.cp.mzn_model import MznModel
from claasp.cipher_modules.models.cp.mzn_models.mzn_hadipour_boomerang_model import (
    MznHadipourBoomerangModel,
)
from claasp.cipher_modules.models.milp.milp_model import MilpModel
from claasp.cipher_modules.models.sat.sat_model import SatModel
from claasp.cipher_modules.models.smt.smt_model import SmtModel
from claasp.cipher_modules.models.utils import boomerang_checker_for_permutation
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.name_mappings import BLOCK_CIPHER, PERMUTATION

SBOX = [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2]


class ToyArxPermutation(Cipher):
    """A small reversible ARX Feistel network used for exact measurements."""

    def __init__(self, number_of_rounds=3):
        super().__init__("toy_arx", PERMUTATION, ["plaintext"], [8], 8)
        state = "plaintext"
        for _ in range(number_of_rounds):
            self.add_round()
            rotated = self.add_rotate_component([state], [list(range(4, 8))], 4, 1)
            added = self.add_modadd_component(
                [state, rotated.id], [list(range(4, 8)), list(range(4))], 4
            )
            right = self.add_xor_component(
                [state, added.id], [list(range(4)), list(range(4))], 4
            )
            state = self.add_round_output_component(
                [state, right.id], [list(range(4, 8)), list(range(4))], 8
            ).id
        self.add_cipher_output_component([state], [list(range(8))], 8)


def toy_sbox():
    cipher = Cipher("validation_sbox", PERMUTATION, ["plaintext"], [4], 4)
    cipher.add_round()
    box = cipher.add_sbox_component(["plaintext"], [[0, 1, 2, 3]], 4, SBOX)
    output = cipher.add_cipher_output_component([box.id], [[0, 1, 2, 3]], 4)
    return cipher, output.id


@pytest.mark.parametrize("model_class", [MznModel, SatModel, SmtModel, MilpModel])
def test_every_backend_exposes_the_same_xor_differential_validator(model_class):
    cipher, output = toy_sbox()
    model = model_class(cipher)
    candidate = {
        "model_type": "xor_differential",
        "components_values": {
            "plaintext": {"value": "0x1"},
            output: {"value": "0x5"},
        },
    }
    result = model.validate_candidate(candidate, "exhaustive")
    expected = sum(SBOX[x] ^ SBOX[x ^ 1] == 5 for x in range(16))
    assert result["successes"] == expected
    assert result["trials"] == 16
    assert result["observed_probability"] == expected / 16
    assert result["baseline_probability"] == pytest.approx(1 / 15)
    assert result["status"] == "EXACT"


@pytest.mark.parametrize("model_class", [MznModel, SatModel, SmtModel, MilpModel])
def test_every_backend_exposes_the_same_xor_linear_validator(model_class):
    cipher, output = toy_sbox()
    model = model_class(cipher)
    candidate = {
        "model_type": "xor_linear",
        "total_weight": 2,
        "components_values": {
            "plaintext_o": {"value": "0x1"},
            f"{output}_o": {"value": "0x5"},
        },
    }
    result = model.validate_candidate(candidate, "exhaustive")
    matches = sum(
        ((x & 1).bit_count() ^ (SBOX[x] & 5).bit_count()) % 2 == 0 for x in range(16)
    )
    assert result["successes"] == matches
    assert result["observed_correlation"] == 2 * matches / 16 - 1
    assert result["baseline_correlation"] == 0
    assert result["candidate_comparison"]["quantity"] == "absolute_correlation"
    assert result["candidate_comparison"]["implied_trail_value"] == 1 / 4
    assert result["candidate_comparison"]["observed_external_value"] == abs(
        result["observed_correlation"]
    )


def test_differential_linear_validator_uses_pair_parity():
    cipher, output = toy_sbox()
    candidate = {
        "model_type": "xor_differential_linear_one_solution",
        "total_weight": 2,
        "components_values": {
            "plaintext": {"value": "0x1"},
            f"{output}_o": {"value": "0x5"},
        },
    }
    result = validate_candidate(cipher, candidate, "exhaustive")
    matches = sum(
        (((SBOX[x] ^ SBOX[x ^ 1]) & 5).bit_count() % 2) == 0 for x in range(16)
    )
    assert result["successes"] == matches
    assert result["observed_correlation"] == 2 * matches / 16 - 1
    assert result["candidate_comparison"]["quantity"] == "absolute_correlation"


def test_boomerang_validator_counts_quartets_and_excludes_two_point_returns():
    cipher, output = toy_sbox()
    model = MznHadipourBoomerangModel(
        cipher,
        {
            "top_part_number_of_rounds": 0,
            "middle_part_number_of_rounds": 1,
            "bottom_part_number_of_rounds": 0,
        },
    )
    candidate = {
        "model_type": "boomerang",
        "total_weight": "3.0",
        "weight_type": "local_characteristic_weight_estimate",
        "components_values": {
            "upper_plaintext": {"value": "0x1"},
            f"lower_{output}": {"value": "0x5"},
        },
    }
    all_returns = model.validate_boomerang_candidate(candidate, "exhaustive")
    nondegenerate = model.validate_boomerang_candidate(
        candidate, "exhaustive", exclude_returning_quartets=True
    )
    assert all_returns["successes"] == 16
    assert nondegenerate["successes"] == 16
    assert all_returns["observed_probability"] == 1
    comparison = all_returns["candidate_comparison"]
    assert comparison["quantity"] == "probability"
    assert comparison["implied_trail_value"] == 1 / 8
    assert comparison["observed_minus_implied_value"] == 7 / 8
    assert comparison["observed_minus_reported_weight_bits"] == -3
    assert nondegenerate["baseline_probability"] < all_returns["baseline_probability"]


def test_candidate_validation_rejects_missing_endpoints():
    cipher, _ = toy_sbox()
    with pytest.raises(ValueError, match="no output_difference"):
        validate_candidate(
            cipher,
            {
                "model_type": "xor_differential",
                "components_values": {"plaintext": {"value": "0x1"}},
            },
            10,
        )


def test_keyed_boomerang_reuses_the_existing_vectorized_checker():
    cipher = SpeckBlockCipher(block_bit_size=16, key_bit_size=32, number_of_rounds=2)
    output = next(
        component.id
        for component in cipher.all_components()
        if component.type == "cipher_output"
    )
    candidate = {
        "model_type": "boomerang",
        "components_values": {
            "upper_plaintext": {"value": "0x0000"},
            f"lower_{output}": {"value": "0x0000"},
        },
    }
    result = validate_candidate(cipher, candidate, 32, fixed_key=0, seed=1)
    assert result["checker"] == "boomerang_checker_for_block_cipher_single_key"
    assert result["successes"] == 32
    assert result["observed_probability"] == 1
    assert result["confidence_interval_95"] is not None
    nondegenerate = validate_candidate(
        cipher, candidate, 32, fixed_key=0, seed=1, exclude_returning_quartets=True
    )
    assert nondegenerate["checker"] == "boomerang_checker_for_block_cipher_single_key"
    assert nondegenerate["successes"] == 0


def test_vectorized_filter_excludes_swapped_two_point_returns():
    cipher = Cipher("keyed_xor", BLOCK_CIPHER, ["plaintext", "key"], [8, 8], 8)
    cipher.add_round()
    xor = cipher.add_xor_component(
        ["plaintext", "key"], [list(range(8)), list(range(8))], 8
    )
    output = cipher.add_cipher_output_component([xor.id], [list(range(8))], 8)
    candidate = {
        "model_type": "boomerang",
        "components_values": {
            "upper_plaintext": {"value": "0x01"},
            f"lower_{output.id}": {"value": "0x01"},
        },
    }
    assert (
        validate_candidate(cipher, candidate, 32, fixed_key=0, seed=4)["successes"]
        == 32
    )
    assert (
        validate_candidate(
            cipher, candidate, 32, fixed_key=0, seed=4, exclude_returning_quartets=True
        )["successes"]
        == 0
    )


def test_explicit_truncated_checker_uses_existing_utility():
    cipher, output = toy_sbox()
    candidate = {
        "model_type": "deterministic_truncated_xor_differential",
        "components_values": {
            "plaintext": {"value": "0x1"},
            output: {"value": "0x0"},
        },
    }
    with pytest.raises(NotImplementedError, match="byte-aligned"):
        validate_candidate(
            cipher,
            candidate,
            16,
            checker="differential_truncated_checker_permutation",
            output_difference="????",
        )


def test_arx_differential_candidate_is_measured_over_all_inputs():
    cipher = ToyArxPermutation()
    output = next(
        component.id
        for component in cipher.all_components()
        if component.type == "cipher_output"
    )
    candidate = {
        "model_type": "xor_differential",
        "total_weight": 6,
        "components_values": {
            "plaintext": {"value": "0x12"},
            output: {"value": "0x80"},
        },
    }
    result = SatModel(cipher).validate_candidate(candidate, "exhaustive")
    assert result["successes"] == 18
    assert result["observed_probability"] == 18 / 256
    assert result["baseline_probability"] == pytest.approx(1 / 255)
    assert result["candidate_comparison"]["implied_trail_value"] == 1 / 64
    assert result["candidate_comparison"]["observed_minus_implied_value"] == (
        18 / 256 - 1 / 64
    )


def test_two_round_arx_boomerang_counts_nondegenerate_returns():
    cipher = ToyArxPermutation(number_of_rounds=2)
    output = next(
        component.id
        for component in cipher.all_components()
        if component.type == "cipher_output"
    )
    model = MznHadipourBoomerangModel(
        cipher,
        {
            "top_part_number_of_rounds": 0,
            "middle_part_number_of_rounds": 2,
            "bottom_part_number_of_rounds": 0,
        },
        middle_model="exact",
    )
    candidate = {
        "model_type": "boomerang",
        "total_weight": "0.0",
        "weight_type": "outer_characteristic_weight",
        "components_values": {
            "upper_plaintext": {"value": "0xfa"},
            f"lower_{output}": {"value": "0xf0"},
        },
    }
    result = model.validate_boomerang_candidate(
        candidate, "exhaustive", exclude_returning_quartets=True
    )
    assert result["successes"] == 16
    assert result["trials"] == 256
    assert result["observed_probability"] == 1 / 16
    assert result["candidate_comparison"]["reported_weight_bits"] == 0
    assert "implied_trail_value" not in result["candidate_comparison"]
    assert result["candidate_comparison"]["reason"] == (
        "the score does not estimate the complete event"
    )


def test_keyless_vectorized_boomerang_matches_exact_arx_rate():
    cipher = ToyArxPermutation(number_of_rounds=2)
    output = next(
        component.id
        for component in cipher.all_components()
        if component.type == "cipher_output"
    )
    candidate = {
        "model_type": "boomerang",
        "components_values": {
            "upper_plaintext": {"value": "0xfa"},
            f"lower_{output}": {"value": "0xf0"},
        },
    }
    direct = boomerang_checker_for_permutation(
        cipher, 0xfa, 0xf0, 4097, 8, seed=1,
        exclude_returning_quartets=True, return_counts=True,
    )
    result = MznHadipourBoomerangModel(
        cipher,
        {
            "top_part_number_of_rounds": 0,
            "middle_part_number_of_rounds": 2,
            "bottom_part_number_of_rounds": 0,
        },
        middle_model="exact",
    ).validate_boomerang_candidate(
        candidate, 4097, seed=1, exclude_returning_quartets=True
    )
    assert result["checker"] == "boomerang_checker_for_permutation"
    assert direct == (result["successes"], result["trials"])
    assert 0.04 < result["observed_probability"] < 0.09
    assert result["status"] == "MEASURED"
    assert result["confidence_interval_95"] is not None


def test_keyless_vectorized_boomerang_excludes_two_point_returns():
    cipher = ToyArxPermutation(number_of_rounds=2)
    assert boomerang_checker_for_permutation(cipher, 1, 0, 4097, 8, seed=2) == 1.0
    assert boomerang_checker_for_permutation(
        cipher, 1, 0, 4097, 8, seed=2,
        exclude_returning_quartets=True,
    ) == 0.0


def test_keyless_vectorized_boomerang_matches_independent_scalar_count():
    cipher = ToyArxPermutation(number_of_rounds=2)
    inverse = cipher.cipher_inverse()
    inputs = np.random.default_rng(17).integers(
        0, 256, size=(1, 257), dtype=np.uint8
    ).ravel()
    count = 0
    for sampled in inputs:
        plaintext_0 = int(sampled)
        plaintext_1 = plaintext_0 ^ 0xfa
        ciphertext_0 = cipher.evaluate([plaintext_0])
        ciphertext_1 = cipher.evaluate([plaintext_1])
        plaintext_2 = inverse.evaluate([ciphertext_0 ^ 0xf0])
        plaintext_3 = inverse.evaluate([ciphertext_1 ^ 0xf0])
        count += (
            plaintext_2 ^ plaintext_3 == 0xfa
            and plaintext_2 not in (plaintext_0, plaintext_1)
        )
    assert boomerang_checker_for_permutation(
        cipher, 0xfa, 0xf0, 257, 8, seed=17,
        exclude_returning_quartets=True, return_counts=True,
    ) == (count, 257)


def test_keyless_vectorized_boomerang_supports_ascon_and_explicit_inverse():
    from claasp.ciphers.permutations.ascon_sbox_sigma_permutation import (
        AsconSboxSigmaPermutation,
    )

    cipher = AsconSboxSigmaPermutation(number_of_rounds=1)
    inverse = cipher.cipher_inverse()
    assert boomerang_checker_for_permutation(
        cipher, 1, 0, 8, 320, seed=1, return_counts=True
    ) == (8, 8)
    assert boomerang_checker_for_permutation(
        cipher, 1, 0, 8, 320, seed=1, inverse_cipher=inverse,
        return_counts=True,
    ) == (8, 8)
    output = next(
        component.id
        for component in cipher.all_components()
        if component.type == "cipher_output"
    )
    result = validate_candidate(
        cipher,
        {
            "model_type": "boomerang",
            "components_values": {
                "upper_plaintext": {"value": "0x1"},
                f"lower_{output}": {"value": "0x0"},
            },
        },
        8,
        seed=1,
        inverse_cipher=inverse,
    )
    assert result["checker"] == "boomerang_checker_for_permutation"
    assert result["successes"] == 8
    with pytest.raises(ValueError, match="multiple of 8"):
        boomerang_checker_for_permutation(cipher, 1, 0, 8, 319)


def test_keyless_vectorized_boomerang_reports_keccak_inverse_limitation():
    from claasp.ciphers.permutations.keccak_sbox_permutation import (
        KeccakSboxPermutation,
    )

    cipher = KeccakSboxPermutation(number_of_rounds=1, word_size=8)
    with pytest.raises(ValueError, match="supply inverse_cipher"):
        boomerang_checker_for_permutation(cipher, 1, 0, 8, 200)


def test_keyless_vectorized_boomerang_supports_invertible_keccak():
    from claasp.ciphers.permutations.keccak_invertible_permutation import (
        KeccakInvertiblePermutation,
    )

    cipher = KeccakInvertiblePermutation(number_of_rounds=1, word_size=8)
    assert boomerang_checker_for_permutation(
        cipher, 1, 0, 8, 200, seed=1, return_counts=True
    ) == (8, 8)


def test_explicit_truncated_checker_runs_on_byte_aligned_cipher():
    cipher = ToyArxPermutation()
    output = next(
        component.id
        for component in cipher.all_components()
        if component.type == "cipher_output"
    )
    candidate = {
        "model_type": "deterministic_truncated_xor_differential",
        "components_values": {
            "plaintext": {"value": "0x12"},
            output: {"value": "0x80"},
        },
    }
    result = validate_candidate(
        cipher,
        candidate,
        32,
        checker="differential_truncated_checker_permutation",
        output_difference="0???????",
        seed=3,
    )
    assert result["checker"] == "differential_truncated_checker_permutation"
    assert 0 <= result["observed_probability"] <= 1


def test_keyed_differential_linear_checker_is_available():
    cipher = SpeckBlockCipher(block_bit_size=16, key_bit_size=32, number_of_rounds=2)
    output = next(
        component.id
        for component in cipher.all_components()
        if component.type == "cipher_output"
    )
    candidate = {
        "model_type": "xor_differential_linear_one_solution",
        "components_values": {
            "plaintext": {"value": "0x0000"},
            f"{output}_o": {"value": "0x0001"},
        },
    }
    result = validate_candidate(cipher, candidate, 32, fixed_key=0, seed=4)
    assert (
        result["checker"] == "differential_linear_checker_for_block_cipher_single_key"
    )
    assert result["observed_correlation"] == 1


def test_zero_sampled_differential_count_is_inconclusive_with_bound():
    cipher = ToyArxPermutation()
    output = next(
        component.id
        for component in cipher.all_components()
        if component.type == "cipher_output"
    )
    candidate = {
        "model_type": "xor_differential",
        "total_weight": 6,
        "components_values": {
            "plaintext": {"value": "0x00"},
            output: {"value": "0x01"},
        },
    }
    result = validate_candidate(cipher, candidate, 32, seed=2)
    assert result["successes"] == 0
    assert result["status"] == "INCONCLUSIVE"
    assert "observed_minus_implied_value" not in result["candidate_comparison"]
    assert "zero sampled successes" in result["candidate_comparison"]["reason"]
    assert 0 < result["one_sided_upper_bound_95"] < 1


def test_boomerang_random_baseline_matches_all_three_bit_permutations():
    """Independently enumerate random permutations, including two-point returns."""
    total = nondegenerate = 0
    for permutation in permutations(range(8)):
        inverse = [0] * 8
        for x, y in enumerate(permutation):
            inverse[y] = x
        x2 = inverse[permutation[0] ^ 1]
        x3 = inverse[permutation[1] ^ 1]
        if x2 ^ x3 == 1:
            total += 1
            nondegenerate += x2 not in (0, 1)
    denominator = math.factorial(8)
    assert total / denominator == pytest.approx(1 / 7 + 6 / 35)
    assert nondegenerate / denominator == pytest.approx(6 / 35)
