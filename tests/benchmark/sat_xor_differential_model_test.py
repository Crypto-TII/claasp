from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
from claasp.cipher_modules.models.utils import set_fixed_variables
from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.name_mappings import INPUT_KEY, INPUT_PLAINTEXT

SPECK = SpeckBlockCipher()
AES = AESBlockCipher()


def test_build_xor_differential_trail_model_with_speck_cipher(benchmark):
    sat = SatXorDifferentialModel(SPECK)
    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT,
        constraint_type="not_equal",
        bit_positions=range(32),
        bit_values=(0,) * 32,
    )
    key = set_fixed_variables(
        component_id=INPUT_KEY, constraint_type="equal", bit_positions=range(64), bit_values=(0,) * 64
    )
    benchmark(sat.build_xor_differential_trail_model, 3, fixed_variables=[plaintext, key])


def test_build_xor_differential_trail_model_with_aes_cipher(benchmark):
    sat = SatXorDifferentialModel(AES)
    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT,
        constraint_type="not_equal",
        bit_positions=range(32),
        bit_values=(0,) * 32,
    )
    key = set_fixed_variables(
        component_id=INPUT_KEY, constraint_type="equal", bit_positions=range(64), bit_values=(0,) * 64
    )
    benchmark(sat.build_xor_differential_trail_model, 3, fixed_variables=[plaintext, key])


def test_find_all_xor_differential_trails_with_fixed_weight_with_speck_cipher(benchmark):
    sat = SatXorDifferentialModel(SPECK)
    sat.window_size_weight_pr_vars = 1
    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT, constraint_type="not_equal", bit_positions=range(32), bit_values=(0,) * 32
    )
    key = set_fixed_variables(
        component_id=INPUT_KEY, constraint_type="equal", bit_positions=range(64), bit_values=(0,) * 64
    )
    benchmark(sat.find_all_xor_differential_trails_with_fixed_weight, 9, fixed_values=[plaintext, key])


def test_find_all_xor_differential_trails_with_fixed_weight_with_aes_cipher(benchmark):
    sat = SatXorDifferentialModel(AES)
    sat.window_size_weight_pr_vars = 1
    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT, constraint_type="not_equal", bit_positions=range(32), bit_values=(0,) * 32
    )
    key = set_fixed_variables(
        component_id=INPUT_KEY, constraint_type="equal", bit_positions=range(64), bit_values=(0,) * 64
    )
    benchmark(sat.find_all_xor_differential_trails_with_fixed_weight, 9, fixed_values=[plaintext, key])


def test_find_lowest_weight_xor_differential_trail_with_speck_cipher(benchmark):
    speck = SpeckBlockCipher(number_of_rounds=7)
    sat = SatXorDifferentialModel(speck)
    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT, constraint_type="not_equal", bit_positions=range(32), bit_values=(0,) * 32
    )
    key = set_fixed_variables(
        component_id=INPUT_KEY, constraint_type="equal", bit_positions=range(64), bit_values=(0,) * 64
    )
    benchmark(sat.find_lowest_weight_xor_differential_trail, fixed_values=[plaintext, key])


def test_find_one_xor_differential_trail_with_fixed_weight(benchmark):
    window_size_by_round_list = [0] * SPECK.number_of_rounds
    sat = SatXorDifferentialModel(SPECK)
    sat.set_window_size_heuristic_by_round(window_size_by_round_list)
    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT, constraint_type="not_equal", bit_positions=range(32), bit_values=(0,) * 32
    )
    key = set_fixed_variables(
        component_id=INPUT_KEY, constraint_type="equal", bit_positions=range(64), bit_values=(0,) * 64
    )
    benchmark(sat.find_one_xor_differential_trail_with_fixed_weight, 3, fixed_values=[plaintext, key])


def test_find_one_xor_differential_trail_with_fixed_weight_with_aes_cipher(benchmark):
    sat = SatXorDifferentialModel(AES)
    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT, constraint_type="not_equal", bit_positions=range(32), bit_values=(0,) * 32
    )
    key = set_fixed_variables(
        component_id=INPUT_KEY, constraint_type="equal", bit_positions=range(64), bit_values=(0,) * 64
    )
    benchmark(sat.find_one_xor_differential_trail_with_fixed_weight, 3, fixed_values=[plaintext, key])
