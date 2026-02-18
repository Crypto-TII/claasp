from claasp.cipher_modules.models.cp.mzn_models.mzn_wordwise_deterministic_truncated_xor_differential_model import (
    MznWordwiseDeterministicTruncatedXorDifferentialModel,
)
from claasp.cipher_modules.models.cp.solvers import CHUFFED
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher


def test_find_one_wordwise_deterministic_truncated_xor_differential_trail():
    aes = AESBlockCipher(number_of_rounds=2)
    mzn = MznWordwiseDeterministicTruncatedXorDifferentialModel(aes)
    fixed_variables = [set_fixed_variables("key_value", "equal", range(16), (0,) * 16)]
    mzn.build_deterministic_truncated_xor_differential_trail_model(fixed_variables, wordwise=True)

    assert len(mzn.model_constraints) == 1361
    assert mzn.model_constraints[2] == "array[0..15] of var 0..3: key_active;"
    assert mzn.model_constraints[3] == "array[0..15] of var -2..255: key_value;"
    assert mzn.model_constraints[4] == "array[0..15] of var 0..3: plaintext_active;"
    assert mzn.model_constraints[5] == "array[0..15] of var -2..255: plaintext_value;"


"""
def test_build_wordwise_deterministic_truncated_xor_differential_trail_model():
    aes = AESBlockCipher(number_of_rounds=2)
    mzn = MznWordwiseDeterministicTruncatedXorDifferentialModel(aes)
    fixed_variables = [set_fixed_variables('key_value', 'equal', range(16), (0,) * 16)]
    mzn.build_wordwise_deterministic_truncated_xor_differential_trail_model(fixed_variables)

    assert len(mzn.model_constraints) == 1361
    assert mzn.model_constraints[2] == 'array[0..15] of var 0..3: key_active;'
    assert mzn.model_constraints[3] == 'array[0..15] of var -2..255: key_value;'
    assert mzn.model_constraints[4] == 'array[0..15] of var 0..3: plaintext_active;'
    assert mzn.model_constraints[5] == 'array[0..15] of var -2..255: plaintext_value;'


def test_find_one_wordwise_deterministic_truncated_xor_differential_trail():
    aes = AESBlockCipher(number_of_rounds=2)
    mzn = MznWordwiseDeterministicTruncatedXorDifferentialModel(aes)
    plaintext = set_fixed_variables(component_id='plaintext_value', constraint_type='not_equal',
                                    bit_positions=range(16), bit_values=(0,) * 16)
    key = set_fixed_variables(component_id='key_value', constraint_type='equal', bit_positions=range(16), bit_values=(0,) * 16)
    trail = mzn.find_one_wordwise_deterministic_truncated_xor_differential_trail(1, [plaintext, key], 'chuffed', solve_external = True)

    assert str(trail[0]['cipher']) == 'speck_p32_k64_o32_r1'

    assert trail[0]['components_values']['key']['value'] == '000000000000000000000000000000000000000000000000000000' \
                                                            '0000000000'
    assert trail[0]['model_type'] == 'deterministic_truncated_xor_differential_one_solution'
    assert trail[0]['solver_name'] == 'chuffed'

    trail = mzn.find_one_wordwise_deterministic_truncated_xor_differential_trail(1, [plaintext, key], 'chuffed', solve_external = False)

    assert str(trail[0]['cipher']) == 'speck_p32_k64_o32_r1'

    assert trail[0]['components_values']['key']['value'] == '000000000000000000000000000000000000000000000000000000' \
                                                            '0000000000'
    assert trail[0]['model_type'] == 'deterministic_truncated_xor_differential_one_solution'
    assert trail[0]['solver_name'] == 'chuffed'
"""
