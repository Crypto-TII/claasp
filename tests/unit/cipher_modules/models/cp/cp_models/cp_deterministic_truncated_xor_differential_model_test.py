from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
from claasp.cipher_modules.models.cp.cp_models.cp_deterministic_truncated_xor_differential_model import \
    CpDeterministicTruncatedXorDifferentialModel


def test_build_deterministic_truncated_xor_differential_trail_model():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    cp = CpDeterministicTruncatedXorDifferentialModel(speck)
    fixed_variables = [set_fixed_variables('key', 'equal', range(64), integer_to_bit_list(0, 64, 'little'))]
    cp.build_deterministic_truncated_xor_differential_trail_model(fixed_variables)

    assert len(cp.model_constraints) == 423
    assert cp.model_constraints[2] == 'array[0..31] of var 0..2: plaintext;'
    assert cp.model_constraints[3] == 'array[0..63] of var 0..2: key;'
    assert cp.model_constraints[4] == 'array[0..15] of var 0..2: rot_0_0;'


def test_build_inverse_deterministic_truncated_xor_differential_trail_model():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    cp = CpDeterministicTruncatedXorDifferentialModel(speck)
    fixed_variables = [set_fixed_variables('key', 'equal', range(64), integer_to_bit_list(0, 64, 'little')),
                       set_fixed_variables('plaintext', 'not_equal', range(32), integer_to_bit_list(0, 32, 'little'))]
    cp.build_inverse_deterministic_truncated_xor_differential_trail_model(2, fixed_variables)

    assert len(cp.model_constraints) == 1166
    assert cp.model_constraints[2] == 'constraint rot_0_0[0] = plaintext[9];'
    assert cp.model_constraints[3] == 'constraint rot_0_0[1] = plaintext[10];'
    assert cp.model_constraints[4] == 'constraint rot_0_0[2] = plaintext[11];'


def test_find_all_deterministic_truncated_xor_differential_trail():
    speck = SpeckBlockCipher(number_of_rounds=3)
    cp = CpDeterministicTruncatedXorDifferentialModel(speck)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='not_equal',
                                    bit_positions=range(32), bit_values=[0] * 32)
    key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(64), bit_values=[0] * 64)
    trail = cp.find_all_deterministic_truncated_xor_differential_trail(3, [plaintext, key], 'Chuffed')

    assert len(trail) == 3
    for i in range(len(trail)):
        assert trail[i]['cipher_id'] == 'speck_p32_k64_o32_r3'
        assert trail[i]['model_type'] == 'deterministic_truncated_xor_differential'
        assert trail[i]['components_values']['cipher_output_2_12']['weight'] == 0
        assert trail[i]['model_type'] == 'deterministic_truncated_xor_differential'
        assert trail[i]['solver_name'] == 'Chuffed'
        assert trail[i]['total_weight'] == '0.0'


def test_find_one_deterministic_truncated_xor_differential_trail():
    speck = SpeckBlockCipher(number_of_rounds=1)
    cp = CpDeterministicTruncatedXorDifferentialModel(speck)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='not_equal',
                                    bit_positions=range(32), bit_values=[0] * 32)
    key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(64), bit_values=[0] * 64)
    trail = cp.find_one_deterministic_truncated_xor_differential_trail(1, [plaintext, key], 'Chuffed')

    assert trail[0]['cipher_id'] == 'speck_p32_k64_o32_r1'
    assert trail[0]['components_values']['cipher_output_0_6']['weight'] == 0

    assert trail[0]['components_values']['intermediate_output_0_5']['weight'] == 0
    assert trail[0]['components_values']['key']['value'] == '000000000000000000000000000000000000000000000000000000' \
                                                            '0000000000'
    assert trail[0]['components_values']['key']['weight'] == 0
    assert trail[0]['components_values']['modadd_0_1']['weight'] == 0
    assert trail[0]['components_values']['plaintext']['weight'] == 0
    assert trail[0]['components_values']['rot_0_0']['weight'] == 0
    assert trail[0]['components_values']['rot_0_3']['weight'] == 0
    assert trail[0]['components_values']['xor_0_2']['weight'] == 0
    assert trail[0]['components_values']['xor_0_4']['weight'] == 0
    assert trail[0]['model_type'] == 'deterministic_truncated_xor_differential_one_solution'
    assert trail[0]['solver_name'] == 'Chuffed'
    assert trail[0]['total_weight'] == '0.0'


def test_input_wordwise_deterministic_truncated_xor_differential_constraints():
    aes = AESBlockCipher(number_of_rounds=2)
    cp = CpDeterministicTruncatedXorDifferentialModel(aes)
    declarations, constraints = cp.input_wordwise_deterministic_truncated_xor_differential_constraints()

    assert len(constraints) == 275

    assert declarations[0] == 'array[0..15] of var 0..3: key_active;'
    assert declarations[1] == 'array[0..15] of var -2..255: key_value;'
    assert declarations[2] == 'array[0..15] of var 0..3: plaintext_active;'

    assert constraints[0] == 'constraint if key_active[0] == 0 then key_value[0] = 0 elseif key_active[0] == 1 then ' \
                             'key_value[0] > 0 elseif key_active[0] == 2 then key_value[0] =-1 else ' \
                             'key_value[0] =-2 endif;'
    assert constraints[1] == 'constraint if key_active[1] == 0 then key_value[1] = 0 elseif key_active[1] == 1 then ' \
                             'key_value[1] > 0 elseif key_active[1] == 2 then key_value[1] =-1 else ' \
                             'key_value[1] =-2 endif;'
    assert constraints[2] == 'constraint if key_active[2] == 0 then key_value[2] = 0 elseif key_active[2] == 1 then ' \
                             'key_value[2] > 0 elseif key_active[2] == 2 then key_value[2] =-1 else ' \
                             'key_value[2] =-2 endif;'
