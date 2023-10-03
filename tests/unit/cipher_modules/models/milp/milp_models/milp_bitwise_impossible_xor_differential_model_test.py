from claasp.cipher_modules.models.utils import set_fixed_variables
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_impossible_xor_differential_model import \
    MilpBitwiseImpossibleXorDifferentialModel


def test_build_bitwise_impossible_xor_differential_trail_model():
    simon = SimonBlockCipher(block_bit_size=32, number_of_rounds=2)
    milp = MilpBitwiseImpossibleXorDifferentialModel(simon)
    milp.init_model_in_sage_milp_class()
    milp._forward_cipher = simon.get_partial_cipher(0, 1, keep_key_schedule=True)
    milp._backward_cipher = simon.cipher_partial_inverse(1, 1, suffix="_backward", keep_key_schedule=False)
    milp.build_bitwise_impossible_xor_differential_trail_model()

    constraints = milp.model_constraints

    assert len(constraints) == 2432
    assert str(constraints[0]) == 'x_16 == x_0'
    assert str(constraints[1]) == 'x_17 == x_1'
    assert str(constraints[-2]) == 'x_926 == x_766'
    assert str(constraints[-1]) == 'x_927 == x_767'

def test_find_one_bitwise_impossible_xor_differential_trail_model():
    simon = SimonBlockCipher(block_bit_size=32, number_of_rounds=11)
    milp = MilpBitwiseImpossibleXorDifferentialModel(simon)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(32), bit_values=[0] * 31 + [1])
    key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(64), bit_values=[0] * 64)
    ciphertext = set_fixed_variables(component_id='cipher_output_10_13', constraint_type='equal', bit_positions=range(32), bit_values=[0] * 6 + [2, 0, 2] + [0] * 23)
    trail = milp.find_one_bitwise_impossible_xor_differential_trail(6, fixed_values=[plaintext, key, ciphertext])
    assert trail['status'] == 'SATISFIABLE'
    assert trail['components_values']['intermediate_output_5_12']['value'] == '????????????????0??????1??????0?'
    assert trail['components_values']['intermediate_output_5_12_backward']['value'] == '????????00?????0???????0????????'
