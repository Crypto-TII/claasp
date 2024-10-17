from claasp.cipher_modules.models.milp.milp_models.milp_impossible_xor_differential_model import \
        MilpImpossibleXorDifferentialModel
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.name_mappings import IMPOSSIBLE_XOR_DIFFERENTIAL, INPUT_KEY, INPUT_PLAINTEXT


def test_find_one_impossible_xor_differential_trail():
    speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=8)
    milp = MilpImpossibleXorDifferentialModel(speck)
    trail = milp.find_one_impossible_xor_differential_trail(1, 0, 0)

    assert str(trail['cipher']) == 'speck_p8_k16_o8_r8'
    assert trail['model_type'] == IMPOSSIBLE_XOR_DIFFERENTIAL
    assert trail['solver_name'] == 'GLPK'
    assert trail['status'] == 'SATISFIABLE'
    assert trail['components_values'][INPUT_KEY]['value'][1:] == '000'
    assert trail['components_values'][INPUT_PLAINTEXT]['value'] == '00'
    assert trail['components_values']['cipher_output_7_12']['value'] == '00'


def test_find_all_impossible_xor_differential_trails():
    speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=8)
    milp = MilpImpossibleXorDifferentialModel(speck)
    trails = milp.find_all_impossible_xor_differential_trails(1, 0, 0)

    assert len(trails) == 2