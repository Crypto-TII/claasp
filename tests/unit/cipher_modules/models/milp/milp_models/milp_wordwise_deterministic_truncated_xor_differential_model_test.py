from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values
from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher

from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import \
    MilpWordwiseDeterministicTruncatedXorDifferentialModel


def test_build_wordwise_deterministic_truncated_xor_differential_trail_model():
    aes = AESBlockCipher(number_of_rounds=2)
    milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(aes)
    milp.init_model_in_sage_milp_class()
    milp.build_wordwise_deterministic_truncated_xor_differential_trail_model()
    constraints = milp.model_constraints

    assert len(constraints) == 43944
    assert str(constraints[0]) == '1 <= 1 + x_0 - x_1 + x_2 + x_3 + x_4 + x_5 + x_6 + x_7 + x_8 + x_9'
    assert str(constraints[1]) == '1 <= 1 + x_1 - x_9'
    assert str(constraints[-2]) == 'x_3062 == x_2886'
    assert str(constraints[-1]) == 'x_3063 == x_2887'

def test_find_one_wordwise_deterministic_truncated_xor_differential_trail_model():
    aes = AESBlockCipher(number_of_rounds=2)
    milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(aes)
    trail = milp.find_one_wordwise_deterministic_truncated_xor_differential_trail(
        get_single_key_scenario_format_for_fixed_values(aes))
    assert trail['status'] == 'SATISFIABLE'

def test_find_lowest_varied_patterns_wordwise_deterministic_truncated_xor_differential_trail_model():
    midori = MidoriBlockCipher(number_of_rounds=2)
    milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(midori)
    trail = milp.find_lowest_varied_patterns_wordwise_deterministic_truncated_xor_differential_trail(
        get_single_key_scenario_format_for_fixed_values(midori))
    assert trail['status'] == 'SATISFIABLE'
    assert trail['total_weight'] == 3.0