from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
from claasp.cipher_modules.models.smt.smt_models.smt_xor_linear_model import SmtXorLinearModel


def test_find_all_xor_linear_trails_with_weight_at_most():
    speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=4)
    smt = SmtXorLinearModel(speck)
    key = set_fixed_variables('key', 'not_equal', list(range(16)), [0] * 16)
    trails = smt.find_all_xor_linear_trails_with_weight_at_most(0, 3, fixed_values=[key])

    assert len(trails) == 73


def test_find_lowest_weight_xor_linear_trail():
    speck = SpeckBlockCipher(number_of_rounds=3)
    smt = SmtXorLinearModel(speck)
    trail = smt.find_lowest_weight_xor_linear_trail()
    assert trail['total_weight'] == 1.0


def test_find_one_xor_linear_trail():
    speck = SpeckBlockCipher(number_of_rounds=4)
    smt = SmtXorLinearModel(speck)
    solution = smt.find_one_xor_linear_trail()
    assert str(solution['cipher']) == 'speck_p32_k64_o32_r4'
    assert solution['solver_name'] == 'z3'
    assert eval('0x' + solution['components_values']['modadd_0_1_i']['value']) >= 0
    assert solution['components_values']['modadd_0_1_i']['weight'] == 0
    assert solution['components_values']['modadd_0_1_i']['sign'] == 1
    assert eval('0x' + solution['components_values']['xor_0_4_o']['value']) >= 0
    assert solution['components_values']['xor_0_4_o']['weight'] == 0
    assert solution['components_values']['xor_0_4_o']['sign'] == 1


def test_find_one_xor_linear_trail_with_fixed_weight():
    speck = SpeckBlockCipher(number_of_rounds=3)
    smt = SmtXorLinearModel(speck)
    result = smt.find_one_xor_linear_trail_with_fixed_weight(7)
    assert result['total_weight'] == 7.0


def test_fix_variables_value_xor_linear_constraints():
    speck = SpeckBlockCipher(number_of_rounds=3)
    smt = SmtXorLinearModel(speck)
    fixed_variables = [set_fixed_variables('plaintext', 'equal', range(4), integer_to_bit_list(5, 4, 'big'))]
    assert smt.fix_variables_value_xor_linear_constraints(fixed_variables) == ['(assert (not plaintext_0_o))',
                                                                               '(assert plaintext_1_o)',
                                                                               '(assert (not plaintext_2_o))',
                                                                               '(assert plaintext_3_o)']
