from claasp.components.and_component import AND
from claasp.cipher_modules.models.cp.mzn_model import MznModel
from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.ciphers.toys.fancy_block_cipher import FancyBlockCipher
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.components.and_component import cp_xor_differential_probability_ddt, cp_xor_linear_probability_lat
from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import \
    MilpBitwiseDeterministicTruncatedXorDifferentialModel

def test_cp_xor_differential_probability_ddt():
    assert cp_xor_differential_probability_ddt(2) == [4, 0, 2, 2, 2, 2, 2, 2]


def test_cp_xor_linear_probability_lat():
    assert cp_xor_linear_probability_lat(2) == [2, 1, 0, 1, 0, 1, 0, -1]


def test_cp_constraints():
    fancy = FancyBlockCipher()
    and_component = fancy.component_from(0, 8)
    declarations, constraints = and_component.cp_constraints()

    assert declarations == []

    assert constraints[0] == 'constraint and_0_8[0] = xor_0_7[0] * key[12];'
    assert constraints[-1] == 'constraint and_0_8[11] = xor_0_7[11] * key[23];'


def test_cp_wordwise_deterministic_truncated_xor_differential_constraints():
    aes = AESBlockCipher()
    cp = MznModel(aes)
    and_component = AND(0, 18, ['sbox_0_2', 'sbox_0_6', 'sbox_0_10', 'sbox_0_14'],
                        [[0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7],
                         [0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7]], 32)
    declarations, constraints = and_component.cp_wordwise_deterministic_truncated_xor_differential_constraints(cp)

    assert declarations == []

    assert constraints[0] == 'constraint if sbox_0_2_active[0] == 0 then and_0_18_active[0] = 0 /\\ and_0_18_value[0] = 0 ' \
                             'else and_0_18_active[0] = 3 /\\ and_0_18_value[0] = -2 endif;'
    assert constraints[-1] == 'constraint if sbox_0_14_active[0] == 0 then and_0_18_active[3] = 0 /\\ and_0_18_value[3] = 0' \
                              ' else and_0_18_active[3] = 3 /\\ and_0_18_value[3] = -2 endif;'


def test_cp_xor_linear_mask_propagation_constraints():
    fancy = FancyBlockCipher()
    cp = MznModel(fancy)
    and_component = fancy.component_from(0, 8)
    declarations, constraints = and_component.cp_xor_linear_mask_propagation_constraints(cp)

    assert declarations == ['array[0..23] of var 0..1:and_0_8_i;', 'array[0..11] of var 0..1:and_0_8_o;']

    assert constraints[0] == 'constraint table([and_0_8_i[0]]++[and_0_8_i[12]]++[and_0_8_o[0]]++[p[0]],and2inputs_LAT);'
    assert constraints[-1] == 'constraint table([and_0_8_i[11]]++[and_0_8_i[23]]++[and_0_8_o[11]]++[p[11]],' \
                              'and2inputs_LAT);'


def test_generic_sign_linear_constraints():
    simon = SimonBlockCipher()
    and_component = simon.component_from(0, 4)
    input_constraints = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    output = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]

    assert and_component.generic_sign_linear_constraints(input_constraints, output) == 1


def test_sat_constraints():
    fancy = FancyBlockCipher(number_of_rounds=3)
    and_component = fancy.component_from(0, 8)
    output_bit_ids, constraints = and_component.sat_constraints()

    assert output_bit_ids[0] == 'and_0_8_0'
    assert output_bit_ids[1] == 'and_0_8_1'
    assert output_bit_ids[2] == 'and_0_8_2'

    assert constraints[-3] == '-and_0_8_11 xor_0_7_11'
    assert constraints[-2] == '-and_0_8_11 key_23'
    assert constraints[-1] == 'and_0_8_11 -xor_0_7_11 -key_23'


def test_smt_constraints():
    fancy = FancyBlockCipher(number_of_rounds=3)
    and_component = fancy.component_from(0, 8)
    output_bit_ids, constraints = and_component.smt_constraints()

    assert output_bit_ids[0] == 'and_0_8_0'
    assert output_bit_ids[1] == 'and_0_8_1'
    assert output_bit_ids[-2] == 'and_0_8_10'
    assert output_bit_ids[-1] == 'and_0_8_11'

    assert constraints[0] == '(assert (= and_0_8_0 (and xor_0_7_0 key_12)))'
    assert constraints[1] == '(assert (= and_0_8_1 (and xor_0_7_1 key_13)))'
    assert constraints[-2] == '(assert (= and_0_8_10 (and xor_0_7_10 key_22)))'
    assert constraints[-1] == '(assert (= and_0_8_11 (and xor_0_7_11 key_23)))'

def test_milp_bitwise_deterministic_truncated_xor_differential_constraints():
    cipher = FancyBlockCipher(number_of_rounds=20)
    milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
    milp.init_model_in_sage_milp_class()
    and_component = cipher.component_from(0,8)
    variables, constraints = and_component.milp_bitwise_deterministic_truncated_xor_differential_constraints(milp)

    assert str(variables[0]) == "('x_class[xor_0_7_0]', x_0)"
    assert str(variables[1]) == "('x_class[xor_0_7_1]', x_1)"
    assert str(variables[-2]) == "('x_class[and_0_8_10]', x_34)"
    assert str(variables[-1]) == "('x_class[and_0_8_11]', x_35)"

    assert str(constraints[0]) == 'x_0 + x_12 <= 4 - 4*x_36'
    assert str(constraints[1]) == '1 - 4*x_36 <= x_0 + x_12'
    assert str(constraints[-2]) == 'x_35 <= 2 + 2*x_47'
    assert str(constraints[-1]) == '2 <= x_35 + 2*x_47'
