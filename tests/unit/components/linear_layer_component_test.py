from claasp.cipher_modules.models.milp.milp_model import MilpModel
from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import \
    MilpBitwiseDeterministicTruncatedXorDifferentialModel
from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import \
    MilpWordwiseDeterministicTruncatedXorDifferentialModel

def test_cms_constraints():
    fancy = FancyBlockCipher(number_of_rounds=3)
    linear_layer_component = fancy.component_from(0, 6)
    output_bit_ids, constraints = linear_layer_component.cms_constraints()

    assert output_bit_ids[0] == 'linear_layer_0_6_0'
    assert output_bit_ids[1] == 'linear_layer_0_6_1'
    assert output_bit_ids[2] == 'linear_layer_0_6_2'

    assert constraints[-3] == 'x -linear_layer_0_6_21 sbox_0_0_1 sbox_0_1_2 sbox_0_1_3 sbox_0_2_0 sbox_0_2_1 ' \
                              'sbox_0_2_3 sbox_0_3_1 sbox_0_3_2 sbox_0_4_1 sbox_0_4_2 sbox_0_5_1 sbox_0_5_3'
    assert constraints[-2] == 'x -linear_layer_0_6_22 sbox_0_0_2 sbox_0_2_2 sbox_0_3_2 sbox_0_4_3 sbox_0_5_0 ' \
                              'sbox_0_5_1 sbox_0_5_3'
    assert constraints[-1] == 'x -linear_layer_0_6_23 sbox_0_0_0 sbox_0_0_1 sbox_0_0_2 sbox_0_0_3 sbox_0_1_3 ' \
                              'sbox_0_2_1 sbox_0_3_1 sbox_0_3_2 sbox_0_3_3 sbox_0_4_1 sbox_0_4_2 sbox_0_4_3 ' \
                              'sbox_0_5_1 sbox_0_5_2 sbox_0_5_3'


def test_cms_xor_linear_mask_propagation_constraints():
    fancy = FancyBlockCipher(number_of_rounds=3)
    linear_layer_component = fancy.component_from(0, 6)
    output_bit_ids, constraints = linear_layer_component.cms_xor_linear_mask_propagation_constraints()

    assert output_bit_ids[0] == 'linear_layer_0_6_0_i'
    assert output_bit_ids[1] == 'linear_layer_0_6_1_i'
    assert output_bit_ids[2] == 'linear_layer_0_6_2_i'

    assert constraints[-3] == 'x -linear_layer_0_6_21_o dummy_0_linear_layer_0_6_21_o dummy_1_linear_layer_0_6_21_o ' \
                              'dummy_2_linear_layer_0_6_21_o dummy_3_linear_layer_0_6_21_o ' \
                              'dummy_4_linear_layer_0_6_21_o dummy_5_linear_layer_0_6_21_o ' \
                              'dummy_6_linear_layer_0_6_21_o dummy_8_linear_layer_0_6_21_o ' \
                              'dummy_9_linear_layer_0_6_21_o dummy_10_linear_layer_0_6_21_o ' \
                              'dummy_11_linear_layer_0_6_21_o dummy_12_linear_layer_0_6_21_o ' \
                              'dummy_18_linear_layer_0_6_21_o dummy_19_linear_layer_0_6_21_o ' \
                              'dummy_23_linear_layer_0_6_21_o'
    assert constraints[-2] == 'x -linear_layer_0_6_22_o dummy_0_linear_layer_0_6_22_o dummy_1_linear_layer_0_6_22_o ' \
                              'dummy_2_linear_layer_0_6_22_o dummy_3_linear_layer_0_6_22_o ' \
                              'dummy_4_linear_layer_0_6_22_o dummy_6_linear_layer_0_6_22_o ' \
                              'dummy_9_linear_layer_0_6_22_o dummy_13_linear_layer_0_6_22_o ' \
                              'dummy_14_linear_layer_0_6_22_o dummy_15_linear_layer_0_6_22_o ' \
                              'dummy_16_linear_layer_0_6_22_o dummy_19_linear_layer_0_6_22_o ' \
                              'dummy_20_linear_layer_0_6_22_o dummy_21_linear_layer_0_6_22_o'
    assert constraints[-1] == 'x -linear_layer_0_6_23_o dummy_1_linear_layer_0_6_23_o dummy_5_linear_layer_0_6_23_o ' \
                              'dummy_7_linear_layer_0_6_23_o dummy_8_linear_layer_0_6_23_o ' \
                              'dummy_9_linear_layer_0_6_23_o dummy_14_linear_layer_0_6_23_o ' \
                              'dummy_17_linear_layer_0_6_23_o dummy_18_linear_layer_0_6_23_o ' \
                              'dummy_23_linear_layer_0_6_23_o'


def test_cp_constraints():
    fancy = FancyBlockCipher(number_of_rounds=3)
    linear_layer_component = fancy.component_from(0, 6)
    declarations, constraints = linear_layer_component.cp_constraints()

    assert declarations == []

    assert constraints[0] == 'constraint linear_layer_0_6[0] = (sbox_0_0[2] + sbox_0_0[3] + sbox_0_1[0] + ' \
                             'sbox_0_1[1] + sbox_0_1[3] + sbox_0_2[0] + sbox_0_2[1] + sbox_0_3[1] + sbox_0_4[2] + ' \
                             'sbox_0_5[1] + sbox_0_5[3]) mod 2;'
    assert constraints[-1] == 'constraint linear_layer_0_6[23] = (sbox_0_0[0] + sbox_0_0[1] + sbox_0_0[2] + ' \
                              'sbox_0_0[3] + sbox_0_1[3] + sbox_0_2[1] + sbox_0_3[1] + sbox_0_3[2] + sbox_0_3[3] + ' \
                              'sbox_0_4[1] + sbox_0_4[2] + sbox_0_4[3] + sbox_0_5[1] + sbox_0_5[2] + sbox_0_5[3]) ' \
                              'mod 2;'


def test_cp_deterministic_truncated_xor_differential_constraints():
    fancy = FancyBlockCipher(number_of_rounds=3)
    linear_layer_component = fancy.component_from(0, 6)
    declarations, constraints = linear_layer_component.cp_deterministic_truncated_xor_differential_constraints()

    assert declarations == []

    assert constraints[0] == 'constraint if ((sbox_0_0[2] < 2) /\\ (sbox_0_0[3] < 2) /\\ (sbox_0_1[0] < 2) /\\ ' \
                             '(sbox_0_1[1] < 2) /\\ (sbox_0_1[3] < 2) /\\ (sbox_0_2[0] < 2) /\\ (sbox_0_2[1] < 2)' \
                             ' /\\ (sbox_0_3[1] < 2) /\\ (sbox_0_4[2] < 2) /\\ (sbox_0_5[1] < 2) /\\ ' \
                             '(sbox_0_5[3]< 2)) then linear_layer_0_6[0] = (sbox_0_0[2] + sbox_0_0[3] + sbox_0_1[0] ' \
                             '+ sbox_0_1[1] + sbox_0_1[3] + sbox_0_2[0] + sbox_0_2[1] + sbox_0_3[1] + sbox_0_4[2] + ' \
                             'sbox_0_5[1] + sbox_0_5[3]) mod 2 else linear_layer_0_6[0] = 2 endif;'
    assert constraints[-1] == 'constraint if ((sbox_0_0[0] < 2) /\\ (sbox_0_0[1] < 2) /\\ (sbox_0_0[2] < 2) /\\ ' \
                              '(sbox_0_0[3] < 2) /\\ (sbox_0_1[3] < 2) /\\ (sbox_0_2[1] < 2) /\\ (sbox_0_3[1] < 2) ' \
                              '/\\ (sbox_0_3[2] < 2) /\\ (sbox_0_3[3] < 2) /\\ (sbox_0_4[1] < 2) /\\ ' \
                              '(sbox_0_4[2] < 2) /\\ (sbox_0_4[3] < 2) /\\ (sbox_0_5[1] < 2) /\\ (sbox_0_5[2] < 2) ' \
                              '/\\ (sbox_0_5[3]< 2)) then linear_layer_0_6[23] = (sbox_0_0[0] + sbox_0_0[1] + ' \
                              'sbox_0_0[2] + sbox_0_0[3] + sbox_0_1[3] + sbox_0_2[1] + sbox_0_3[1] + sbox_0_3[2] + ' \
                              'sbox_0_3[3] + sbox_0_4[1] + sbox_0_4[2] + sbox_0_4[3] + sbox_0_5[1] + sbox_0_5[2] + ' \
                              'sbox_0_5[3]) mod 2 else linear_layer_0_6[23] = 2 endif;'

    fancy = FancyBlockCipher(number_of_rounds=3)
    linear_component = fancy.component_from(0, 6)
    declarations, constraints = linear_component.cp_deterministic_truncated_xor_differential_constraints(True)

    assert declarations == []

    assert constraints[0] == 'constraint if ((sbox_0_0_inverse[2] < 2) /\\ (sbox_0_0_inverse[3] < 2) /\\ ' \
                             '(sbox_0_1_inverse[0] < 2) /\\ (sbox_0_1_inverse[1] < 2) /\\ (sbox_0_1_inverse[3] < 2)' \
                             ' /\\ (sbox_0_2_inverse[0] < 2) /\\ (sbox_0_2_inverse[1] < 2) /\\ ' \
                             '(sbox_0_3_inverse[1] < 2) /\\ (sbox_0_4_inverse[2] < 2) /\\ (sbox_0_5_inverse[1] < 2) ' \
                             '/\\ (sbox_0_5_inverse[3]< 2)) then linear_layer_0_6_inverse[0] = (sbox_0_0_inverse[2]' \
                             ' + sbox_0_0_inverse[3] + sbox_0_1_inverse[0] + sbox_0_1_inverse[1] + ' \
                             'sbox_0_1_inverse[3] + sbox_0_2_inverse[0] + sbox_0_2_inverse[1] + sbox_0_3_inverse[1]' \
                             ' + sbox_0_4_inverse[2] + sbox_0_5_inverse[1] + sbox_0_5_inverse[3]) mod 2 else ' \
                             'linear_layer_0_6_inverse[0] = 2 endif;'

    assert constraints[-1] == 'constraint if ((sbox_0_0_inverse[0] < 2) /\\ (sbox_0_0_inverse[1] < 2) /\\ ' \
                              '(sbox_0_0_inverse[2] < 2) /\\ (sbox_0_0_inverse[3] < 2) /\\ (sbox_0_1_inverse[3] < 2)' \
                              ' /\\ (sbox_0_2_inverse[1] < 2) /\\ (sbox_0_3_inverse[1] < 2) /\\ ' \
                              '(sbox_0_3_inverse[2] < 2) /\\ (sbox_0_3_inverse[3] < 2) /\\ (sbox_0_4_inverse[1] < 2)' \
                              ' /\\ (sbox_0_4_inverse[2] < 2) /\\ (sbox_0_4_inverse[3] < 2) /\\' \
                              ' (sbox_0_5_inverse[1] < 2) /\\ (sbox_0_5_inverse[2] < 2) /\\ (sbox_0_5_inverse[3]< 2))' \
                              ' then linear_layer_0_6_inverse[23] = (sbox_0_0_inverse[0] + sbox_0_0_inverse[1] +' \
                              ' sbox_0_0_inverse[2] + sbox_0_0_inverse[3] + sbox_0_1_inverse[3] + sbox_0_2_inverse[1]' \
                              ' + sbox_0_3_inverse[1] + sbox_0_3_inverse[2] + sbox_0_3_inverse[3] + ' \
                              'sbox_0_4_inverse[1] + sbox_0_4_inverse[2] + sbox_0_4_inverse[3] + sbox_0_5_inverse[1]' \
                              ' + sbox_0_5_inverse[2] + sbox_0_5_inverse[3]) mod 2 else linear_layer_0_6_inverse[23]' \
                              ' = 2 endif;'


def test_cp_xor_linear_mask_propagation_constraints():
    fancy = FancyBlockCipher()
    linear_layer_component = fancy.component_from(0, 6)
    declarations, constraints = linear_layer_component.cp_xor_linear_mask_propagation_constraints()

    assert declarations == ['array[0..23] of var 0..1:linear_layer_0_6_i;',
                            'array[0..23] of var 0..1:linear_layer_0_6_o;']

    assert constraints[0] == 'constraint linear_layer_0_6_i[0]=(linear_layer_0_6_o[3]+linear_layer_0_6_o[6]+' \
                             'linear_layer_0_6_o[8]+linear_layer_0_6_o[9]+linear_layer_0_6_o[12]+' \
                             'linear_layer_0_6_o[14]+linear_layer_0_6_o[15]+linear_layer_0_6_o[16]+' \
                             'linear_layer_0_6_o[18]+linear_layer_0_6_o[19]+linear_layer_0_6_o[23]) mod 2;'
    assert constraints[-1] == 'constraint linear_layer_0_6_i[23]=(linear_layer_0_6_o[0]+linear_layer_0_6_o[1]+' \
                              'linear_layer_0_6_o[2]+linear_layer_0_6_o[3]+linear_layer_0_6_o[4]+' \
                              'linear_layer_0_6_o[7]+linear_layer_0_6_o[8]+linear_layer_0_6_o[11]+' \
                              'linear_layer_0_6_o[13]+linear_layer_0_6_o[14]+linear_layer_0_6_o[15]+' \
                              'linear_layer_0_6_o[18]+linear_layer_0_6_o[19]+linear_layer_0_6_o[20]+' \
                              'linear_layer_0_6_o[21]+linear_layer_0_6_o[22]+linear_layer_0_6_o[23]) mod 2;'


def test_milp_constraints():
    present = PresentBlockCipher(number_of_rounds=6)
    milp = MilpModel(present)
    milp.init_model_in_sage_milp_class()
    linear_layer_component = present.component_from(0, 17)
    variables, constraints = linear_layer_component.milp_constraints(milp)

    assert str(variables[0]) == "('x[sbox_0_1_0]', x_0)"
    assert str(variables[1]) == "('x[sbox_0_1_1]', x_1)"
    assert str(variables[-2]) == "('x[linear_layer_0_17_62]', x_126)"
    assert str(variables[-1]) == "('x[linear_layer_0_17_63]', x_127)"

    assert str(constraints[0]) == "x_64 == x_0"
    assert str(constraints[1]) == "x_65 == x_4"
    assert str(constraints[-2]) == "x_126 == x_59"
    assert str(constraints[-1]) == "x_127 == x_63"


def test_milp_xor_linear_mask_propagation_constraints():
    present = PresentBlockCipher(number_of_rounds=6)
    milp = MilpModel(present)
    milp.init_model_in_sage_milp_class()
    linear_layer_component = present.component_from(0, 17)
    variables, constraints = linear_layer_component.milp_xor_linear_mask_propagation_constraints(milp)

    assert str(variables[0]) == "('x[linear_layer_0_17_0_i]', x_0)"
    assert str(variables[1]) == "('x[linear_layer_0_17_1_i]', x_1)"
    assert str(variables[-2]) == "('x[linear_layer_0_17_62_o]', x_126)"
    assert str(variables[-1]) == "('x[linear_layer_0_17_63_o]', x_127)"

    assert str(constraints[0]) == "x_64 == x_0"
    assert str(constraints[1]) == "x_65 == x_4"
    assert str(constraints[-2]) == "x_126 == x_59"
    assert str(constraints[-1]) == "x_127 == x_63"


def test_sat_constraints():
    fancy = FancyBlockCipher(number_of_rounds=3)
    linear_layer_component = fancy.component_from(0, 6)
    constraints = linear_layer_component.sat_constraints()

    assert constraints[1][-1] == 'linear_layer_0_6_23 -sbox_0_0_0 -sbox_0_0_1 -sbox_0_0_2 -sbox_0_0_3 -sbox_0_1_3 ' \
                                 '-sbox_0_2_1 -sbox_0_3_1 -sbox_0_3_2 -sbox_0_3_3 -sbox_0_4_1 -sbox_0_4_2 ' \
                                 '-sbox_0_4_3 -sbox_0_5_1 -sbox_0_5_2 -sbox_0_5_3'


def test_sat_xor_linear_mask_propagation_constraints():
    fancy = FancyBlockCipher(number_of_rounds=3)
    linear_layer_component = fancy.component_from(0, 6)
    constraints = linear_layer_component.sat_xor_linear_mask_propagation_constraints()
    assert constraints[1][-1] == 'linear_layer_0_6_23_o -dummy_1_linear_layer_0_6_23_o ' \
                                 '-dummy_5_linear_layer_0_6_23_o -dummy_7_linear_layer_0_6_23_o ' \
                                 '-dummy_8_linear_layer_0_6_23_o -dummy_9_linear_layer_0_6_23_o ' \
                                 '-dummy_14_linear_layer_0_6_23_o -dummy_17_linear_layer_0_6_23_o ' \
                                 '-dummy_18_linear_layer_0_6_23_o -dummy_23_linear_layer_0_6_23_o'


def test_smt_constraints():
    fancy = FancyBlockCipher(number_of_rounds=3)
    linear_layer_component = fancy.component_from(0, 6)
    output_bit_ids, constraints = linear_layer_component.smt_constraints()

    assert output_bit_ids[0] == 'linear_layer_0_6_0'
    assert output_bit_ids[1] == 'linear_layer_0_6_1'
    assert output_bit_ids[-2] == 'linear_layer_0_6_22'
    assert output_bit_ids[-1] == 'linear_layer_0_6_23'

    assert constraints[0] == '(assert (= linear_layer_0_6_0 (xor sbox_0_0_2 sbox_0_0_3 sbox_0_1_0 sbox_0_1_1 ' \
                             'sbox_0_1_3 sbox_0_2_0 sbox_0_2_1 sbox_0_3_1 sbox_0_4_2 sbox_0_5_1 sbox_0_5_3)))'
    assert constraints[1] == '(assert (= linear_layer_0_6_1 (xor sbox_0_0_1 sbox_0_0_2 sbox_0_0_3 sbox_0_1_0 ' \
                             'sbox_0_1_2 sbox_0_1_3 sbox_0_2_1 sbox_0_2_2 sbox_0_3_1 sbox_0_3_3 sbox_0_4_0 ' \
                             'sbox_0_4_1 sbox_0_4_2 sbox_0_4_3 sbox_0_5_0 sbox_0_5_1 sbox_0_5_3)))'
    assert constraints[-2] == '(assert (= linear_layer_0_6_22 (xor sbox_0_0_2 sbox_0_2_2 sbox_0_3_2 sbox_0_4_3 ' \
                              'sbox_0_5_0 sbox_0_5_1 sbox_0_5_3)))'
    assert constraints[-1] == '(assert (= linear_layer_0_6_23 (xor sbox_0_0_0 sbox_0_0_1 sbox_0_0_2 sbox_0_0_3 ' \
                              'sbox_0_1_3 sbox_0_2_1 sbox_0_3_1 sbox_0_3_2 sbox_0_3_3 sbox_0_4_1 sbox_0_4_2 ' \
                              'sbox_0_4_3 sbox_0_5_1 sbox_0_5_2 sbox_0_5_3)))'


def test_smt_xor_linear_mask_propagation_constraints():
    fancy = FancyBlockCipher(number_of_rounds=3)
    linear_layer_component = fancy.component_from(0, 6)
    constraints = linear_layer_component.smt_xor_linear_mask_propagation_constraints()

    assert constraints[0][0] == 'linear_layer_0_6_0_i'
    assert constraints[0][1] == 'linear_layer_0_6_1_i'
    assert constraints[0][2] == 'linear_layer_0_6_2_i'
    assert constraints[0][3] == 'linear_layer_0_6_3_i'
    assert constraints[0][4] == 'linear_layer_0_6_4_i'
    assert constraints[0][5] == 'linear_layer_0_6_5_i'
    assert constraints[0][6] == 'linear_layer_0_6_6_i'

    assert constraints[0][331] == 'linear_layer_0_6_17_o'
    assert constraints[0][332] == 'linear_layer_0_6_18_o'
    assert constraints[0][333] == 'linear_layer_0_6_19_o'
    assert constraints[0][334] == 'linear_layer_0_6_20_o'
    assert constraints[0][335] == 'linear_layer_0_6_21_o'
    assert constraints[0][336] == 'linear_layer_0_6_22_o'
    assert constraints[0][337] == 'linear_layer_0_6_23_o'

def test_milp_bitwise_deterministic_truncated_xor_differential_constraints():
    present = PresentBlockCipher(number_of_rounds=6)
    milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(present)
    milp.init_model_in_sage_milp_class()
    linear_layer_component = present.component_from(0, 17)
    variables, constraints = linear_layer_component.milp_bitwise_deterministic_truncated_xor_differential_constraints(
        milp)

    assert str(variables[0]) == "('x_class[sbox_0_1_0]', x_0)"
    assert str(variables[1]) == "('x_class[sbox_0_1_1]', x_1)"
    assert str(variables[-2]) == "('x_class[linear_layer_0_17_62]', x_126)"
    assert str(variables[-1]) == "('x_class[linear_layer_0_17_63]', x_127)"

    assert str(constraints[0]) == 'x_64 == x_0'
    assert str(constraints[1]) == 'x_65 == x_4'
    assert str(constraints[-2]) == 'x_126 == x_59'
    assert str(constraints[-1]) == 'x_127 == x_63'


def test_milp_wordwise_deterministic_truncated_xor_differential_constraints():
    cipher = MidoriBlockCipher(number_of_rounds=2)
    milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(cipher)
    milp.init_model_in_sage_milp_class()
    linear_layer_component = cipher.component_from(0, 21)
    variables, constraints = linear_layer_component.milp_wordwise_deterministic_truncated_xor_differential_constraints(
        milp)

    assert str(variables[0]) == "('x[mix_column_0_20_word_0_class_bit_0]', x_0)"
    assert str(variables[1]) == "('x[mix_column_0_20_word_0_class_bit_1]', x_1)"
    assert str(variables[-2]) == "('x[mix_column_0_21_14]', x_46)"
    assert str(variables[-1]) == "('x[mix_column_0_21_15]', x_47)"

    assert str(constraints[0]) == '1 <= 1 + x_6 + x_8 + x_9 + x_10 + x_11 + x_13 + x_18 + x_19 - x_25'
    assert str(constraints[1]) == '1 <= 1 + x_6 + x_8 + x_9 + x_10 + x_11 + x_12 + x_13 + x_19 - x_25'
    assert str(constraints[-2]) == '1 <= 2 - x_6 - x_8'
    assert str(constraints[-1]) == '1 <= 1 + x_7 - x_8'