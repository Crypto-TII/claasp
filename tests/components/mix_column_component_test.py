import pytest

from claasp.cipher_modules.models.cp.cp_model import CpModel
from claasp.cipher_modules.models.milp.milp_model import MilpModel
from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
from claasp.ciphers.block_ciphers.skinny_block_cipher import SkinnyBlockCipher
from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel


@pytest.mark.filterwarnings("ignore::DeprecationWarning:")
def test_algebraic_polynomials():
    midori = MidoriBlockCipher(number_of_rounds=16)
    mix_column = midori.get_component_from_id("mix_column_0_20")
    algebraic_polynomials = mix_column.algebraic_polynomials(AlgebraicModel(midori))

    assert str(algebraic_polynomials[0]) == "mix_column_0_20_x0 + mix_column_0_20_y0"
    assert str(algebraic_polynomials[1]) == "mix_column_0_20_x1 + mix_column_0_20_y1"
    assert str(algebraic_polynomials[2]) == "mix_column_0_20_x2 + mix_column_0_20_y2"
    assert str(algebraic_polynomials[-3]) == "mix_column_0_20_y61^2 + mix_column_0_20_y61"
    assert str(algebraic_polynomials[-2]) == "mix_column_0_20_y62^2 + mix_column_0_20_y62"
    assert str(algebraic_polynomials[-1]) == "mix_column_0_20_y63^2 + mix_column_0_20_y63"


def test_cp_create_component():
    aes = AESBlockCipher(number_of_rounds=3)
    cp = CpModel(aes)
    mix_column_component_1 = aes.component_from(0, 21)
    mix_column_component_2 = aes.component_from(0, 22)
    declarations, constraints = mix_column_component_1._cp_create_component(cp.word_size, mix_column_component_2,
                                                                            1, cp.list_of_xor_components)

    assert declarations == ['array[0..3] of var 0..1: input_xor_mix_column_0_22_mix_column_0_21;',
                            'array[0..3] of var 0..1: output_xor_mix_column_0_22_mix_column_0_21;']

    assert constraints == ['constraint table([input_xor_mix_column_0_22_mix_column_0_21[s]|s in 0..3]++'
                           '[output_xor_mix_column_0_22_mix_column_0_21[s]|s in 0..3],mix_column_truncated_table_1);']


def test_cms_constraints():
    midori = MidoriBlockCipher(number_of_rounds=3)
    mix_column_component = midori.component_from(0, 23)
    output_bit_ids, constraints = mix_column_component.cms_constraints()

    assert output_bit_ids[0] == 'mix_column_0_23_0'
    assert output_bit_ids[1] == 'mix_column_0_23_1'
    assert output_bit_ids[2] == 'mix_column_0_23_2'

    assert constraints[-3] == '-mix_column_0_23_15 -mix_column_0_20_35 mix_column_0_20_39 -mix_column_0_20_43'
    assert constraints[-2] == '-mix_column_0_23_15 mix_column_0_20_35 -mix_column_0_20_39 -mix_column_0_20_43'
    assert constraints[-1] == 'mix_column_0_23_15 -mix_column_0_20_35 -mix_column_0_20_39 -mix_column_0_20_43'


def test_cp_constraints():
    aes = AESBlockCipher(number_of_rounds=3)
    mix_column_component = aes.component_from(0, 21)
    declarations, constraints = mix_column_component.cp_constraints()

    assert declarations == []

    assert constraints[0] == 'constraint mix_column_0_21[0] = (rot_0_17[1] + rot_0_18[0] + rot_0_18[1] + ' \
                             'rot_0_19[0] + rot_0_20[0]) mod 2;'
    assert constraints[-1] == 'constraint mix_column_0_21[31] = (rot_0_17[0] + rot_0_17[7] + rot_0_18[7] + ' \
                              'rot_0_19[7] + rot_0_20[0]) mod 2;'


def test_cp_deterministic_truncated_xor_differential_constraints():
    aes = AESBlockCipher(number_of_rounds=3)
    mix_column_component = aes.component_from(0, 21)
    declarations, constraints = mix_column_component.cp_deterministic_truncated_xor_differential_constraints()

    assert declarations == []

    assert constraints[0] == 'constraint if ((rot_0_17[1] < 2) /\\ (rot_0_18[0] < 2) /\\ (rot_0_18[1] < 2) /\\ ' \
                             '(rot_0_19[0] < 2) /\\ (rot_0_20[0]< 2)) then mix_column_0_21[0] = (rot_0_17[1] + ' \
                             'rot_0_18[0] + rot_0_18[1] + rot_0_19[0] + rot_0_20[0]) mod 2 else ' \
                             'mix_column_0_21[0] = 2 endif;'
    assert constraints[-1] == 'constraint if ((rot_0_17[0] < 2) /\\ (rot_0_17[7] < 2) /\\ (rot_0_18[7] < 2) /\\ ' \
                              '(rot_0_19[7] < 2) /\\ (rot_0_20[0]< 2)) then mix_column_0_21[31] = (rot_0_17[0] + ' \
                              'rot_0_17[7] + rot_0_18[7] + rot_0_19[7] + rot_0_20[0]) mod 2 else ' \
                              'mix_column_0_21[31] = 2 endif;'


def test_cp_xor_linear_mask_propagation_constraints():
    aes = AESBlockCipher(number_of_rounds=3)
    mix_column_component = aes.component_from(0, 21)
    declarations, constraints = mix_column_component.cp_xor_linear_mask_propagation_constraints()

    assert declarations == ['array[0..31] of var 0..1:mix_column_0_21_i;',
                            'array[0..31] of var 0..1:mix_column_0_21_o;']

    assert constraints[0] == 'constraint mix_column_0_21_i[0]=(mix_column_0_21_o[1]+mix_column_0_21_o[2]+' \
                             'mix_column_0_21_o[3]+mix_column_0_21_o[8]+mix_column_0_21_o[9]+mix_column_0_21_o[11]+' \
                             'mix_column_0_21_o[16]+mix_column_0_21_o[18]+mix_column_0_21_o[19]+' \
                             'mix_column_0_21_o[24]+mix_column_0_21_o[27]) mod 2;'
    assert constraints[-1] == 'constraint mix_column_0_21_i[31]=(mix_column_0_21_o[0]+mix_column_0_21_o[2]+' \
                              'mix_column_0_21_o[7]+mix_column_0_21_o[9]+mix_column_0_21_o[10]+' \
                              'mix_column_0_21_o[15]+mix_column_0_21_o[18]+mix_column_0_21_o[23]+' \
                              'mix_column_0_21_o[24]+mix_column_0_21_o[25]+mix_column_0_21_o[26]) mod 2;'


def test_milp_constraints():
    aes = AESBlockCipher(number_of_rounds=3)
    milp = MilpModel(aes)
    milp.init_model_in_sage_milp_class()
    mix_column_component = aes.component_from(0, 21)
    variables, constraints = mix_column_component.milp_constraints(milp)

    assert str(variables[0]) == "('x[rot_0_17_0]', x_0)"
    assert str(variables[1]) == "('x[rot_0_17_1]', x_1)"
    assert str(variables[-2]) == "('x[mix_column_0_21_30]', x_62)"
    assert str(variables[-1]) == "('x[mix_column_0_21_31]', x_63)"

    assert str(constraints[:3]) == '[1 <= 1 - x_1 + x_8 + x_9 + x_16 + x_24 + x_32,' \
                                   ' 1 <= 1 + x_1 - x_8 + x_9 + x_16 + x_24 + x_32,' \
                                   ' 1 <= 1 + x_1 + x_8 - x_9 + x_16 + x_24 + x_32]'


def test_milp_xor_linear_mask_propagation_constraints():
    skinny = SkinnyBlockCipher(block_bit_size=128, number_of_rounds=2)
    milp = MilpModel(skinny)
    milp.init_model_in_sage_milp_class()
    mix_column_component = skinny.component_from(0, 31)
    variables, constraints = mix_column_component.milp_xor_linear_mask_propagation_constraints(milp)

    assert str(variables[0]) == "('x[mix_column_0_31_0_i]', x_0)"
    assert str(variables[1]) == "('x[mix_column_0_31_1_i]', x_1)"
    assert str(variables[-2]) == "('x[mix_column_0_31_30_o]', x_62)"
    assert str(variables[-1]) == "('x[mix_column_0_31_31_o]', x_63)"

    assert str(constraints[0]) == "x_32 == x_24"
    assert str(constraints[1]) == "x_33 == x_25"
    assert str(constraints[-2]) == "1 <= 3 - x_15 + x_23 - x_31 - x_63"
    assert str(constraints[-1]) == "1 <= 3 + x_15 - x_23 - x_31 - x_63"


def test_sat_constraints():
    midori = MidoriBlockCipher(number_of_rounds=3)
    mix_column_component = midori.component_from(0, 23)
    output_bit_ids, constraints = mix_column_component.sat_constraints()

    assert output_bit_ids[0] == 'mix_column_0_23_0'
    assert output_bit_ids[1] == 'mix_column_0_23_1'
    assert output_bit_ids[2] == 'mix_column_0_23_2'

    assert constraints[-3] == '-mix_column_0_23_15 -mix_column_0_20_35 mix_column_0_20_39 -mix_column_0_20_43'
    assert constraints[-2] == '-mix_column_0_23_15 mix_column_0_20_35 -mix_column_0_20_39 -mix_column_0_20_43'
    assert constraints[-1] == 'mix_column_0_23_15 -mix_column_0_20_35 -mix_column_0_20_39 -mix_column_0_20_43'


def test_sat_xor_linear_mask_propagation_constraints():
    midori = MidoriBlockCipher(number_of_rounds=3)
    mix_column_component = midori.component_from(0, 23)
    variables, constraints = mix_column_component.sat_xor_linear_mask_propagation_constraints()

    assert variables[0] == 'mix_column_0_23_0_i'
    assert variables[1] == 'mix_column_0_23_1_i'
    assert variables[2] == 'mix_column_0_23_2_i'

    assert constraints[-3] == '-mix_column_0_23_15_o -dummy_3_mix_column_0_23_15_o dummy_7_mix_column_0_23_15_o ' \
                              '-dummy_11_mix_column_0_23_15_o'
    assert constraints[-2] == '-mix_column_0_23_15_o dummy_3_mix_column_0_23_15_o -dummy_7_mix_column_0_23_15_o ' \
                              '-dummy_11_mix_column_0_23_15_o'
    assert constraints[-1] == 'mix_column_0_23_15_o -dummy_3_mix_column_0_23_15_o -dummy_7_mix_column_0_23_15_o ' \
                              '-dummy_11_mix_column_0_23_15_o'


def test_smt_constraints():
    midori = MidoriBlockCipher(number_of_rounds=3)
    mix_column_component = midori.component_from(0, 23)
    variables, constraints = mix_column_component.smt_constraints()

    assert variables[0] == 'mix_column_0_23_0'
    assert variables[1] == 'mix_column_0_23_1'
    assert variables[-2] == 'mix_column_0_23_14'
    assert variables[-1] == 'mix_column_0_23_15'

    assert constraints[0] == '(assert (= mix_column_0_23_0 (xor mix_column_0_20_36 mix_column_0_20_40 ' \
                             'mix_column_0_20_44)))'
    assert constraints[1] == '(assert (= mix_column_0_23_1 (xor mix_column_0_20_37 mix_column_0_20_41 ' \
                             'mix_column_0_20_45)))'
    assert constraints[-2] == '(assert (= mix_column_0_23_14 (xor mix_column_0_20_34 mix_column_0_20_38 ' \
                              'mix_column_0_20_42)))'
    assert constraints[-1] == '(assert (= mix_column_0_23_15 (xor mix_column_0_20_35 mix_column_0_20_39 ' \
                              'mix_column_0_20_43)))'


def test_smt_xor_linear_mask_propagation_constraints():
    midori = MidoriBlockCipher(number_of_rounds=3)
    mix_column_component = midori.component_from(0, 23)
    variables, constraints = mix_column_component.smt_xor_linear_mask_propagation_constraints()

    assert variables[0] == 'mix_column_0_23_0_i'
    assert variables[1] == 'mix_column_0_23_1_i'
    assert variables[-2] == 'mix_column_0_23_14_o'
    assert variables[-1] == 'mix_column_0_23_15_o'

    assert constraints[0] == '(assert (= mix_column_0_23_0_i dummy_0_mix_column_0_23_4_o ' \
                             'dummy_0_mix_column_0_23_8_o dummy_0_mix_column_0_23_12_o))'
    assert constraints[1] == '(assert (= mix_column_0_23_1_i dummy_1_mix_column_0_23_5_o dummy_1_' \
                             'mix_column_0_23_9_o dummy_1_mix_column_0_23_13_o))'
    assert constraints[-2] == '(assert (= mix_column_0_23_14_o (xor dummy_2_mix_column_0_23_14_o ' \
                              'dummy_6_mix_column_0_23_14_o dummy_10_mix_column_0_23_14_o)))'
    assert constraints[-1] == '(assert (= mix_column_0_23_15_o (xor dummy_3_mix_column_0_23_15_o ' \
                              'dummy_7_mix_column_0_23_15_o dummy_11_mix_column_0_23_15_o)))'
