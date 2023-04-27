from claasp.cipher_modules.models.cp.cp_model import CpModel
from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
from claasp.components.xor_component import cp_build_truncated_table, generic_with_constant_sign_linear_constraints


def test_cp_build_truncated_table():
    assert cp_build_truncated_table(3) == 'array[0..4, 1..3] of int: xor_truncated_table_3 = ' \
                                          'array2d(0..4, 1..3, [0,0,0,0,1,1,1,0,1,1,1,0,1,1,1]);'


def test_generic_with_constant_sign_linear_constraints():
    constant = [0, 1, 1, 0, 0, 1, 1, 0]
    const_mask = [0, 1, 0, 1, 1, 0, 0, 0]
    input_bit_positions = [0, 1, 2, 3, 4, 5, 6, 7]

    assert generic_with_constant_sign_linear_constraints(constant, const_mask, input_bit_positions) == -1


def test_algebraic_polynomials():
    fancy = FancyBlockCipher(number_of_rounds=1)
    xor_component = fancy.get_component_from_id("xor_0_7")
    algebraic = AlgebraicModel(fancy)
    algebraic_polynomials = xor_component.algebraic_polynomials(algebraic)

    assert str(algebraic_polynomials) == '[xor_0_7_y0 + xor_0_7_x12 + xor_0_7_x0,' \
                                         ' xor_0_7_y1 + xor_0_7_x13 + xor_0_7_x1,' \
                                         ' xor_0_7_y2 + xor_0_7_x14 + xor_0_7_x2,' \
                                         ' xor_0_7_y3 + xor_0_7_x15 + xor_0_7_x3,' \
                                         ' xor_0_7_y4 + xor_0_7_x16 + xor_0_7_x4,' \
                                         ' xor_0_7_y5 + xor_0_7_x17 + xor_0_7_x5,' \
                                         ' xor_0_7_y6 + xor_0_7_x18 + xor_0_7_x6,' \
                                         ' xor_0_7_y7 + xor_0_7_x19 + xor_0_7_x7,' \
                                         ' xor_0_7_y8 + xor_0_7_x20 + xor_0_7_x8,' \
                                         ' xor_0_7_y9 + xor_0_7_x21 + xor_0_7_x9,' \
                                         ' xor_0_7_y10 + xor_0_7_x22 + xor_0_7_x10,' \
                                         ' xor_0_7_y11 + xor_0_7_x23 + xor_0_7_x11]'

    fancy = FancyBlockCipher(number_of_rounds=2)
    xor_component = fancy.get_component_from_id("xor_1_13")
    algebraic = AlgebraicModel(fancy)
    algebraic_polynomials = xor_component.algebraic_polynomials(algebraic)
    assert str(algebraic_polynomials) == '[xor_1_13_y0 + xor_1_13_x12 + xor_1_13_x6 + xor_1_13_x0,' \
                                         ' xor_1_13_y1 + xor_1_13_x13 + xor_1_13_x7 + xor_1_13_x1,' \
                                         ' xor_1_13_y2 + xor_1_13_x14 + xor_1_13_x8 + xor_1_13_x2,' \
                                         ' xor_1_13_y3 + xor_1_13_x15 + xor_1_13_x9 + xor_1_13_x3,' \
                                         ' xor_1_13_y4 + xor_1_13_x16 + xor_1_13_x10 + xor_1_13_x4,' \
                                         ' xor_1_13_y5 + xor_1_13_x17 + xor_1_13_x11 + xor_1_13_x5]'


def test_cp_wordwise_deterministic_truncated_xor_differential_constraints():
    aes = AESBlockCipher(number_of_rounds=5)
    cp = CpModel(aes)
    xor_component = aes.component_from(0, 0)
    declarations, constraints = xor_component.cp_wordwise_deterministic_truncated_xor_differential_constraints(cp)

    assert declarations == []

    assert constraints[0] == 'constraint temp_0_0_value = key_value[0] /\\ temp_0_0_active = key_active[0];'
    assert constraints[-1] == 'constraint if temp_0_15_active + temp_1_15_active > 2 then xor_0_0_active[15] == 3 /\\' \
                              ' xor_0_0_value[15] = -2 elif temp_0_15_active + temp_1_15_active == 1 then ' \
                              'xor_0_0_active[15] = 1 /\\ xor_0_0_value[15] = temp_0_15_value + temp_1_15_value elif ' \
                              'temp_0_15_active + temp_1_15_active == 0 then xor_0_0_active[15] = 0 /\\ ' \
                              'xor_0_0_value[15] = 0 elif temp_0_15_value + temp_1_15_value < 0 then ' \
                              'xor_0_0_active[15] = 2 /\\ xor_0_0_value[15] = -1 elif temp_0_15_value == ' \
                              'temp_1_15_value then xor_0_0_active[15] = 0 /\\ xor_0_0_value[15] = 0 else ' \
                              'xor_0_0_active[15] = 1 /\\ xor_0_0_value[15] = sum[(((floor(temp_0_15_value/(2**j)) + ' \
                              'floor(temp_1_15_value/(2**j))) mod 2) * (2**j)) | j in 0..log2(temp_0_15_value + ' \
                              'temp_1_15_value)] endif;'


def test_cp_xor_differential_propagation_first_step_constraints():
    aes = AESBlockCipher(number_of_rounds=3)
    cp = CpModel(aes)
    xor_component = aes.component_from(2, 31)
    declarations, constraints = xor_component.cp_xor_differential_propagation_first_step_constraints(cp,
                                                                                                     cp._variables_list)

    assert declarations == ['array[0..1, 1..2] of int: xor_truncated_table_2 = array2d(0..1, 1..2, [0,0,1,1]);']

    assert constraints == 'constraint table([rot_2_16[0]]++[xor_2_26[0]], xor_truncated_table_2);'


def test_smt_constraints():
    speck = SpeckBlockCipher(number_of_rounds=3)
    xor_component = speck.component_from(0, 2)
    output_bit_ids, constraints = xor_component.smt_constraints()

    assert output_bit_ids[0] == 'xor_0_2_0'
    assert output_bit_ids[1] == 'xor_0_2_1'
    assert output_bit_ids[-2] == 'xor_0_2_14'
    assert output_bit_ids[-1] == 'xor_0_2_15'

    assert constraints[0] == '(assert (= xor_0_2_0 (xor modadd_0_1_0 key_48)))'
    assert constraints[1] == '(assert (= xor_0_2_1 (xor modadd_0_1_1 key_49)))'
    assert constraints[-2] == '(assert (= xor_0_2_14 (xor modadd_0_1_14 key_62)))'
    assert constraints[-1] == '(assert (= xor_0_2_15 (xor modadd_0_1_15 key_63)))'
