from claasp.components.shift_component import SHIFT
from claasp.cipher_modules.models.cp.cp_model import CpModel
from claasp.cipher_modules.models.milp.milp_model import MilpModel
from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
from claasp.cipher_modules.models.minizinc.minizinc_model import MinizincModel
from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import \
    MilpBitwiseDeterministicTruncatedXorDifferentialModel
from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import \
    MilpWordwiseDeterministicTruncatedXorDifferentialModel
def test_algebraic_polynomials():
    fancy = FancyBlockCipher(number_of_rounds=2)
    shift_component = fancy.get_component_from_id("shift_1_12")
    algebraic = AlgebraicModel(fancy)
    algebraic_polynomials = shift_component.algebraic_polynomials(algebraic)

    assert str(algebraic_polynomials) == '[shift_1_12_y0,' \
                                         ' shift_1_12_y1,' \
                                         ' shift_1_12_y2,' \
                                         ' shift_1_12_y3 + shift_1_12_x0,' \
                                         ' shift_1_12_y4 + shift_1_12_x1,' \
                                         ' shift_1_12_y5 + shift_1_12_x2]'


def test_cms_constraints():
    tea = TeaBlockCipher(number_of_rounds=3)
    shift_component = tea.component_from(0, 0)
    output_bit_ids, constraints = shift_component.cms_constraints()

    assert output_bit_ids[0] == 'shift_0_0_0'
    assert output_bit_ids[1] == 'shift_0_0_1'
    assert output_bit_ids[2] == 'shift_0_0_2'

    assert constraints[-3] == '-shift_0_0_29'
    assert constraints[-2] == '-shift_0_0_30'
    assert constraints[-1] == '-shift_0_0_31'


def test_cp_constraints():
    tea = TeaBlockCipher(number_of_rounds=3)
    shift_component = tea.component_from(0, 0)
    declarations, constraints = shift_component.cp_constraints()

    assert declarations == []

    assert constraints[0] == 'constraint shift_0_0[0] = plaintext[36];'
    assert constraints[-5] == 'constraint shift_0_0[27] = plaintext[63];'
    assert constraints[-4] == 'constraint shift_0_0[28] = 0;'
    assert constraints[-3] == 'constraint shift_0_0[29] = 0;'
    assert constraints[-2] == 'constraint shift_0_0[30] = 0;'
    assert constraints[-1] == 'constraint shift_0_0[31] = 0;'


def test_cp_inverse_constraints():
    tea = TeaBlockCipher(number_of_rounds=3)
    shift_component = tea.component_from(0, 0)
    declarations, constraints = shift_component.cp_inverse_constraints()

    assert declarations == []

    assert constraints[0] == 'constraint shift_0_0_inverse[0] = plaintext[36];'
    assert constraints[-1] == 'constraint shift_0_0_inverse[31] = 0;'


def test_cp_wordwise_deterministic_truncated_xor_differential_constraints():
    aes = AESBlockCipher(number_of_rounds=3)
    cp = CpModel(aes)
    shift_component = SHIFT(0, 18, ['sbox_0_2', 'sbox_0_6', 'sbox_0_10', 'sbox_0_14'],
                            [[0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7],
                             [0, 1, 2, 3, 4, 5, 6, 7]], 32, -8)
    declarations, constraints = shift_component.cp_wordwise_deterministic_truncated_xor_differential_constraints(cp)

    assert declarations == []

    assert constraints[0] == 'constraint shift_0_18_active[0] = sbox_0_6_active[0];'
    assert constraints[-1] == 'constraint shift_0_18_value[3] = 0;'


def test_cp_xor_differential_first_step_constraints():
    aes = AESBlockCipher(number_of_rounds=3)
    cp = CpModel(aes)
    shift_component = SHIFT(0, 18, ['sbox_0_2', 'sbox_0_6', 'sbox_0_10', 'sbox_0_14'],
                            [[0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7],
                             [0, 1, 2, 3, 4, 5, 6, 7]], 32, -8)
    declarations, constraints = shift_component.cp_xor_differential_first_step_constraints(cp)

    assert declarations == ['array[0..3] of var 0..1: shift_0_18;']

    assert constraints == ['constraint shift_0_18[0] = sbox_0_6[0];',
                           'constraint shift_0_18[1] = sbox_0_10[0];',
                           'constraint shift_0_18[2] = sbox_0_14[0];',
                           'constraint shift_0_18[3] = 0;']


def test_cp_xor_linear_mask_propagation_constraints():
    tea = TeaBlockCipher(number_of_rounds=3)
    shift_component = tea.component_from(0, 0)
    declarations, constraints = shift_component.cp_xor_linear_mask_propagation_constraints()

    assert declarations == ['array[0..31] of var 0..1: shift_0_0_i;', 'array[0..31] of var 0..1: shift_0_0_o;']

    assert constraints[0] == 'constraint shift_0_0_o[0]=shift_0_0_i[4];'
    assert constraints[1] == 'constraint shift_0_0_o[1]=shift_0_0_i[5];'
    assert constraints[-1] == 'constraint shift_0_0_i[3]=0;'


def test_milp_constraints():
    tea = TeaBlockCipher(block_bit_size=16, key_bit_size=32, number_of_rounds=2)
    milp = MilpModel(tea)
    milp.init_model_in_sage_milp_class()
    shift_component = tea.get_component_from_id("shift_0_0")
    variables, constraints = shift_component.milp_constraints(milp)

    assert str(variables[0]) == "('x[plaintext_8]', x_0)"
    assert str(variables[1]) == "('x[plaintext_9]', x_1)"
    assert str(variables[-2]) == "('x[shift_0_0_6]', x_14)"
    assert str(variables[-1]) == "('x[shift_0_0_7]', x_15)"

    assert str(constraints) == '[x_8 == x_4, x_9 == x_5, x_10 == x_6, x_11 == x_7,' \
                               ' x_12 == 0, x_13 == 0, x_14 == 0, x_15 == 0]'


def test_milp_xor_linear_mask_propagation_constraints():
    tea = TeaBlockCipher(block_bit_size=16, key_bit_size=32, number_of_rounds=2)
    milp = MilpModel(tea)
    milp.init_model_in_sage_milp_class()
    shift_component = tea.get_component_from_id("shift_0_0")
    variables, constraints = shift_component.milp_xor_linear_mask_propagation_constraints(milp)

    assert str(variables[0]) == "('x[shift_0_0_0_i]', x_0)"
    assert str(variables[1]) == "('x[shift_0_0_1_i]', x_1)"
    assert str(variables[-2]) == "('x[shift_0_0_6_o]', x_14)"
    assert str(variables[-1]) == "('x[shift_0_0_7_o]', x_15)"

    assert str(constraints) == '[x_0 == 0, x_1 == 0, x_2 == 0, x_3 == 0, ' \
                               'x_8 == x_4, x_9 == x_5, x_10 == x_6, x_11 == x_7]'


def test_minizinc_constraints():
    tea = TeaBlockCipher(number_of_rounds=32)
    minizinc = MinizincModel(tea)
    shift_component = tea.get_component_from_id("shift_0_0")
    _, shift_mzn_constraints = shift_component.minizinc_constraints(minizinc)

    assert shift_mzn_constraints[0] == 'constraint LSHIFT(array1d(0..32-1, [shift_0_0_x0,shift_0_0_x1,shift_0_0_x2,' \
                                       'shift_0_0_x3,shift_0_0_x4,shift_0_0_x5,shift_0_0_x6,shift_0_0_x7,' \
                                       'shift_0_0_x8,shift_0_0_x9,shift_0_0_x10,shift_0_0_x11,shift_0_0_x12,' \
                                       'shift_0_0_x13,shift_0_0_x14,shift_0_0_x15,shift_0_0_x16,shift_0_0_x17,' \
                                       'shift_0_0_x18,shift_0_0_x19,shift_0_0_x20,shift_0_0_x21,shift_0_0_x22,' \
                                       'shift_0_0_x23,shift_0_0_x24,shift_0_0_x25,shift_0_0_x26,shift_0_0_x27,' \
                                       'shift_0_0_x28,shift_0_0_x29,shift_0_0_x30,shift_0_0_x31]), 4)=' \
                                       'array1d(0..32-1, [shift_0_0_y0,shift_0_0_y1,shift_0_0_y2,shift_0_0_y3,' \
                                       'shift_0_0_y4,shift_0_0_y5,shift_0_0_y6,shift_0_0_y7,shift_0_0_y8,' \
                                       'shift_0_0_y9,shift_0_0_y10,shift_0_0_y11,shift_0_0_y12,shift_0_0_y13,' \
                                       'shift_0_0_y14,shift_0_0_y15,shift_0_0_y16,shift_0_0_y17,shift_0_0_y18,' \
                                       'shift_0_0_y19,shift_0_0_y20,shift_0_0_y21,shift_0_0_y22,shift_0_0_y23,' \
                                       'shift_0_0_y24,shift_0_0_y25,shift_0_0_y26,shift_0_0_y27,shift_0_0_y28,' \
                                       'shift_0_0_y29,shift_0_0_y30,shift_0_0_y31]);\n'


def test_sat_constraints():
    tea = TeaBlockCipher(number_of_rounds=3)
    shift_component = tea.component_from(0, 0)
    output_bit_ids, constraints = shift_component.sat_constraints()

    assert output_bit_ids[0] == 'shift_0_0_0'
    assert output_bit_ids[1] == 'shift_0_0_1'
    assert output_bit_ids[2] == 'shift_0_0_2'

    assert constraints[-3] == '-shift_0_0_29'
    assert constraints[-2] == '-shift_0_0_30'
    assert constraints[-1] == '-shift_0_0_31'


def test_sat_xor_linear_mask_propagation_constraints():
    tea = TeaBlockCipher(number_of_rounds=3)
    shift_component = tea.component_from(0, 0)
    output_bit_ids, constraints = shift_component.sat_xor_linear_mask_propagation_constraints()

    assert output_bit_ids[0] == 'shift_0_0_0_i'
    assert output_bit_ids[1] == 'shift_0_0_1_i'
    assert output_bit_ids[2] == 'shift_0_0_2_i'

    assert constraints[-3] == 'shift_0_0_30_i -shift_0_0_26_o'
    assert constraints[-2] == 'shift_0_0_27_o -shift_0_0_31_i'
    assert constraints[-1] == 'shift_0_0_31_i -shift_0_0_27_o'


def test_smt_constraints():
    tea = TeaBlockCipher(number_of_rounds=3)
    shift_component = tea.component_from(0, 0)
    output_bit_ids, constraints = shift_component.smt_constraints()

    assert output_bit_ids[0] == 'shift_0_0_0'
    assert output_bit_ids[1] == 'shift_0_0_1'
    assert output_bit_ids[-2] == 'shift_0_0_30'
    assert output_bit_ids[-1] == 'shift_0_0_31'

    assert constraints[0] == '(assert (= shift_0_0_0 plaintext_36))'
    assert constraints[1] == '(assert (= shift_0_0_1 plaintext_37))'
    assert constraints[-5] == '(assert (= shift_0_0_27 plaintext_63))'
    assert constraints[-4] == '(assert (not shift_0_0_28))'
    assert constraints[-3] == '(assert (not shift_0_0_29))'
    assert constraints[-2] == '(assert (not shift_0_0_30))'
    assert constraints[-1] == '(assert (not shift_0_0_31))'

    tea = TeaBlockCipher(number_of_rounds=3)
    shift_component = tea.component_from(0, 4)
    output_bit_ids, constraints = shift_component.smt_constraints()

    assert output_bit_ids[0] == 'shift_0_4_0'
    assert output_bit_ids[1] == 'shift_0_4_1'
    assert output_bit_ids[-2] == 'shift_0_4_30'
    assert output_bit_ids[-1] == 'shift_0_4_31'

    assert constraints[0] == '(assert (not shift_0_4_0))'
    assert constraints[1] == '(assert (not shift_0_4_1))'
    assert constraints[2] == '(assert (not shift_0_4_2))'
    assert constraints[3] == '(assert (not shift_0_4_3))'
    assert constraints[4] == '(assert (not shift_0_4_4))'
    assert constraints[5] == '(assert (= shift_0_4_5 plaintext_32))'
    assert constraints[-2] == '(assert (= shift_0_4_30 plaintext_57))'
    assert constraints[-1] == '(assert (= shift_0_4_31 plaintext_58))'


def test_smt_xor_linear_mask_propagation_constraints():
    tea = TeaBlockCipher(number_of_rounds=3)
    shift_component = tea.component_from(0, 0)
    output_bit_ids, constraints = shift_component.smt_xor_linear_mask_propagation_constraints()

    assert output_bit_ids[0] == 'shift_0_0_0_i'
    assert output_bit_ids[1] == 'shift_0_0_1_i'
    assert output_bit_ids[-2] == 'shift_0_0_30_o'
    assert output_bit_ids[-1] == 'shift_0_0_31_o'

    assert constraints[0] == '(assert (not shift_0_0_0_i))'
    assert constraints[1] == '(assert (not shift_0_0_1_i))'
    assert constraints[-2] == '(assert (= shift_0_0_26_o shift_0_0_30_i))'
    assert constraints[-1] == '(assert (= shift_0_0_27_o shift_0_0_31_i))'

    tea = TeaBlockCipher(block_bit_size=64, key_bit_size=128, number_of_rounds=32)
    shift_component = tea.component_from(0, 4)
    output_bit_ids, constraints = shift_component.smt_xor_linear_mask_propagation_constraints()

    assert output_bit_ids[0] == 'shift_0_4_0_i'
    assert output_bit_ids[1] == 'shift_0_4_1_i'
    assert output_bit_ids[-2] == 'shift_0_4_30_o'
    assert output_bit_ids[-1] == 'shift_0_4_31_o'

    assert constraints[0] == '(assert (= shift_0_4_5_o shift_0_4_0_i))'
    assert constraints[1] == '(assert (= shift_0_4_6_o shift_0_4_1_i))'
    assert constraints[-2] == '(assert (not shift_0_4_30_i))'
    assert constraints[-1] == '(assert (not shift_0_4_31_i))'


def test_milp_bitwise_deterministic_truncated_xor_differential_constraints():
    cipher = TeaBlockCipher(block_bit_size=16, key_bit_size=32, number_of_rounds=2)
    milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
    milp.init_model_in_sage_milp_class()
    shift_component = cipher.get_component_from_id("shift_0_0")
    variables, constraints = shift_component.milp_bitwise_deterministic_truncated_xor_differential_constraints(milp)

    assert str(variables[0]) == "('x_class[plaintext_8]', x_0)"
    assert str(variables[1]) == "('x_class[plaintext_9]', x_1)"
    assert str(variables[-2]) == "('x_class[shift_0_0_6]', x_14)"
    assert str(variables[-1]) == "('x_class[shift_0_0_7]', x_15)"

    assert str(constraints[0]) == "x_8 == x_4"
    assert str(constraints[1]) == "x_9 == x_5"
    assert str(constraints[-2]) == "x_14 == 0"
    assert str(constraints[-1]) == "x_15 == 0"

def test_milp_wordwise_deterministic_truncated_xor_differential_constraints():
    cipher = AESBlockCipher(number_of_rounds=3)
    milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(cipher)
    milp.init_model_in_sage_milp_class()
    shift_component = SHIFT(0, 18, ['sbox_0_2', 'sbox_0_6', 'sbox_0_10', 'sbox_0_14'],
                                  [[0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7],
                                   [0, 1, 2, 3, 4, 5, 6, 7]], 32, -8)
    variables, constraints = shift_component.milp_wordwise_deterministic_truncated_xor_differential_constraints(
        milp)

    assert str(variables[0]) == "('x_class[sbox_0_2_word_0_class]', x_0)"
    assert str(variables[1]) == "('x_class[sbox_0_6_word_0_class]', x_1)"
    assert str(variables[-2]) == "('x[shift_0_18_30]', x_70)"
    assert str(variables[-1]) == "('x[shift_0_18_31]', x_71)"

    assert str(constraints[0]) == "x_4 == x_1"
    assert str(constraints[1]) == "x_5 == x_2"
    assert str(constraints[-2]) == "x_70 == 0"
    assert str(constraints[-1]) == "x_71 == 0"