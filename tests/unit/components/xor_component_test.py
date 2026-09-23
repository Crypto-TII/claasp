from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
from claasp.cipher_modules.models.cp.mzn_model import MznModel
from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import (
    MilpBitwiseDeterministicTruncatedXorDifferentialModel,
)
from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import (
    MilpWordwiseDeterministicTruncatedXorDifferentialModel,
)
from claasp.ciphers.single_component_ciphers.xor_cipher import XorCipher
from claasp.components.xor_component import Xor, cp_build_truncated_table, generic_with_constant_sign_linear_constraints
from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import (
    SmtXorQuasidifferentialModel,
)

def test_cp_build_truncated_table():
    assert cp_build_truncated_table(3) == 'array[0..4, 1..3] of int: xor_truncated_table_3 = ' \
                                          'array2d(0..4, 1..3, [0,0,0,0,1,1,1,0,1,1,1,0,1,1,1]);'


def test_generic_with_constant_sign_linear_constraints():
    constant = [0, 1, 1, 0, 0, 1, 1, 0]
    const_mask = [0, 1, 0, 1, 1, 0, 0, 0]
    input_bit_positions = [0, 1, 2, 3, 4, 5, 6, 7]

    assert generic_with_constant_sign_linear_constraints(constant, const_mask, input_bit_positions) == -1


def test_algebraic_polynomials():
    cipher = XorCipher(word_bit_size=12, number_of_inputs=2)
    xor_component = cipher.component_from_id("xor_0_0")
    algebraic = AlgebraicModel(cipher)
    algebraic_polynomials = xor_component.algebraic_polynomials(algebraic)

    assert str(algebraic_polynomials) == '[xor_0_0_y0 + xor_0_0_x12 + xor_0_0_x0,' \
                                         ' xor_0_0_y1 + xor_0_0_x13 + xor_0_0_x1,' \
                                         ' xor_0_0_y2 + xor_0_0_x14 + xor_0_0_x2,' \
                                         ' xor_0_0_y3 + xor_0_0_x15 + xor_0_0_x3,' \
                                         ' xor_0_0_y4 + xor_0_0_x16 + xor_0_0_x4,' \
                                         ' xor_0_0_y5 + xor_0_0_x17 + xor_0_0_x5,' \
                                         ' xor_0_0_y6 + xor_0_0_x18 + xor_0_0_x6,' \
                                         ' xor_0_0_y7 + xor_0_0_x19 + xor_0_0_x7,' \
                                         ' xor_0_0_y8 + xor_0_0_x20 + xor_0_0_x8,' \
                                         ' xor_0_0_y9 + xor_0_0_x21 + xor_0_0_x9,' \
                                         ' xor_0_0_y10 + xor_0_0_x22 + xor_0_0_x10,' \
                                         ' xor_0_0_y11 + xor_0_0_x23 + xor_0_0_x11]'

    cipher = XorCipher(word_bit_size=6, number_of_inputs=3)
    xor_component = cipher.component_from_id("xor_0_0")
    algebraic = AlgebraicModel(cipher)
    algebraic_polynomials = xor_component.algebraic_polynomials(algebraic)
    assert str(algebraic_polynomials) == '[xor_0_0_y0 + xor_0_0_x12 + xor_0_0_x6 + xor_0_0_x0,' \
                                         ' xor_0_0_y1 + xor_0_0_x13 + xor_0_0_x7 + xor_0_0_x1,' \
                                         ' xor_0_0_y2 + xor_0_0_x14 + xor_0_0_x8 + xor_0_0_x2,' \
                                         ' xor_0_0_y3 + xor_0_0_x15 + xor_0_0_x9 + xor_0_0_x3,' \
                                         ' xor_0_0_y4 + xor_0_0_x16 + xor_0_0_x10 + xor_0_0_x4,' \
                                         ' xor_0_0_y5 + xor_0_0_x17 + xor_0_0_x11 + xor_0_0_x5]'


def test_cp_xor_differential_propagation_first_step_constraints():
    cipher = XorCipher(word_bit_size=8, number_of_inputs=2)
    cp = MznModel(cipher)
    cp.word_size = 8
    xor_component = cipher.component_from_id("xor_0_0")
    declarations, constraints = xor_component.cp_xor_differential_propagation_first_step_constraints(
        cp,
        cp._variables_declarations,
    )

    assert declarations == ['array[0..1, 1..2] of int: xor_truncated_table_2 = array2d(0..1, 1..2, [0,0,1,1]);']

    assert constraints == 'constraint table([plaintext[0]]++[key[0]], xor_truncated_table_2);'


def test_cp_xor_differential_propagation_first_step_constraints_truncates_partial_word():
    cipher = XorCipher(word_bit_size=5, number_of_inputs=2)
    cp = MznModel(cipher)
    cp.word_size = 4
    xor_component = cipher.component_from_id("xor_0_0")

    declarations, constraints = xor_component.cp_xor_differential_propagation_first_step_constraints(
        cp,
        cp._variables_declarations,
    )

    assert declarations == [
        "array[0..1, 1..2] of int: xor_truncated_table_2 = array2d(0..1, 1..2, [0,0,1,1]);"
    ]
    assert constraints == "constraint table([plaintext[0]]++[key[0]], xor_truncated_table_2);"


def test_smt_constraints():
    component = Xor(0, 0, ['plaintext', 'key'], [list(range(2)), list(range(2))], 2)
    output_bit_ids, constraints = component.smt_constraints()

    assert output_bit_ids[0] == 'xor_0_0_0'
    assert output_bit_ids[1] == 'xor_0_0_1'

    assert constraints[0] == '(assert (= xor_0_0_0 (xor plaintext_0 key_0)))'
    assert constraints[1] == '(assert (= xor_0_0_1 (xor plaintext_1 key_1)))'

def test_milp_bitwise_deterministic_truncated_xor_differential_binary_constraints():
    cipher = XorCipher(word_bit_size=16, number_of_inputs=2)
    milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
    milp.init_model_in_sage_milp_class()
    xor_component = cipher.component_from_id("xor_0_0")
    variables, constraints = xor_component.milp_bitwise_deterministic_truncated_xor_differential_binary_constraints(milp)

    assert str(variables[0]) == "('x[plaintext_0_class_bit_0]', x_0)"
    assert str(variables[1]) == "('x[plaintext_0_class_bit_1]', x_1)"
    assert str(variables[-2]) == "('x[xor_0_0_15_class_bit_0]', x_94)"
    assert str(variables[-1]) == "('x[xor_0_0_15_class_bit_1]', x_95)"

    assert str(constraints[0]) == 'x_96 == 2*x_0 + x_1'
    assert str(constraints[1]) == 'x_97 == 2*x_2 + x_3'
    assert str(constraints[-2]) == '1 <= 1 - x_30 + x_94'
    assert str(constraints[-1]) == '1 <= 2 - x_62 - x_63'


def test_milp_bitwise_deterministic_truncated_xor_differential_constraints():
    cipher = XorCipher(word_bit_size=16, number_of_inputs=2)
    milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
    milp.init_model_in_sage_milp_class()
    xor_component = cipher.component_from_id("xor_0_0")
    variables, constraints = xor_component.milp_bitwise_deterministic_truncated_xor_differential_constraints(milp)

    assert str(variables[0]) == "('x_class[plaintext_0]', x_0)"
    assert str(variables[1]) == "('x_class[plaintext_1]', x_1)"
    assert str(variables[-2]) == "('x_class[xor_0_0_14]', x_46)"
    assert str(variables[-1]) == "('x_class[xor_0_0_15]', x_47)"

    assert str(constraints[0]) == 'x_0 <= 3 - 2*x_48'
    assert str(constraints[1]) == '2 - 2*x_48 <= x_0'
    assert str(constraints[-2]) == 'x_47 <= 2 + 4*x_95'
    assert str(constraints[-1]) == '2 <= x_47 + 4*x_95'


def test_milp_wordwise_deterministic_truncated_xor_differential_constraints():
    cipher = XorCipher(word_bit_size=8, number_of_inputs=2)
    milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(cipher)
    milp.init_model_in_sage_milp_class()
    milp._word_size = 8
    xor_component = cipher.component_from_id("xor_0_0")
    variables, constraints = xor_component.milp_wordwise_deterministic_truncated_xor_differential_constraints(milp)

    assert str(variables[0]) == "('x[plaintext_word_0_class_bit_0]', x_0)"
    assert str(variables[1]) == "('x[plaintext_word_0_class_bit_1]', x_1)"
    assert str(variables[-2]) == "('x[xor_0_0_6]', x_28)"
    assert str(variables[-1]) == "('x[xor_0_0_7]', x_29)"

    assert str(constraints[0]) == '1 <= 1 + x_0 + x_2 + x_3 + x_4 + x_5 + x_6 + x_7 + x_8 + x_9 + x_11 - x_21'
    assert str(constraints[1]) == '1 <= 1 + x_1 + x_10 + x_12 + x_13 + x_14 + x_15 + x_16 + x_17 + x_18 + x_19 - x_21'
    assert str(constraints[-2]) == '1 <= 1 + x_1 - x_9'
    assert str(constraints[-1]) == '1 <= 2 - x_0 - x_9'


def test_milp_wordwise_deterministic_truncated_xor_differential_sequential_constraints():
    cipher = XorCipher(word_bit_size=8, number_of_inputs=2)
    milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(cipher)
    milp.init_model_in_sage_milp_class()
    milp._word_size = 8
    xor_component = cipher.component_from_id("xor_0_0")
    variables, constraints = xor_component.milp_wordwise_deterministic_truncated_xor_differential_sequential_constraints(milp)

    assert str(variables[0]) == "('x[plaintext_word_0_class_bit_0]', x_0)"
    assert str(variables[1]) == "('x[plaintext_word_0_class_bit_1]', x_1)"
    assert str(variables[-2]) == "('x[xor_0_0_6]', x_28)"
    assert str(variables[-1]) == "('x[xor_0_0_7]', x_29)"

    assert str(constraints[0]) == '1 <= 1 + x_0 + x_2 + x_3 + x_4 + x_5 + x_6 + x_7 + x_8 + x_9 + x_11 - x_21'
    assert str(constraints[1]) == '1 <= 1 + x_1 + x_10 + x_12 + x_13 + x_14 + x_15 + x_16 + x_17 + x_18 + x_19 - x_21'
    assert str(constraints[-2]) == '1 <= 1 + x_1 - x_9'
    assert str(constraints[-1]) == '1 <= 2 - x_0 - x_9'


def test_milp_wordwise_deterministic_truncated_xor_differential_simple_constraints():
    cipher = XorCipher(word_bit_size=8, number_of_inputs=2)
    milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(cipher)
    milp.init_model_in_sage_milp_class()
    milp._word_size = 8
    xor_component = cipher.component_from_id("xor_0_0")
    variables, constraints = xor_component.milp_wordwise_deterministic_truncated_xor_differential_simple_constraints(milp)

    assert str(variables[0]) == "('x_class[plaintext_word_0_class]', x_0)"
    assert str(variables[1]) == "('x_class[key_word_0_class]', x_1)"
    assert str(variables[-2]) == "('x_class[key_word_0_class]', x_1)"
    assert str(variables[-1]) == "('x_class[xor_0_0_word_0_class]', x_2)"

    assert str(constraints[0]) == '2 <= 7 + x_0 + x_1 - 7*x_3'
    assert str(constraints[1]) == '1 + x_0 + x_1 - 7*x_3 <= 2'
    assert str(constraints[-2]) == 'x_2 <= 2 + 6*x_6 + 6*x_7'
    assert str(constraints[-1]) == '2 <= x_2 + 6*x_6 + 6*x_7'

def test_smt_xor_quasidifferential_propagation_constraints():
    cipher = XorCipher(word_bit_size=2, number_of_inputs=2)
    model = SmtXorQuasidifferentialModel(cipher)
    xor_component = cipher.component_from(0, 0)
    variables, constraints = xor_component.smt_xor_quasidifferential_propagation_constraints(model)

    assert variables == ['xor_0_0_0', 'xor_0_0_1', 'qdt_xor_0_0_0', 'qdt_xor_0_0_1']

    assert constraints == ['(assert (= xor_0_0_0 (xor plaintext_0 key_0)))',
                           '(assert (= xor_0_0_1 (xor plaintext_1 key_1)))',
                           '(assert (= qdt_plaintext_0 qdt_xor_0_0_0))',
                           '(assert (= qdt_key_0 qdt_xor_0_0_0))',
                           '(assert (= qdt_plaintext_1 qdt_xor_0_0_1))',
                           '(assert (= qdt_key_1 qdt_xor_0_0_1))']