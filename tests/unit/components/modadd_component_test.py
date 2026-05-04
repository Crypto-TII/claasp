from claasp.ciphers.single_component_ciphers.modadd_cipher import ModaddCipher
from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import \
    MilpBitwiseDeterministicTruncatedXorDifferentialModel


def test_algebraic_polynomials():
    cipher = ModaddCipher(word_bit_size=6, number_of_inputs=3)
    modadd_component = cipher.component_from_id("modadd_0_0")
    algebraic = AlgebraicModel(cipher)
    algebraic_polynomials = modadd_component.algebraic_polynomials(algebraic)

    assert str(algebraic_polynomials[0]) == "modadd_0_0_c0_0"
    assert str(algebraic_polynomials[1]) == "modadd_0_0_o0_0 + modadd_0_0_c0_0 + modadd_0_0_x6 + modadd_0_0_x0"
    assert str(algebraic_polynomials[-2]) == "modadd_0_0_o0_4*modadd_0_0_c1_4 + modadd_0_0_x16*modadd_0_0_c1_4 + modadd_0_0_x16*modadd_0_0_o0_4 + modadd_0_0_c1_5"
    assert str(algebraic_polynomials[-1]) == "modadd_0_0_c1_5 + modadd_0_0_o0_5 + modadd_0_0_y5 + modadd_0_0_x17"

def test_milp_bitwise_deterministic_truncated_xor_differential_binary_constraints():
    cipher = ModaddCipher(word_bit_size=16, number_of_inputs=2)
    milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
    milp.init_model_in_sage_milp_class()
    modadd_component = cipher.component_from_id("modadd_0_0")
    variables, constraints = modadd_component.milp_bitwise_deterministic_truncated_xor_differential_binary_constraints(milp)

    assert str(variables[0]) == "('x[plaintext_0_class_bit_0]', x_0)"
    assert str(variables[1]) == "('x[plaintext_0_class_bit_1]', x_1)"
    assert str(variables[-2]) == "('x[modadd_0_0_15_class_bit_0]', x_94)"
    assert str(variables[-1]) == "('x[modadd_0_0_15_class_bit_1]', x_95)"

    assert str(constraints[0]) == 'x_96 == 2*x_0 + x_1'
    assert str(constraints[1]) == 'x_97 == 2*x_2 + x_3'
    assert str(constraints[-2]) == '1 <= 18 - x_30 + x_94 - 17*x_159'
    assert str(constraints[-1]) == '1 <= 19 - x_62 - x_63 - 17*x_159'

def test_milp_bitwise_deterministic_truncated_xor_differential_constraints():
    cipher = ModaddCipher(word_bit_size=16, number_of_inputs=2)
    milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
    milp.init_model_in_sage_milp_class()
    modadd_component = cipher.component_from_id("modadd_0_0")
    variables, constraints = modadd_component.milp_bitwise_deterministic_truncated_xor_differential_constraints(milp)

    assert str(variables[0]) == "('x_class[plaintext_0]', x_0)"
    assert str(variables[1]) == "('x_class[plaintext_1]', x_1)"
    assert str(variables[-2]) == "('x_class[modadd_0_0_14]', x_46)"
    assert str(variables[-1]) == "('x_class[modadd_0_0_15]', x_47)"

    assert str(constraints[0]) == 'x_48 <= 15'
    assert str(constraints[1]) == '0 <= x_48'
    assert str(constraints[-2]) == '2 <= 4 + x_47 - 4*x_157 + 4*x_160'
    assert str(constraints[-1]) == 'x_157 <= x_15 + x_31'