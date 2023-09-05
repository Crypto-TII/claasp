from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import \
    MilpBitwiseDeterministicTruncatedXorDifferentialModel


def test_algebraic_polynomials():
    fancy = FancyBlockCipher(number_of_rounds=2)
    modadd_component = fancy.get_component_from_id("modadd_1_9")
    algebraic = AlgebraicModel(fancy)
    algebraic_polynomials = modadd_component.algebraic_polynomials(algebraic)

    assert str(algebraic_polynomials[0]) == "modadd_1_9_c0_0"
    assert str(algebraic_polynomials[1]) == "modadd_1_9_o0_0 + modadd_1_9_c0_0 + modadd_1_9_x6 + modadd_1_9_x0"
    assert str(algebraic_polynomials[-2]) == "modadd_1_9_o0_4*modadd_1_9_c1_4 + modadd_1_9_x16*modadd_1_9_c1_4 + " \
                                             "modadd_1_9_x16*modadd_1_9_o0_4 + modadd_1_9_c1_5"
    assert str(algebraic_polynomials[-1]) == "modadd_1_9_c1_5 + modadd_1_9_o0_5 + modadd_1_9_y5 + modadd_1_9_x17"

def test_milp_bitwise_deterministic_truncated_xor_differential_binary_constraints():
    cipher = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
    milp.init_model_in_sage_milp_class()
    modadd_component = cipher.get_component_from_id("modadd_0_1")
    variables, constraints = modadd_component.milp_bitwise_deterministic_truncated_xor_differential_binary_constraints(milp)

    assert str(variables[0]) == "('x[rot_0_0_0_class_bit_0]', x_0)"
    assert str(variables[1]) == "('x[rot_0_0_0_class_bit_1]', x_1)"
    assert str(variables[-2]) == "('x[modadd_0_1_15_class_bit_0]', x_94)"
    assert str(variables[-1]) == "('x[modadd_0_1_15_class_bit_1]', x_95)"

    assert str(constraints[0]) == 'x_96 == 2*x_0 + x_1'
    assert str(constraints[1]) == 'x_97 == 2*x_2 + x_3'
    assert str(constraints[-2]) == '1 <= 18 - x_30 + x_94 - 17*x_159'
    assert str(constraints[-1]) == '1 <= 19 - x_62 - x_63 - 17*x_159'

def test_milp_bitwise_deterministic_truncated_xor_differential_constraints():
    cipher = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
    milp.init_model_in_sage_milp_class()
    modadd_component = cipher.get_component_from_id("modadd_0_1")
    variables, constraints = modadd_component.milp_bitwise_deterministic_truncated_xor_differential_constraints(milp)

    assert str(variables[0]) == "('x_class[rot_0_0_0]', x_0)"
    assert str(variables[1]) == "('x_class[rot_0_0_1]', x_1)"
    assert str(variables[-2]) == "('x_class[modadd_0_1_14]', x_46)"
    assert str(variables[-1]) == "('x_class[modadd_0_1_15]', x_47)"

    assert str(constraints[0]) == 'x_48 <= 15'
    assert str(constraints[1]) == '0 <= x_48'
    assert str(constraints[-2]) == '2 <= 4 + x_47 - 4*x_157 + 4*x_160'
    assert str(constraints[-1]) == 'x_157 <= x_15 + x_31'