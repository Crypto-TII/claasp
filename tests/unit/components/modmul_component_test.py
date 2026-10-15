from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import (
    MilpBitwiseDeterministicTruncatedXorDifferentialModel,
)
from claasp.ciphers.single_component_ciphers.modmul_cipher import ModmulCipher
from claasp.components.modmul_component import ModMul


def test_modmul_component_creation():
    component = ModMul(
        current_round_number=1,
        current_round_number_of_components=0,
        input_id_links=["input1", "input2"],
        input_bit_positions=[[0, 1, 2, 3], [0, 1, 2, 3]],
        output_bit_size=4,
        modulus=16
    )

    assert component.id == "modmul_1_0"
    assert component.type == "word_operation"
    assert component.input_bit_size == 8
    assert component.output_bit_size == 4

    # Check evaluation string mapping based on the vector eval implementations
    bit_eval = component.get_bit_based_vectorized_python_code(["a", "b"], False)
    assert bit_eval == ["  modmul_1_0 = bit_vector_MODMUL([a,b ], 2, 4)"]

    byte_eval = component.get_byte_based_vectorized_python_code(["a", "b"])
    assert byte_eval == ["  modmul_1_0 = byte_vector_MODMUL(['a', 'b'])"]


def test_sat_bitwise_deterministic_truncated_xor_differential_constraints():
    modmul_component = ModMul(0, 7, ['modadd_0_4', 'plaintext'], [list(range(32)), list(range(32, 64))], 32, 2 ** 32)
    output_bit_ids, constraints = modmul_component.sat_bitwise_deterministic_truncated_xor_differential_constraints()

    assert output_bit_ids[0] == 'modmul_0_7_0_0'
    assert output_bit_ids[1] == 'modmul_0_7_1_0'
    assert output_bit_ids[-2] == 'modmul_0_7_30_1'
    assert output_bit_ids[-1] == 'modmul_0_7_31_1'

    assert constraints[0] == 'modmul_0_7_31_0 -modadd_0_4_31_0'
    assert constraints[1] == 'modmul_0_7_31_0 -modadd_0_4_31_1'
    assert constraints[-2] == '-modmul_0_7_0_0 modadd_0_4_0_0 modadd_0_4_0_1 plaintext_32_0 plaintext_32_1 ' \
                              'modmul_0_7_1_0'
    assert constraints[-1] == '-modmul_0_7_0_1'


def test_milp_bitwise_deterministic_truncated_xor_differential_constraints():
    cipher = ModmulCipher(word_bit_size=16, number_of_inputs=2)
    milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
    milp.init_model_in_sage_milp_class()
    modmul_component = cipher.component_from_id("modmul_0_0")
    variables, constraints = modmul_component.milp_bitwise_deterministic_truncated_xor_differential_constraints(milp)

    assert str(variables[0]) == "('x_class[plaintext_0]', x_0)"
    assert str(variables[1]) == "('x_class[plaintext_1]', x_1)"
    assert str(variables[-2]) == "('x_class[modmul_0_0_14]', x_46)"
    assert str(variables[-1]) == "('x_class[modmul_0_0_15]', x_47)"

    assert str(constraints[0]) == '1 <= 4 + x_0 - 4*x_48'
    assert str(constraints[1]) == '1 + x_0 - 4*x_48 <= 1'
    assert str(constraints[-2]) == 'x_111 <= x_50 + x_110'
    assert str(constraints[-1]) == 'x_32 == 2*x_111'
