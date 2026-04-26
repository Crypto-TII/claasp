from claasp.cipher_modules.models.milp.milp_model import MilpModel
from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import (
    MilpBitwiseDeterministicTruncatedXorDifferentialModel,
)
from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import (
    MilpWordwiseDeterministicTruncatedXorDifferentialModel,
)
from claasp.ciphers.single_component_ciphers.linear_layer_cipher import LinearLayerCipher
from claasp.components.linear_layer_component import LinearLayer


MATRIX = [
    [1, 0, 1, 0],
    [1, 1, 0, 1],
    [0, 1, 1, 0],
    [1, 1, 1, 1],
]


def make_linear_layer_component():
    return LinearLayer(0, 0, ["input"], [[0, 1, 2, 3]], 4, MATRIX)


def make_linear_layer_cipher():
    return LinearLayerCipher(bit_size=4, description=MATRIX)


def test_cms_constraints():
    linear_layer_component = make_linear_layer_component()
    output_bit_ids, constraints = linear_layer_component.cms_constraints()

    assert output_bit_ids == [
        "linear_layer_0_0_0",
        "linear_layer_0_0_1",
        "linear_layer_0_0_2",
        "linear_layer_0_0_3",
    ]
    assert constraints == [
        "x -linear_layer_0_0_0 input_0 input_1 input_3",
        "x -linear_layer_0_0_1 input_1 input_2 input_3",
        "x -linear_layer_0_0_2 input_0 input_2 input_3",
        "x -linear_layer_0_0_3 input_1 input_3",
    ]


def test_cms_xor_linear_mask_propagation_constraints():
    linear_layer_component = make_linear_layer_component()
    output_bit_ids, constraints = linear_layer_component.cms_xor_linear_mask_propagation_constraints()

    assert output_bit_ids[0] == "linear_layer_0_0_0_i"
    assert output_bit_ids[1] == "linear_layer_0_0_1_i"
    assert output_bit_ids[-2] == "linear_layer_0_0_2_o"
    assert output_bit_ids[-1] == "linear_layer_0_0_3_o"

    assert constraints[0] == "linear_layer_0_0_0_i -dummy_0_linear_layer_0_0_3_o"
    assert constraints[7] == "dummy_1_linear_layer_0_0_3_o -dummy_1_linear_layer_0_0_2_o"
    assert constraints[-2] == "x -linear_layer_0_0_2_o dummy_1_linear_layer_0_0_2_o dummy_3_linear_layer_0_0_2_o"
    assert constraints[-1] == "x -linear_layer_0_0_3_o dummy_0_linear_layer_0_0_3_o dummy_1_linear_layer_0_0_3_o dummy_2_linear_layer_0_0_3_o"


def test_cp_constraints():
    linear_layer_component = make_linear_layer_component()
    declarations, constraints = linear_layer_component.cp_constraints()

    assert declarations == []
    assert constraints == [
        "constraint linear_layer_0_0[0] = (input[0] + input[1] + input[3]) mod 2;",
        "constraint linear_layer_0_0[1] = (input[1] + input[2] + input[3]) mod 2;",
        "constraint linear_layer_0_0[2] = (input[0] + input[2] + input[3]) mod 2;",
        "constraint linear_layer_0_0[3] = (input[1] + input[3]) mod 2;",
    ]


def test_cp_deterministic_truncated_xor_differential_constraints():
    linear_layer_component = make_linear_layer_component()
    declarations, constraints = linear_layer_component.cp_deterministic_truncated_xor_differential_constraints()

    assert declarations == []
    assert constraints == [
        "constraint if ((input[0] < 2) /\\ (input[1] < 2) /\\ (input[3] < 2)) then linear_layer_0_0[0] = (input[0] + input[1] + input[3]) mod 2 else linear_layer_0_0[0] = 2 endif;",
        "constraint if ((input[1] < 2) /\\ (input[2] < 2) /\\ (input[3] < 2)) then linear_layer_0_0[1] = (input[1] + input[2] + input[3]) mod 2 else linear_layer_0_0[1] = 2 endif;",
        "constraint if ((input[0] < 2) /\\ (input[2] < 2) /\\ (input[3] < 2)) then linear_layer_0_0[2] = (input[0] + input[2] + input[3]) mod 2 else linear_layer_0_0[2] = 2 endif;",
        "constraint if ((input[1] < 2) /\\ (input[3] < 2)) then linear_layer_0_0[3] = (input[1] + input[3]) mod 2 else linear_layer_0_0[3] = 2 endif;",
    ]


def test_cp_xor_linear_mask_propagation_constraints():
    linear_layer_component = make_linear_layer_component()
    declarations, constraints = linear_layer_component.cp_xor_linear_mask_propagation_constraints()

    assert declarations == [
        "array[0..3] of var 0..1:linear_layer_0_0_i;",
        "array[0..3] of var 0..1:linear_layer_0_0_o;",
    ]
    assert constraints == [
        "constraint linear_layer_0_0_i[0]=(linear_layer_0_0_o[0]+linear_layer_0_0_o[2]) mod 2;",
        "constraint linear_layer_0_0_i[1]=(linear_layer_0_0_o[0]+linear_layer_0_0_o[1]+linear_layer_0_0_o[3]) mod 2;",
        "constraint linear_layer_0_0_i[2]=(linear_layer_0_0_o[1]+linear_layer_0_0_o[2]) mod 2;",
        "constraint linear_layer_0_0_i[3]=(linear_layer_0_0_o[0]+linear_layer_0_0_o[1]+linear_layer_0_0_o[2]+linear_layer_0_0_o[3]) mod 2;",
    ]


def test_milp_constraints():
    cipher = make_linear_layer_cipher()
    milp = MilpModel(cipher)
    milp.init_model_in_sage_milp_class()
    linear_layer_component = cipher.component_from_id("linear_layer_0_0")
    variables, constraints = linear_layer_component.milp_constraints(milp)

    assert str(variables[0]) == "('x[plaintext_0]', x_0)"
    assert str(variables[1]) == "('x[plaintext_1]', x_1)"
    assert str(variables[-2]) == "('x[linear_layer_0_0_2]', x_6)"
    assert str(variables[-1]) == "('x[linear_layer_0_0_3]', x_7)"

    assert str(constraints[0]) == "1 <= 1 - x_0 + x_1 + x_3 + x_4"
    assert str(constraints[1]) == "1 <= 1 + x_0 - x_1 + x_3 + x_4"
    assert str(constraints[-2]) == "1 <= 1 + x_1 + x_3 - x_7"
    assert str(constraints[-1]) == "1 <= 3 - x_1 - x_3 - x_7"


def test_milp_xor_linear_mask_propagation_constraints():
    cipher = make_linear_layer_cipher()
    milp = MilpModel(cipher)
    milp.init_model_in_sage_milp_class()
    linear_layer_component = cipher.component_from_id("linear_layer_0_0")
    variables, constraints = linear_layer_component.milp_xor_linear_mask_propagation_constraints(milp)

    assert str(variables[0]) == "('x[linear_layer_0_0_0_i]', x_0)"
    assert str(variables[1]) == "('x[linear_layer_0_0_1_i]', x_1)"
    assert str(variables[-2]) == "('x[linear_layer_0_0_2_o]', x_6)"
    assert str(variables[-1]) == "('x[linear_layer_0_0_3_o]', x_7)"

    assert str(constraints[0]) == "1 <= 1 - x_0 + x_1 + x_3 + x_4"
    assert str(constraints[1]) == "1 <= 1 + x_0 - x_1 + x_3 + x_4"
    assert str(constraints[-2]) == "1 <= 3 - x_0 + x_1 - x_2 - x_7"
    assert str(constraints[-1]) == "1 <= 3 + x_0 - x_1 - x_2 - x_7"


def test_sat_constraints():
    linear_layer_component = make_linear_layer_component()
    output_bit_ids, constraints = linear_layer_component.sat_constraints()

    assert output_bit_ids == [
        "linear_layer_0_0_0",
        "linear_layer_0_0_1",
        "linear_layer_0_0_2",
        "linear_layer_0_0_3",
    ]
    assert constraints[0] == "-linear_layer_0_0_0 input_0 input_1 input_3"
    assert constraints[1] == "linear_layer_0_0_0 -input_0 input_1 input_3"
    assert constraints[-2] == "linear_layer_0_0_3 input_1 -input_3"
    assert constraints[-1] == "-linear_layer_0_0_3 -input_1 -input_3"


def test_sat_bitwise_deterministic_truncated_xor_differential_constraints():
    linear_layer_component = make_linear_layer_component()
    output_bit_ids, constraints = linear_layer_component.sat_bitwise_deterministic_truncated_xor_differential_constraints()

    assert output_bit_ids[0] == "linear_layer_0_0_0_0"
    assert output_bit_ids[1] == "linear_layer_0_0_1_0"
    assert output_bit_ids[-2] == "linear_layer_0_0_2_1"
    assert output_bit_ids[-1] == "linear_layer_0_0_3_1"

    assert constraints[0] == "inter_0_linear_layer_0_0_0_0 -input_0_0"
    assert constraints[10] == "inter_0_linear_layer_0_0_0_1 input_3_1 linear_layer_0_0_0_0 -linear_layer_0_0_0_1"
    assert constraints[-2] == "input_3_1 linear_layer_0_0_3_0 linear_layer_0_0_3_1 -input_1_1"
    assert constraints[-1] == "linear_layer_0_0_3_0 -input_1_1 -input_3_1 -linear_layer_0_0_3_1"


def test_sat_xor_linear_mask_propagation_constraints():
    linear_layer_component = make_linear_layer_component()
    output_bit_ids, constraints = linear_layer_component.sat_xor_linear_mask_propagation_constraints()

    assert output_bit_ids[0] == "linear_layer_0_0_0_i"
    assert output_bit_ids[1] == "linear_layer_0_0_1_i"
    assert output_bit_ids[-2] == "linear_layer_0_0_2_o"
    assert output_bit_ids[-1] == "linear_layer_0_0_3_o"

    assert constraints[0] == "linear_layer_0_0_0_i -dummy_0_linear_layer_0_0_3_o"
    assert constraints[14] == "dummy_3_linear_layer_0_0_2_o -dummy_3_linear_layer_0_0_1_o"
    assert constraints[-2] == "-linear_layer_0_0_3_o dummy_0_linear_layer_0_0_3_o -dummy_1_linear_layer_0_0_3_o -dummy_2_linear_layer_0_0_3_o"
    assert constraints[-1] == "linear_layer_0_0_3_o -dummy_0_linear_layer_0_0_3_o -dummy_1_linear_layer_0_0_3_o -dummy_2_linear_layer_0_0_3_o"


def test_smt_constraints():
    linear_layer_component = make_linear_layer_component()
    output_bit_ids, constraints = linear_layer_component.smt_constraints()

    assert output_bit_ids == [
        "linear_layer_0_0_0",
        "linear_layer_0_0_1",
        "linear_layer_0_0_2",
        "linear_layer_0_0_3",
    ]
    assert constraints == [
        "(assert (= linear_layer_0_0_0 (xor input_0 input_1 input_3)))",
        "(assert (= linear_layer_0_0_1 (xor input_1 input_2 input_3)))",
        "(assert (= linear_layer_0_0_2 (xor input_0 input_2 input_3)))",
        "(assert (= linear_layer_0_0_3 (xor input_1 input_3)))",
    ]


def test_smt_xor_linear_mask_propagation_constraints():
    linear_layer_component = make_linear_layer_component()
    output_bit_ids, constraints = linear_layer_component.smt_xor_linear_mask_propagation_constraints()

    assert output_bit_ids[0] == "linear_layer_0_0_0_i"
    assert output_bit_ids[1] == "linear_layer_0_0_1_i"
    assert output_bit_ids[-2] == "linear_layer_0_0_2_o"
    assert output_bit_ids[-1] == "linear_layer_0_0_3_o"

    assert constraints == [
        "(assert (= linear_layer_0_0_0_i dummy_0_linear_layer_0_0_0_o dummy_0_linear_layer_0_0_3_o))",
        "(assert (= linear_layer_0_0_1_i dummy_1_linear_layer_0_0_0_o dummy_1_linear_layer_0_0_1_o dummy_1_linear_layer_0_0_2_o dummy_1_linear_layer_0_0_3_o))",
        "(assert (= linear_layer_0_0_2_i dummy_2_linear_layer_0_0_1_o dummy_2_linear_layer_0_0_3_o))",
        "(assert (= linear_layer_0_0_3_i dummy_3_linear_layer_0_0_0_o dummy_3_linear_layer_0_0_1_o dummy_3_linear_layer_0_0_2_o))",
        "(assert (= linear_layer_0_0_0_o (xor dummy_0_linear_layer_0_0_0_o dummy_1_linear_layer_0_0_0_o dummy_3_linear_layer_0_0_0_o)))",
        "(assert (= linear_layer_0_0_1_o (xor dummy_1_linear_layer_0_0_1_o dummy_2_linear_layer_0_0_1_o dummy_3_linear_layer_0_0_1_o)))",
        "(assert (= linear_layer_0_0_2_o (xor dummy_1_linear_layer_0_0_2_o dummy_3_linear_layer_0_0_2_o)))",
        "(assert (= linear_layer_0_0_3_o (xor dummy_0_linear_layer_0_0_3_o dummy_1_linear_layer_0_0_3_o dummy_2_linear_layer_0_0_3_o)))",
    ]


def test_milp_bitwise_deterministic_truncated_xor_differential_constraints():
    cipher = make_linear_layer_cipher()
    milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
    milp.init_model_in_sage_milp_class()
    linear_layer_component = cipher.component_from_id("linear_layer_0_0")
    variables, constraints = linear_layer_component.milp_bitwise_deterministic_truncated_xor_differential_constraints(milp)

    assert str(variables[0]) == "('x_class[plaintext_0]', x_0)"
    assert str(variables[1]) == "('x_class[plaintext_1]', x_1)"
    assert str(variables[-2]) == "('x_class[linear_layer_0_0_2]', x_6)"
    assert str(variables[-1]) == "('x_class[linear_layer_0_0_3]', x_7)"

    assert str(constraints[0]) == "x_0 <= 3 - 2*x_8"
    assert str(constraints[1]) == "2 - 2*x_8 <= x_0"
    assert str(constraints[6]) == "-2 + x_8 + x_9 + x_10 <= x_11"
    assert str(constraints[-2]) == "x_7 <= 2 + 4*x_15"
    assert str(constraints[-1]) == "2 <= x_7 + 4*x_15"


def test_milp_bitwise_deterministic_truncated_xor_differential_binary_constraints():
    cipher = make_linear_layer_cipher()
    milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
    milp.init_model_in_sage_milp_class()
    linear_layer_component = cipher.component_from_id("linear_layer_0_0")
    variables, constraints = linear_layer_component.milp_bitwise_deterministic_truncated_xor_differential_binary_constraints(milp)

    assert str(variables[0]) == "('x_class[plaintext_0]', x_0)"
    assert str(variables[1]) == "('x_class[plaintext_1]', x_1)"
    assert str(variables[-2]) == "('x_class[linear_layer_0_0_2]', x_6)"
    assert str(variables[-1]) == "('x_class[linear_layer_0_0_3]', x_7)"

    assert str(constraints[0]) == "x_0 == 2*x_8 + x_9"
    assert str(constraints[1]) == "x_1 == 2*x_10 + x_11"
    assert str(constraints[8]) == "0 <= 3 + x_8 + x_10 + x_14 - 4*x_24"
    assert str(constraints[-2]) == "1 <= 1 - x_10 + x_22 + 6*x_33"
    assert str(constraints[-1]) == "1 <= 2 - x_14 - x_15 + 6*x_33"


def test_milp_wordwise_deterministic_truncated_xor_differential_constraints():
    cipher = make_linear_layer_cipher()
    milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(cipher)
    milp.init_model_in_sage_milp_class()
    milp._word_size = 2
    linear_layer_component = cipher.component_from_id("linear_layer_0_0")
    variables, constraints = linear_layer_component.milp_wordwise_deterministic_truncated_xor_differential_constraints(milp)

    assert str(variables[0]) == "('x[plaintext_word_0_class_bit_0]', x_0)"
    assert str(variables[1]) == "('x[plaintext_word_0_class_bit_1]', x_1)"
    assert str(variables[-2]) == "('x[linear_layer_0_0_2]', x_14)"
    assert str(variables[-1]) == "('x[linear_layer_0_0_3]', x_15)"

    assert str(constraints[0]) == "1 <= 1 + x_0 + x_1 + x_5 - x_9"
    assert str(constraints[1]) == "1 <= 1 + x_1 + x_4 + x_5 - x_9"
    assert str(constraints[-2]) == "1 <= 1 + x_5 - x_6"
    assert str(constraints[-1]) == "1 <= 1 + x_1 - x_2"
