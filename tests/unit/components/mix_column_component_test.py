
from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
from claasp.cipher_modules.models.cp.mzn_model import MznModel
from claasp.cipher_modules.models.milp.milp_model import MilpModel
from claasp.ciphers.single_component_ciphers.mix_column_cipher import MixColumnCipher
from claasp.components.mix_column_component import MixColumn

MATRIX = [[1, 2], [3, 1]]
IRREDUCIBLE_POLYNOMIAL = 0b10011
WORD_SIZE = 4
BIT_SIZE = 8


def make_mix_column_component(component_index=0, input_name="plaintext"):
    return MixColumn(
        0,
        component_index,
        [input_name],
        [list(range(BIT_SIZE))],
        BIT_SIZE,
        [MATRIX, IRREDUCIBLE_POLYNOMIAL, WORD_SIZE],
    )


def make_mix_column_cipher():
    return MixColumnCipher(word_size=WORD_SIZE, matrix=MATRIX, irreducible_polynomial=IRREDUCIBLE_POLYNOMIAL)


def test_algebraic_polynomials():
    cipher = make_mix_column_cipher()
    mix_column_component = cipher.component_from_id("mix_column_0_0")
    algebraic_polynomials = mix_column_component.algebraic_polynomials(AlgebraicModel(cipher))

    assert str(algebraic_polynomials[0]) == "mix_column_0_0_x0 + mix_column_0_0_x7 + mix_column_0_0_y0"
    assert str(algebraic_polynomials[1]) == "mix_column_0_0_x1 + mix_column_0_0_x4 + mix_column_0_0_x7 + mix_column_0_0_y1"
    assert str(algebraic_polynomials[-2]) == "mix_column_0_0_y6^2 + mix_column_0_0_y6"
    assert str(algebraic_polynomials[-1]) == "mix_column_0_0_y7^2 + mix_column_0_0_y7"


def test_cp_create_component():
    cp = MznModel(make_mix_column_cipher())
    cp.word_size = WORD_SIZE
    mix_column_component_1 = make_mix_column_component(component_index=0)
    mix_column_component_2 = make_mix_column_component(component_index=1, input_name="input")
    declarations, constraints = mix_column_component_1._cp_create_component(
        cp.word_size,
        mix_column_component_2,
        1,
        cp.list_of_xor_components,
    )

    assert declarations == [
        "array[0..1] of var 0..1: input_xor_mix_column_0_1_mix_column_0_0;",
        "array[0..1] of var 0..1: output_xor_mix_column_0_1_mix_column_0_0;",
    ]
    assert constraints == [
        "constraint table([input_xor_mix_column_0_1_mix_column_0_0[s]|s in 0..1]++"
        "[output_xor_mix_column_0_1_mix_column_0_0[s]|s in 0..1],mix_column_truncated_table_1);"
    ]


def test_cms_constraints():
    mix_column_component = make_mix_column_component()
    output_bit_ids, constraints = mix_column_component.cms_constraints()

    assert output_bit_ids[0] == "mix_column_0_0_0"
    assert output_bit_ids[1] == "mix_column_0_0_1"
    assert output_bit_ids[2] == "mix_column_0_0_2"
    assert constraints[-3] == "-mix_column_0_0_7 -plaintext_0 plaintext_3 -plaintext_7"
    assert constraints[-2] == "-mix_column_0_0_7 plaintext_0 -plaintext_3 -plaintext_7"
    assert constraints[-1] == "mix_column_0_0_7 -plaintext_0 -plaintext_3 -plaintext_7"


def test_cp_constraints():
    mix_column_component = make_mix_column_component()
    declarations, constraints = mix_column_component.cp_constraints()

    assert declarations == []
    assert constraints[0] == "constraint mix_column_0_0[0] = (plaintext[0] + plaintext[5]) mod 2;"
    assert constraints[-1] == "constraint mix_column_0_0[7] = (plaintext[0] + plaintext[3] + plaintext[7]) mod 2;"


def test_cp_deterministic_truncated_xor_differential_constraints():
    mix_column_component = make_mix_column_component()
    declarations, constraints = mix_column_component.cp_deterministic_truncated_xor_differential_constraints()

    assert declarations == []
    assert constraints[0] == (
        "constraint if ((plaintext[0] < 2) /\\ (plaintext[5] < 2)) then mix_column_0_0[0] = "
        "(plaintext[0] + plaintext[5]) mod 2 else mix_column_0_0[0] = 2 endif;"
    )
    assert constraints[-1] == (
        "constraint if ((plaintext[0] < 2) /\\ (plaintext[3] < 2) /\\ (plaintext[7] < 2)) then "
        "mix_column_0_0[7] = (plaintext[0] + plaintext[3] + plaintext[7]) mod 2 else mix_column_0_0[7] = 2 endif;"
    )


def test_cp_xor_linear_mask_propagation_constraints():
    mix_column_component = make_mix_column_component()
    declarations, constraints = mix_column_component.cp_xor_linear_mask_propagation_constraints()

    assert declarations == [
        "array[0..7] of var 0..1:mix_column_0_0_i;",
        "array[0..7] of var 0..1:mix_column_0_0_o;",
    ]
    assert constraints[0] == (
        "constraint mix_column_0_0_i[0]=(mix_column_0_0_o[1]+mix_column_0_0_o[2]+mix_column_0_0_o[4]+"
        "mix_column_0_0_o[6]+mix_column_0_0_o[7]) mod 2;"
    )
    assert constraints[-1] == (
        "constraint mix_column_0_0_i[7]=(mix_column_0_0_o[0]+mix_column_0_0_o[2]+mix_column_0_0_o[4]+"
        "mix_column_0_0_o[5]) mod 2;"
    )


def test_is_permutation_matrix():
    mix_column_component = make_mix_column_component()
    assert mix_column_component._is_permutation_matrix() is False

    permutation_matrix_component = MixColumn(
        0,
        0,
        ["plaintext"],
        [list(range(8))],
        8,
        [[[0, 1], [1, 0]], 0, 4],
    )
    assert permutation_matrix_component._is_permutation_matrix() is True

    repeated_column_component = MixColumn(
        0,
        0,
        ["plaintext"],
        [list(range(8))],
        8,
        [[[1, 0], [1, 0]], 0, 4],
    )
    assert repeated_column_component._is_permutation_matrix() is False

    non_square_component = MixColumn(
        0,
        0,
        ["plaintext"],
        [list(range(8))],
        8,
        [[[1, 0], [0]], 0, 4],
    )
    assert non_square_component._is_permutation_matrix() is False


def test_cp_xor_differential_first_step_uses_equalities_for_permutation_matrix():
    cp = MznModel(make_mix_column_cipher())
    cp.word_size = 2
    cp.mix_column_mant = []
    cp.list_of_xor_components = []
    mix_column_component = MixColumn(
        0,
        0,
        ["plaintext"],
        [list(range(8))],
        8,
        [[[0, 1], [1, 0]], 0, 4],
    )

    declarations, constraints = mix_column_component.cp_xor_differential_propagation_first_step_constraints(cp)

    assert declarations == ["array[0..3] of var 0..1: mix_column_0_0;"]
    assert constraints == [
        "constraint mix_column_0_0[0] = plaintext[2];",
        "constraint mix_column_0_0[1] = plaintext[3];",
        "constraint mix_column_0_0[2] = plaintext[0];",
        "constraint mix_column_0_0[3] = plaintext[1];",
    ]
    assert cp.mix_column_mant == [mix_column_component]


def test_cp_xor_differential_first_step_uses_table_for_non_permutation_matrix():
    cp = MznModel(make_mix_column_cipher())
    cp.word_size = 4
    cp.mix_column_mant = []
    cp.list_of_xor_components = []
    mix_column_component = make_mix_column_component()

    declarations, constraints = mix_column_component.cp_xor_differential_propagation_first_step_constraints(cp)

    assert declarations[0] == "array[0..1] of var 0..1: mix_column_0_0;"
    assert declarations[1].startswith("array[0..5, 1..4] of int: mix_column_truncated_table_mix_column_0_0")
    assert constraints == [
        "constraint table([plaintext[0]]++[plaintext[1]]++[mix_column_0_0[0]]++[mix_column_0_0[1]], "
        "mix_column_truncated_table_mix_column_0_0);"
    ]


def test_milp_constraints():
    cipher = make_mix_column_cipher()
    milp = MilpModel(cipher)
    milp.init_model_in_sage_milp_class()
    mix_column_component = cipher.component_from_id("mix_column_0_0")
    variables, constraints = mix_column_component.milp_constraints(milp)

    assert str(variables[0]) == "('x[plaintext_0]', x_0)"
    assert str(variables[1]) == "('x[plaintext_1]', x_1)"
    assert str(variables[-2]) == "('x[mix_column_0_0_6]', x_14)"
    assert str(variables[-1]) == "('x[mix_column_0_0_7]', x_15)"
    assert str(constraints[:3]) == "[1 <= 1 - x_0 + x_5 + x_8, 1 <= 1 + x_0 - x_5 + x_8, 1 <= 1 + x_0 + x_5 - x_8]"


def test_milp_xor_linear_mask_propagation_constraints():
    cipher = make_mix_column_cipher()
    milp = MilpModel(cipher)
    milp.init_model_in_sage_milp_class()
    mix_column_component = cipher.component_from_id("mix_column_0_0")
    variables, constraints = mix_column_component.milp_xor_linear_mask_propagation_constraints(milp)

    assert str(variables[0]) == "('x[mix_column_0_0_0_i]', x_0)"
    assert str(variables[1]) == "('x[mix_column_0_0_1_i]', x_1)"
    assert str(variables[-2]) == "('x[mix_column_0_0_6_o]', x_14)"
    assert str(variables[-1]) == "('x[mix_column_0_0_7_o]', x_15)"
    assert str(constraints[0]) == "1 <= 1 - x_1 + x_3 + x_4 + x_5 + x_6 + x_7 + x_8"
    assert str(constraints[1]) == "1 <= 1 + x_1 - x_3 + x_4 + x_5 + x_6 + x_7 + x_8"


def test_sat_constraints():
    mix_column_component = make_mix_column_component()
    output_bit_ids, constraints = mix_column_component.sat_constraints()

    assert output_bit_ids[0] == "mix_column_0_0_0"
    assert output_bit_ids[1] == "mix_column_0_0_1"
    assert output_bit_ids[2] == "mix_column_0_0_2"
    assert constraints[-3] == "-mix_column_0_0_7 -plaintext_0 plaintext_3 -plaintext_7"
    assert constraints[-2] == "-mix_column_0_0_7 plaintext_0 -plaintext_3 -plaintext_7"
    assert constraints[-1] == "mix_column_0_0_7 -plaintext_0 -plaintext_3 -plaintext_7"


def test_sat_bitwise_deterministic_truncated_xor_differential_constraints():
    mix_column_component = make_mix_column_component()
    output_bit_ids, constraints = mix_column_component.sat_bitwise_deterministic_truncated_xor_differential_constraints()

    assert output_bit_ids[3] == "mix_column_0_0_3_0"
    assert output_bit_ids[5] == "mix_column_0_0_5_0"
    assert constraints[-3] == "inter_0_mix_column_0_0_7_1 mix_column_0_0_7_0 mix_column_0_0_7_1 -plaintext_7_1"
    assert constraints[-2] == "plaintext_7_1 mix_column_0_0_7_0 mix_column_0_0_7_1 -inter_0_mix_column_0_0_7_1"
    assert constraints[-1] == "mix_column_0_0_7_0 -inter_0_mix_column_0_0_7_1 -plaintext_7_1 -mix_column_0_0_7_1"


def test_sat_xor_linear_mask_propagation_constraints():
    mix_column_component = make_mix_column_component()
    variables, constraints = mix_column_component.sat_xor_linear_mask_propagation_constraints()

    assert variables[0] == "mix_column_0_0_0_i"
    assert variables[1] == "mix_column_0_0_1_i"
    assert variables[2] == "mix_column_0_0_2_i"
    assert constraints[-2] == (
        "mix_column_0_0_7_o dummy_0_mix_column_0_0_7_o -dummy_1_mix_column_0_0_7_o -dummy_5_mix_column_0_0_7_o "
        "-dummy_6_mix_column_0_0_7_o"
    )
    assert constraints[-1] == (
        "-mix_column_0_0_7_o -dummy_0_mix_column_0_0_7_o -dummy_1_mix_column_0_0_7_o -dummy_5_mix_column_0_0_7_o "
        "-dummy_6_mix_column_0_0_7_o"
    )


def test_smt_constraints():
    mix_column_component = make_mix_column_component()
    variables, constraints = mix_column_component.smt_constraints()

    assert variables[0] == "mix_column_0_0_0"
    assert variables[1] == "mix_column_0_0_1"
    assert variables[-2] == "mix_column_0_0_6"
    assert variables[-1] == "mix_column_0_0_7"
    assert constraints[-2] == "(assert (= mix_column_0_0_6 (xor plaintext_0 plaintext_2 plaintext_3 plaintext_6)))"
    assert constraints[-1] == "(assert (= mix_column_0_0_7 (xor plaintext_0 plaintext_3 plaintext_7)))"


def test_smt_xor_linear_mask_propagation_constraints():
    mix_column_component = make_mix_column_component()
    variables, constraints = mix_column_component.smt_xor_linear_mask_propagation_constraints()

    assert variables[0] == "mix_column_0_0_0_i"
    assert variables[1] == "mix_column_0_0_1_i"
    assert variables[-2] == "mix_column_0_0_6_o"
    assert variables[-1] == "mix_column_0_0_7_o"
    assert constraints[-2] == (
        "(assert (= mix_column_0_0_6_o (xor dummy_0_mix_column_0_0_6_o dummy_2_mix_column_0_0_6_o "
        "dummy_3_mix_column_0_0_6_o dummy_4_mix_column_0_0_6_o dummy_5_mix_column_0_0_6_o)))"
    )
    assert constraints[-1] == (
        "(assert (= mix_column_0_0_7_o (xor dummy_0_mix_column_0_0_7_o dummy_1_mix_column_0_0_7_o "
        "dummy_5_mix_column_0_0_7_o dummy_6_mix_column_0_0_7_o)))"
    )
