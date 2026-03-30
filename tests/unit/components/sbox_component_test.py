from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
from claasp.cipher_modules.models.milp.milp_model import MilpModel
from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import (
    MilpBitwiseDeterministicTruncatedXorDifferentialModel,
)
from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import (
    MilpWordwiseDeterministicTruncatedXorDifferentialModel,
)
from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
from claasp.cipher_modules.models.milp.milp_models.milp_xor_linear_model import MilpXorLinearModel
from claasp.cipher_modules.models.sat.sat_model import SatModel
from claasp.cipher_modules.models.smt.smt_model import SmtModel
from claasp.ciphers.single_component_ciphers.sbox_cipher import SboxCipher
from claasp.components.sbox_component import SBOX


PRESENT_SBOX = [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2]


def test_algebraic_polynomials():
    cipher = SboxCipher(bit_size=2, lookup_table=[0, 1, 3, 2])
    sbox_component = cipher.get_component_from_id("sbox_0_0")
    algebraic = AlgebraicModel(cipher)
    algebraic_polynomials = sbox_component.algebraic_polynomials(algebraic)

    assert str(algebraic_polynomials[0]) == "sbox_0_0_y1 + sbox_0_0_x1"
    assert str(algebraic_polynomials[-1]) == "sbox_0_0_y0*sbox_0_0_y1 + sbox_0_0_x0*sbox_0_0_x1 + sbox_0_0_x1"


def test_cms_constraints():
    sbox_component = SBOX(0, 2, ["xor_0_0"], [[4, 5, 6, 7]], 4, PRESENT_SBOX)
    output_bit_ids, constraints = sbox_component.cms_constraints()

    assert output_bit_ids == ["sbox_0_2_0", "sbox_0_2_1", "sbox_0_2_2", "sbox_0_2_3"]
    assert constraints[0] == "xor_0_0_4 xor_0_0_5 xor_0_0_6 xor_0_0_7 sbox_0_2_0"
    assert constraints[-1] == "-xor_0_0_4 -xor_0_0_5 -xor_0_0_6 -xor_0_0_7 -sbox_0_2_3"


def test_cp_constraints():
    sbox = [12, 10, 13, 3, 14, 11, 15, 7, 8, 9, 1, 5, 0, 2, 4, 6]
    sbox_component = SBOX(0, 5, ["xor_0_1"], [[4, 5, 6, 7]], 4, sbox)
    declarations, constraints = sbox_component.cp_constraints([])

    assert declarations[0].startswith("array [1..16, 1..8] of int: table_sbox_0_5")
    assert constraints == [
        "constraint table([xor_0_1[4]]++[xor_0_1[5]]++[xor_0_1[6]]++[xor_0_1[7]]++[sbox_0_5[0]]++"
        "[sbox_0_5[1]]++[sbox_0_5[2]]++[sbox_0_5[3]], table_sbox_0_5);"
    ]


def test_cp_deterministic_truncated_xor_differential_constraints():
    sbox_component = SBOX(0, 1, ["xor_0_0"], [[0, 1, 2, 3]], 4, [1, 2, 3, 4, 0, 7, 6, 5])
    declarations, constraints, sbox_mant = sbox_component.cp_deterministic_truncated_xor_differential_constraints(
        sbox_mant=[]
    )

    assert declarations[0].startswith("array [1..27, 1..6] of int: table_sbox_0_1")
    assert constraints == [
        "constraint table([xor_0_0[0]]++[xor_0_0[1]]++[xor_0_0[2]]++[xor_0_0[3]]++[sbox_0_1[0]]++"
        "[sbox_0_1[1]]++[sbox_0_1[2]]++[sbox_0_1[3]], table_sbox_0_1);"
    ]
    assert sbox_mant[0][1] == "sbox_0_1"


def test_cp_xor_differential_propagation_constraints():
    sbox_component = SBOX(0, 0, ["plaintext"], [[0, 1, 2]], 3, list(range(8)))
    cp = type("DummyModel", (), {})()
    cp.sbox_mant = []
    cp.component_and_probability = {}
    cp.c = 0

    declarations, constraints = sbox_component.cp_xor_differential_propagation_constraints(cp)

    assert declarations[0].startswith("array [1..8, 1..7] of int: DDT_sbox_0_0")
    assert constraints == [
        "constraint table([plaintext[0]]++[plaintext[1]]++[plaintext[2]]++[sbox_0_0[0]]++[sbox_0_0[1]]++"
        "[sbox_0_0[2]]++[p[0]], DDT_sbox_0_0);"
    ]


def test_cp_xor_linear_mask_propagation_constraints():
    sbox_component = SBOX(0, 0, ["plaintext"], [[0, 1, 2]], 3, list(range(8)))
    cp = type("DummyModel", (), {})()
    cp.sbox_mant = []
    cp.component_and_probability = {}
    cp.c = 0

    declarations, constraints = sbox_component.cp_xor_linear_mask_propagation_constraints(cp)

    assert declarations[-2] == "array[0..2] of var 0..1: sbox_0_0_i;"
    assert declarations[-1] == "array[0..2] of var 0..1: sbox_0_0_o;"
    assert constraints == [
        "constraint table([sbox_0_0_i[0]]++[sbox_0_0_i[1]]++[sbox_0_0_i[2]]++[sbox_0_0_o[0]]++"
        "[sbox_0_0_o[1]]++[sbox_0_0_o[2]]++[p[0]],LAT_sbox_0_0);"
    ]


def test_milp_large_xor_differential_probability_constraints():
    cipher = SboxCipher(bit_size=3)
    milp = MilpModel(cipher)
    milp.init_model_in_sage_milp_class()
    sbox_component = cipher.component_from(0, 0)
    variables, constraints = sbox_component.milp_large_xor_differential_probability_constraints(
        milp.binary_variable, milp.integer_variable, milp._non_linear_component_id
    )

    assert str(variables[0]) == "('x[plaintext_0]', x_0)"
    assert str(variables[-1]) == "('x[sbox_0_0_2]', x_5)"
    assert str(constraints[0]) == "x_0 + x_1 + x_2 <= 3*x_6"


def test_milp_large_xor_linear_probability_constraints():
    cipher = SboxCipher(bit_size=3)
    milp = MilpModel(cipher)
    milp.init_model_in_sage_milp_class()
    sbox_component = cipher.component_from(0, 0)
    variables, constraints = sbox_component.milp_large_xor_linear_probability_constraints(
        milp.binary_variable, milp.integer_variable, milp._non_linear_component_id
    )

    assert str(variables[0]) == "('x[sbox_0_0_0_i]', x_0)"
    assert str(variables[-1]) == "('x[sbox_0_0_2_o]', x_5)"
    assert str(constraints[-1]) == "x_7 == 0"


def test_milp_small_xor_differential_probability_constraints():
    cipher = SboxCipher(bit_size=3)
    milp = MilpModel(cipher)
    milp.init_model_in_sage_milp_class()
    sbox_component = cipher.component_from(0, 0)
    variables, constraints = sbox_component.milp_small_xor_differential_probability_constraints(
        milp.binary_variable, milp.integer_variable, milp._non_linear_component_id
    )

    assert str(variables[0]) == "('x[plaintext_0]', x_0)"
    assert str(variables[-1]) == "('x[sbox_0_0_2]', x_5)"
    assert str(constraints[-1]) == "x_8 == 0"


def test_milp_small_xor_linear_probability_constraints():
    cipher = SboxCipher(bit_size=3)
    milp = MilpModel(cipher)
    milp.init_model_in_sage_milp_class()
    sbox_component = cipher.component_from(0, 0)
    variables, constraints = sbox_component.milp_small_xor_linear_probability_constraints(
        milp.binary_variable, milp.integer_variable, milp._non_linear_component_id
    )

    assert str(variables[0]) == "('x[sbox_0_0_0_i]', x_0)"
    assert str(variables[-1]) == "('x[sbox_0_0_2_o]', x_5)"
    assert str(constraints[-1]) == "x_8 == 0"


def test_milp_xor_differential_propagation_constraints():
    cipher = SboxCipher(bit_size=3)
    milp = MilpXorDifferentialModel(cipher)
    milp.init_model_in_sage_milp_class()
    sbox_component = cipher.component_from(0, 0)
    variables, constraints = sbox_component.milp_xor_differential_propagation_constraints(milp)

    assert str(variables[0]) == "('x[plaintext_0]', x_0)"
    assert str(variables[-1]) == "('x[sbox_0_0_2]', x_5)"
    assert str(constraints[-1]) == "x_7 == 0"


def test_milp_xor_linear_mask_propagation_constraints():
    cipher = SboxCipher(bit_size=3)
    milp = MilpXorLinearModel(cipher)
    milp.init_model_in_sage_milp_class()
    sbox_component = cipher.component_from(0, 0)
    variables, constraints = sbox_component.milp_xor_linear_mask_propagation_constraints(milp)

    assert str(variables[0]) == "('x[sbox_0_0_0_i]', x_0)"
    assert str(variables[-1]) == "('x[sbox_0_0_2_o]', x_5)"
    assert str(constraints[-1]) == "x_7 == 0"


def test_sat_constraints():
    sbox_component = SBOX(0, 2, ["xor_0_0"], [[4, 5, 6, 7]], 4, PRESENT_SBOX)
    output_bit_ids, constraints = sbox_component.sat_constraints()

    assert output_bit_ids == ["sbox_0_2_0", "sbox_0_2_1", "sbox_0_2_2", "sbox_0_2_3"]
    assert constraints[0] == "xor_0_0_4 xor_0_0_5 xor_0_0_6 xor_0_0_7 sbox_0_2_0"
    assert constraints[-1] == "-xor_0_0_4 -xor_0_0_5 -xor_0_0_6 -xor_0_0_7 -sbox_0_2_3"


def test_sat_bitwise_deterministic_truncated_xor_differential_constraints():
    sbox_component = SBOX(0, 2, ["xor_0_0"], [[4, 5, 6, 7]], 4, PRESENT_SBOX)
    output_bit_ids, constraints = sbox_component.sat_bitwise_deterministic_truncated_xor_differential_constraints()

    assert output_bit_ids[0] == "sbox_0_2_0_0"
    assert output_bit_ids[1] == "sbox_0_2_1_0"
    assert constraints[-1] == "-xor_0_0_4_0 sbox_0_2_3_0"


def test_sat_xor_differential_propagation_constraints():
    cipher = SboxCipher(bit_size=3)
    sbox_component = cipher.component_from(0, 0)
    sat = SatModel(cipher)
    output_bit_ids, constraints = sbox_component.sat_xor_differential_propagation_constraints(sat)

    assert output_bit_ids == [
        "sbox_0_0_0",
        "sbox_0_0_1",
        "sbox_0_0_2",
        "hw_sbox_0_0_0",
        "hw_sbox_0_0_1",
        "hw_sbox_0_0_2",
    ]
    assert constraints == [
        "-plaintext_2 sbox_0_0_2",
        "plaintext_2 -sbox_0_0_2",
        "-plaintext_1 sbox_0_0_1",
        "plaintext_1 -sbox_0_0_1",
        "-plaintext_0 sbox_0_0_0",
        "plaintext_0 -sbox_0_0_0",
        "-hw_sbox_0_0_2",
        "-hw_sbox_0_0_1",
        "-hw_sbox_0_0_0",
    ]


def test_sat_xor_linear_mask_propagation_constraints():
    cipher = SboxCipher(bit_size=3)
    sbox_component = cipher.component_from(0, 0)
    sat = SatModel(cipher)
    bit_ids, constraints = sbox_component.sat_xor_linear_mask_propagation_constraints(sat)

    assert bit_ids == [
        "sbox_0_0_0_i",
        "sbox_0_0_1_i",
        "sbox_0_0_2_i",
        "sbox_0_0_0_o",
        "sbox_0_0_1_o",
        "sbox_0_0_2_o",
        "hw_sbox_0_0_0_o",
        "hw_sbox_0_0_1_o",
        "hw_sbox_0_0_2_o",
    ]
    assert constraints[-3:] == ["-hw_sbox_0_0_2_o", "-hw_sbox_0_0_1_o", "-hw_sbox_0_0_0_o"]


def test_smt_constraints():
    component = SBOX(0, 1, ["input"], [[0, 1]], 2, [1, 2, 3, 0])
    output_bit_ids, constraints = component.smt_constraints()

    assert output_bit_ids == ["sbox_0_1_0", "sbox_0_1_1"]
    assert constraints[-1] == "(assert (=> (and input_0 input_1) (and (not sbox_0_1_0) (not sbox_0_1_1))))"


def test_smt_xor_differential_propagation_constraints():
    cipher = SboxCipher(bit_size=3)
    smt = SmtModel(cipher)
    sbox_component = cipher.component_from(0, 0)
    output_bit_ids, constraints = sbox_component.smt_xor_differential_propagation_constraints(smt)

    assert output_bit_ids[-2:] == ["hw_sbox_0_0_1", "hw_sbox_0_0_2"]
    assert constraints[-1] == "(assert (or (not hw_sbox_0_0_0)))"


def test_smt_xor_linear_mask_propagation_constraints():
    cipher = SboxCipher(bit_size=2)
    sbox_component = cipher.component_from(0, 0)
    smt = SmtModel(cipher)
    output_bit_ids, constraints = sbox_component.smt_xor_linear_mask_propagation_constraints(smt)

    assert output_bit_ids[-2:] == ["hw_sbox_0_0_0_o", "hw_sbox_0_0_1_o"]
    assert constraints[-1] == "(assert (or (not hw_sbox_0_0_0_o)))"


def test_milp_bitwise_deterministic_truncated_xor_differential_constraints():
    cipher = SboxCipher(bit_size=2)
    milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
    milp.init_model_in_sage_milp_class()
    sbox_component = cipher.component_from(0, 0)
    variables, constraints = sbox_component.milp_bitwise_deterministic_truncated_xor_differential_constraints(milp)

    assert str(variables[0]) == "('x_class[plaintext_0]', x_0)"
    assert str(variables[-1]) == "('x_class[sbox_0_0_1]', x_3)"
    assert str(constraints[-1]) == "2 <= x_3 + 2*x_4"


def test_milp_undisturbed_bits_bitwise_deterministic_truncated_xor_differential_constraints():
    cipher = SboxCipher(bit_size=2)
    milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
    milp.init_model_in_sage_milp_class()
    sbox_component = cipher.component_from(0, 0)
    variables, constraints = sbox_component.milp_undisturbed_bits_bitwise_deterministic_truncated_xor_differential_constraints(milp)

    assert str(variables[0]) == "('x[plaintext_0_class_bit_0]', x_0)"
    assert str(variables[-1]) == "('x[sbox_0_0_1_class_bit_1]', x_7)"
    assert str(constraints[0]) == "x_8 == 2*x_0 + x_1"
    assert str(constraints[-1]) == "1 <= 1 + x_3 - x_7"


def test_milp_wordwise_deterministic_truncated_xor_differential_constraints():
    cipher = SboxCipher(bit_size=4)
    milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(cipher)
    milp.init_model_in_sage_milp_class()
    sbox_component = cipher.component_from(0, 0)
    variables, constraints = sbox_component.milp_wordwise_deterministic_truncated_xor_differential_constraints(milp)

    assert str(variables[0]) == "('x[plaintext_word_0_class_bit_0]', x_0)"
    assert str(variables[-1]) == "('x[sbox_0_0_word_0_class_bit_1]', x_3)"
    assert str(constraints[-1]) == "x_0 <= x_2"


def test_milp_wordwise_deterministic_truncated_xor_differential_simple_constraints():
    cipher = SboxCipher(bit_size=3)
    milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(cipher)
    milp.init_model_in_sage_milp_class()
    sbox_component = cipher.component_from(0, 0)
    variables, constraints = sbox_component.milp_wordwise_deterministic_truncated_xor_differential_simple_constraints(milp)

    assert str(variables[0]) == "('x_class[plaintext_word_0_class]', x_0)"
    assert constraints == []
