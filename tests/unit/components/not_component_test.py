from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
from claasp.cipher_modules.models.milp.milp_model import MilpModel
from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import (
    MilpBitwiseDeterministicTruncatedXorDifferentialModel,
)
from claasp.ciphers.single_component_ciphers.not_cipher import NotCipher
from claasp.components.not_component import Not


def test_algebraic_polynomials():
    cipher = NotCipher(bit_size=64)
    algebraic = AlgebraicModel(cipher)
    not_component = cipher.component_from(0, 0)
    algebraic_polynomials = not_component.algebraic_polynomials(algebraic)

    assert str(algebraic_polynomials[0]) == "not_0_0_y0 + not_0_0_x0 + 1"
    assert str(algebraic_polynomials[1]) == "not_0_0_y1 + not_0_0_x1 + 1"
    assert str(algebraic_polynomials[2]) == "not_0_0_y2 + not_0_0_x2 + 1"
    assert str(algebraic_polynomials[-3]) == "not_0_0_y61 + not_0_0_x61 + 1"
    assert str(algebraic_polynomials[-2]) == "not_0_0_y62 + not_0_0_x62 + 1"
    assert str(algebraic_polynomials[-1]) == "not_0_0_y63 + not_0_0_x63 + 1"


def test_cms_constraints():
    not_component = Not(0, 8, ['xor_0_6'], [list(range(32))], 32)
    output_bit_ids, constraints = not_component.cms_constraints()

    assert output_bit_ids[0] == 'not_0_8_0'
    assert output_bit_ids[1] == 'not_0_8_1'
    assert output_bit_ids[2] == 'not_0_8_2'
    assert constraints[-3] == '-not_0_8_30 -xor_0_6_30'
    assert constraints[-2] == 'not_0_8_31 xor_0_6_31'
    assert constraints[-1] == '-not_0_8_31 -xor_0_6_31'


def test_cp_constraints():
    not_component = Not(0, 8, ['xor_0_6'], [list(range(32))], 32)
    declarations, constraints = not_component.cp_constraints()

    assert declarations == []

    assert constraints[0] == 'constraint not_0_8[0] = (xor_0_6[0] + 1) mod 2;'
    assert constraints[-1] == 'constraint not_0_8[31] = (xor_0_6[31] + 1) mod 2;'


def test_cp_deterministic_truncated_xor_differential_constraints():
    not_component = Not(0, 8, ['xor_0_6'], [list(range(32))], 32)
    declarations, constraints = not_component.cp_deterministic_truncated_xor_differential_constraints()

    assert declarations == []

    assert constraints[0] == 'constraint not_0_8[0] = xor_0_6[0];'
    assert constraints[-1] == 'constraint not_0_8[31] = xor_0_6[31];'


def test_cp_xor_differential_first_step_constraints():
    class DummyModel:
        word_size = 8

    not_component = Not(0, 18, ['plaintext', 'key', 'input3', 'input4'],
                        [[0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7],
                         [0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7]], 32)
    declarations, constraints = not_component.cp_xor_differential_first_step_constraints(DummyModel())

    assert declarations == ['array[0..3] of var 0..1: not_0_18;']

    assert constraints == ['constraint not_0_18[0] = plaintext[0];',
                           'constraint not_0_18[1] = key[0];',
                           'constraint not_0_18[2] = input3[0];',
                           'constraint not_0_18[3] = input4[0];']


def test_cp_xor_differential_propagation_constraints():
    not_component = Not(0, 8, ['xor_0_6'], [list(range(32))], 32)
    declarations, constraints = not_component.cp_xor_differential_propagation_constraints()

    assert declarations == []

    assert constraints[0] == 'constraint not_0_8[0] = xor_0_6[0];'
    assert constraints[-1] == 'constraint not_0_8[31] = xor_0_6[31];'


def test_cp_xor_linear_mask_propagation_constraints():
    not_component = Not(0, 5, ['ascon_0_5_i'], [list(range(64))], 64)
    declarations, constraints = not_component.cp_xor_linear_mask_propagation_constraints()

    assert declarations == ['array[0..63] of var 0..1:not_0_5_i;', 'array[0..63] of var 0..1:not_0_5_o;']

    assert constraints[0] == 'constraint not_0_5_o[0]=not_0_5_i[0];'
    assert constraints[-1] == 'constraint not_0_5_o[63]=not_0_5_i[63];'


def test_generic_sign_linear_constraints():
    not_component = Not(0, 8, ['xor_0_6'], [list(range(32))], 32)
    inputs = [0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0]

    assert not_component.generic_sign_linear_constraints(inputs) == 1


def test_milp_constraints():
    cipher = NotCipher(bit_size=64)
    milp = MilpModel(cipher)
    milp.init_model_in_sage_milp_class()
    not_component = cipher.component_from(0, 0)
    variables, constraints = not_component.milp_constraints(milp)

    assert str(variables[0]) == "('x[plaintext_0]', x_0)"
    assert str(variables[1]) == "('x[plaintext_1]', x_1)"
    assert str(variables[-2]) == "('x[not_0_0_62]', x_126)"
    assert str(variables[-1]) == "('x[not_0_0_63]', x_127)"

    assert str(constraints[0]) == "x_0 + x_64 == 1"
    assert str(constraints[1]) == "x_1 + x_65 == 1"
    assert str(constraints[-2]) == "x_62 + x_126 == 1"
    assert str(constraints[-1]) == "x_63 + x_127 == 1"


def test_milp_xor_differential_propagation_constraints():
    cipher = NotCipher(bit_size=64)
    milp = MilpModel(cipher)
    milp.init_model_in_sage_milp_class()
    not_component = cipher.component_from(0, 0)
    variables, constraints = not_component.milp_xor_differential_propagation_constraints(milp)

    assert str(variables[0]) == "('x[plaintext_0]', x_0)"
    assert str(variables[1]) == "('x[plaintext_1]', x_1)"
    assert str(variables[-2]) == "('x[not_0_0_62]', x_126)"
    assert str(variables[-1]) == "('x[not_0_0_63]', x_127)"

    assert str(constraints[0]) == "x_64 == x_0"
    assert str(constraints[1]) == "x_65 == x_1"
    assert str(constraints[-2]) == "x_126 == x_62"
    assert str(constraints[-1]) == "x_127 == x_63"


def test_milp_xor_linear_mask_propagation_constraints():
    cipher = NotCipher(bit_size=64)
    milp = MilpModel(cipher)
    milp.init_model_in_sage_milp_class()
    not_component = cipher.component_from(0, 0)
    variables, constraints = not_component.milp_xor_linear_mask_propagation_constraints(milp)

    assert str(variables[0]) == "('x[not_0_0_0_i]', x_0)"
    assert str(variables[1]) == "('x[not_0_0_1_i]', x_1)"
    assert str(variables[-2]) == "('x[not_0_0_62_o]', x_126)"
    assert str(variables[-1]) == "('x[not_0_0_63_o]', x_127)"

    assert str(constraints[0]) == "x_64 == x_0"
    assert str(constraints[1]) == "x_65 == x_1"
    assert str(constraints[-2]) == "x_126 == x_62"
    assert str(constraints[-1]) == "x_127 == x_63"


def test_sat_constraints():
    not_component = Not(0, 8, ['xor_0_6'], [list(range(32))], 32)
    output_bit_ids, constraints = not_component.sat_constraints()

    assert output_bit_ids[0] == 'not_0_8_0'
    assert output_bit_ids[1] == 'not_0_8_1'
    assert output_bit_ids[2] == 'not_0_8_2'

    assert constraints[-3] == '-not_0_8_30 -xor_0_6_30'
    assert constraints[-2] == 'not_0_8_31 xor_0_6_31'
    assert constraints[-1] == '-not_0_8_31 -xor_0_6_31'


def test_sat_bitwise_deterministic_truncated_xor_differential_constraints():
    not_component = Not(0, 8, ['xor_0_6'], [list(range(32))], 32)
    output_bit_ids, constraints = not_component.sat_bitwise_deterministic_truncated_xor_differential_constraints()

    assert output_bit_ids[0] == 'not_0_8_0_0'
    assert output_bit_ids[1] == 'not_0_8_1_0'
    assert output_bit_ids[2] == 'not_0_8_2_0'

    assert constraints[-3] == 'xor_0_6_30_0 -xor_0_6_30_1 -not_0_8_30_1'
    assert constraints[-2] == 'xor_0_6_31_0 xor_0_6_31_1 not_0_8_31_1'
    assert constraints[-1] == 'xor_0_6_31_0 -xor_0_6_31_1 -not_0_8_31_1'


def test_sat_xor_differential_propagation_constraints():
    not_component = Not(0, 8, ['xor_0_6'], [list(range(32))], 32)
    output_bit_ids, constraints = not_component.sat_xor_differential_propagation_constraints()

    assert output_bit_ids[0] == 'not_0_8_0'
    assert output_bit_ids[1] == 'not_0_8_1'
    assert output_bit_ids[2] == 'not_0_8_2'

    assert constraints[-3] == 'xor_0_6_30 -not_0_8_30'
    assert constraints[-2] == 'not_0_8_31 -xor_0_6_31'
    assert constraints[-1] == 'xor_0_6_31 -not_0_8_31'


def test_sat_xor_linear_mask_propagation_constraints():
    not_component = Not(0, 8, ['xor_0_6'], [list(range(32))], 32)
    output_bit_ids, constraints = not_component.sat_xor_linear_mask_propagation_constraints()

    assert output_bit_ids[0] == 'not_0_8_0_i'
    assert output_bit_ids[1] == 'not_0_8_1_i'
    assert output_bit_ids[2] == 'not_0_8_2_i'

    assert constraints[-3] == 'not_0_8_30_o -not_0_8_30_i'
    assert constraints[-2] == 'not_0_8_31_i -not_0_8_31_o'
    assert constraints[-1] == 'not_0_8_31_o -not_0_8_31_i'


def test_smt_constraints():
    not_component = Not(0, 5, ['xor_0_2'], [list(range(64))], 64)
    output_bit_ids, constraints = not_component.smt_constraints()

    assert output_bit_ids[0] == 'not_0_5_0'
    assert output_bit_ids[1] == 'not_0_5_1'
    assert output_bit_ids[-2] == 'not_0_5_62'
    assert output_bit_ids[-1] == 'not_0_5_63'

    assert constraints[0] == '(assert (distinct not_0_5_0 xor_0_2_0))'
    assert constraints[1] == '(assert (distinct not_0_5_1 xor_0_2_1))'
    assert constraints[-2] == '(assert (distinct not_0_5_62 xor_0_2_62))'
    assert constraints[-1] == '(assert (distinct not_0_5_63 xor_0_2_63))'


def test_smt_xor_differential_propagation_constraints():
    not_component = Not(0, 5, ['xor_0_2'], [list(range(64))], 64)
    output_bit_ids, constraints = not_component.smt_xor_differential_propagation_constraints()

    assert output_bit_ids[0] == 'not_0_5_0'
    assert output_bit_ids[1] == 'not_0_5_1'
    assert output_bit_ids[-2] == 'not_0_5_62'
    assert output_bit_ids[-1] == 'not_0_5_63'

    assert constraints[0] == '(assert (= not_0_5_0 xor_0_2_0))'
    assert constraints[1] == '(assert (= not_0_5_1 xor_0_2_1))'
    assert constraints[-2] == '(assert (= not_0_5_62 xor_0_2_62))'
    assert constraints[-1] == '(assert (= not_0_5_63 xor_0_2_63))'


def test_smt_xor_linear_mask_propagation_constraints():
    not_component = Not(0, 5, ['not_0_5_i'], [list(range(64))], 64)
    output_bit_ids, constraints = not_component.smt_xor_linear_mask_propagation_constraints()

    assert output_bit_ids[0] == 'not_0_5_0_i'
    assert output_bit_ids[1] == 'not_0_5_1_i'
    assert output_bit_ids[-2] == 'not_0_5_62_o'
    assert output_bit_ids[-1] == 'not_0_5_63_o'

    assert constraints[0] == '(assert (= not_0_5_0_i not_0_5_0_o))'
    assert constraints[1] == '(assert (= not_0_5_1_i not_0_5_1_o))'
    assert constraints[-2] == '(assert (= not_0_5_62_i not_0_5_62_o))'
    assert constraints[-1] == '(assert (= not_0_5_63_i not_0_5_63_o))'

def test_milp_deterministic_truncated_xor_differential_constraints():
    cipher = NotCipher(bit_size=32)
    milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
    milp.init_model_in_sage_milp_class()
    not_component = cipher.component_from(0, 0)
    variables, constraints = not_component.milp_bitwise_deterministic_truncated_xor_differential_constraints(milp)

    assert str(variables[0]) == "('x_class[plaintext_0]', x_0)"
    assert str(variables[1]) == "('x_class[plaintext_1]', x_1)"
    assert str(variables[-2]) == "('x_class[not_0_0_30]', x_62)"
    assert str(variables[-1]) == "('x_class[not_0_0_31]', x_63)"

    assert str(constraints[0]) == 'x_32 == x_0'
    assert str(constraints[1]) == 'x_33 == x_1'
    assert str(constraints[-2]) == 'x_62 == x_30'
    assert str(constraints[-1]) == 'x_63 == x_31'
