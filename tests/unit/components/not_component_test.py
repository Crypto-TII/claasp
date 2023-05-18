from claasp.components.not_component import NOT
from claasp.cipher_modules.models.cp.cp_model import CpModel
from claasp.cipher_modules.models.milp.milp_model import MilpModel
from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.ciphers.permutations.gift_permutation import GiftPermutation
from claasp.ciphers.permutations.ascon_permutation import AsconPermutation
from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel


def test_algebraic_polynomials():
    ascon = AsconPermutation(number_of_rounds=2)
    algebraic = AlgebraicModel(ascon)
    not_component = ascon.get_component_from_id("not_0_5")
    algebraic_polynomials = not_component.algebraic_polynomials(algebraic)

    assert str(algebraic_polynomials[0]) == "not_0_5_y0 + not_0_5_x0 + 1"
    assert str(algebraic_polynomials[1]) == "not_0_5_y1 + not_0_5_x1 + 1"
    assert str(algebraic_polynomials[2]) == "not_0_5_y2 + not_0_5_x2 + 1"
    assert str(algebraic_polynomials[-3]) == "not_0_5_y61 + not_0_5_x61 + 1"
    assert str(algebraic_polynomials[-2]) == "not_0_5_y62 + not_0_5_x62 + 1"
    assert str(algebraic_polynomials[-1]) == "not_0_5_y63 + not_0_5_x63 + 1"


def test_cms_constraints():
    gift = GiftPermutation(number_of_rounds=3)
    not_component = gift.component_from(0, 8)
    output_bit_ids, constraints = not_component.cms_constraints()

    assert output_bit_ids[0] == 'not_0_8_0'
    assert output_bit_ids[1] == 'not_0_8_1'
    assert output_bit_ids[2] == 'not_0_8_2'
    assert constraints[-3] == '-not_0_8_30 -xor_0_6_30'
    assert constraints[-2] == 'not_0_8_31 xor_0_6_31'
    assert constraints[-1] == '-not_0_8_31 -xor_0_6_31'


def test_cp_constraints():
    gift = GiftPermutation(number_of_rounds=3)
    not_component = gift.component_from(0, 8)
    declarations, constraints = not_component.cp_constraints()

    assert declarations == []

    assert constraints[0] == 'constraint not_0_8[0] = (xor_0_6[0] + 1) mod 2;'
    assert constraints[-1] == 'constraint not_0_8[31] = (xor_0_6[31] + 1) mod 2;'


def test_cp_deterministic_truncated_xor_differential_constraints():
    gift = GiftPermutation(number_of_rounds=3)
    not_component = gift.component_from(0, 8)
    declarations, constraints = not_component.cp_deterministic_truncated_xor_differential_constraints()

    assert declarations == []

    assert constraints[0] == 'constraint not_0_8[0] = xor_0_6[0];'
    assert constraints[-1] == 'constraint not_0_8[31] = xor_0_6[31];'


def test_cp_xor_differential_first_step_constraints():
    aes = AESBlockCipher()
    cp = CpModel(aes)
    not_component = NOT(0, 18, ['sbox_0_2', 'sbox_0_6', 'sbox_0_10', 'sbox_0_14'],
                               [[0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7],
                                [0, 1, 2, 3, 4, 5, 6, 7]], 32)
    declarations, constraints = not_component.cp_xor_differential_first_step_constraints(cp)

    assert declarations == ['array[0..3] of var 0..1: not_0_18;']

    assert constraints == ['constraint not_0_18[0] = sbox_0_2[0];',
                           'constraint not_0_18[1] = sbox_0_6[0];',
                           'constraint not_0_18[2] = sbox_0_10[0];',
                           'constraint not_0_18[3] = sbox_0_14[0];']


def test_cp_xor_differential_propagation_constraints():
    gift = GiftPermutation(number_of_rounds=3)
    not_component = gift.component_from(0, 8)
    declarations, constraints = not_component.cp_xor_differential_propagation_constraints()

    assert declarations == []

    assert constraints[0] == 'constraint not_0_8[0] = xor_0_6[0];'
    assert constraints[-1] == 'constraint not_0_8[31] = xor_0_6[31];'


def test_cp_xor_linear_mask_propagation_constraints():
    ascon = AsconPermutation(number_of_rounds=1)
    not_component = ascon.component_from(0, 5)
    declarations, constraints = not_component.cp_xor_linear_mask_propagation_constraints()

    assert declarations == ['array[0..63] of var 0..1:not_0_5_i;', 'array[0..63] of var 0..1:not_0_5_o;']

    assert constraints[0] == 'constraint not_0_5_o[0]=not_0_5_i[0];'
    assert constraints[-1] == 'constraint not_0_5_o[63]=not_0_5_i[63];'


def test_generic_sign_linear_constraints():
    gift = GiftPermutation(number_of_rounds=1)
    not_component = gift.component_from(0, 8)
    inputs = [0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0]

    assert not_component.generic_sign_linear_constraints(inputs) == 1


def test_milp_constraints():
    ascon = AsconPermutation()
    milp = MilpModel(ascon)
    milp.init_model_in_sage_milp_class()
    not_component = ascon.component_from(0, 5)
    variables, constraints = not_component.milp_constraints(milp)

    assert str(variables[0]) == "('x[xor_0_2_0]', x_0)"
    assert str(variables[1]) == "('x[xor_0_2_1]', x_1)"
    assert str(variables[-2]) == "('x[not_0_5_62]', x_126)"
    assert str(variables[-1]) == "('x[not_0_5_63]', x_127)"

    assert str(constraints[0]) == "x_0 + x_64 == 1"
    assert str(constraints[1]) == "x_1 + x_65 == 1"
    assert str(constraints[-2]) == "x_62 + x_126 == 1"
    assert str(constraints[-1]) == "x_63 + x_127 == 1"


def test_milp_xor_differential_propagation_constraints():
    ascon = AsconPermutation()
    milp = MilpModel(ascon)
    milp.init_model_in_sage_milp_class()
    not_component = ascon.component_from(0, 5)
    variables, constraints = not_component.milp_xor_differential_propagation_constraints(milp)

    assert str(variables[0]) == "('x[xor_0_2_0]', x_0)"
    assert str(variables[1]) == "('x[xor_0_2_1]', x_1)"
    assert str(variables[-2]) == "('x[not_0_5_62]', x_126)"
    assert str(variables[-1]) == "('x[not_0_5_63]', x_127)"

    assert str(constraints[0]) == "x_64 == x_0"
    assert str(constraints[1]) == "x_65 == x_1"
    assert str(constraints[-2]) == "x_126 == x_62"
    assert str(constraints[-1]) == "x_127 == x_63"


def test_milp_xor_linear_mask_propagation_constraints():
    ascon = AsconPermutation()
    milp = MilpModel(ascon)
    milp.init_model_in_sage_milp_class()
    not_component = ascon.component_from(0, 5)
    variables, constraints = not_component.milp_xor_linear_mask_propagation_constraints(milp)

    assert str(variables[0]) == "('x[not_0_5_0_i]', x_0)"
    assert str(variables[1]) == "('x[not_0_5_1_i]', x_1)"
    assert str(variables[-2]) == "('x[not_0_5_62_o]', x_126)"
    assert str(variables[-1]) == "('x[not_0_5_63_o]', x_127)"

    assert str(constraints[0]) == "x_64 == x_0"
    assert str(constraints[1]) == "x_65 == x_1"
    assert str(constraints[-2]) == "x_126 == x_62"
    assert str(constraints[-1]) == "x_127 == x_63"


def test_sat_constraints():
    gift = GiftPermutation(number_of_rounds=3)
    not_component = gift.component_from(0, 8)
    output_bit_ids, constraints = not_component.sat_constraints()

    assert output_bit_ids[0] == 'not_0_8_0'
    assert output_bit_ids[1] == 'not_0_8_1'
    assert output_bit_ids[2] == 'not_0_8_2'

    assert constraints[-3] == '-not_0_8_30 -xor_0_6_30'
    assert constraints[-2] == 'not_0_8_31 xor_0_6_31'
    assert constraints[-1] == '-not_0_8_31 -xor_0_6_31'


def test_sat_xor_differential_propagation_constraints():
    gift = GiftPermutation(number_of_rounds=3)
    not_component = gift.component_from(0, 8)
    output_bit_ids, constraints = not_component.sat_xor_differential_propagation_constraints()

    assert output_bit_ids[0] == 'not_0_8_0'
    assert output_bit_ids[1] == 'not_0_8_1'
    assert output_bit_ids[2] == 'not_0_8_2'

    assert constraints[-3] == 'xor_0_6_30 -not_0_8_30'
    assert constraints[-2] == 'not_0_8_31 -xor_0_6_31'
    assert constraints[-1] == 'xor_0_6_31 -not_0_8_31'


def test_sat_xor_linear_mask_propagation_constraints():
    gift = GiftPermutation(number_of_rounds=3)
    not_component = gift.component_from(0, 8)
    output_bit_ids, constraints = not_component.sat_xor_linear_mask_propagation_constraints()

    assert output_bit_ids[0] == 'not_0_8_0_i'
    assert output_bit_ids[1] == 'not_0_8_1_i'
    assert output_bit_ids[2] == 'not_0_8_2_i'

    assert constraints[-3] == 'not_0_8_30_o -not_0_8_30_i'
    assert constraints[-2] == 'not_0_8_31_i -not_0_8_31_o'
    assert constraints[-1] == 'not_0_8_31_o -not_0_8_31_i'


def test_smt_constraints():
    ascon = AsconPermutation(number_of_rounds=3)
    not_component = ascon.component_from(0, 5)
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
    ascon = AsconPermutation(number_of_rounds=3)
    not_component = ascon.component_from(0, 5)
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
    ascon = AsconPermutation(number_of_rounds=3)
    not_component = ascon.component_from(0, 5)
    output_bit_ids, constraints = not_component.smt_xor_linear_mask_propagation_constraints()

    assert output_bit_ids[0] == 'not_0_5_0_i'
    assert output_bit_ids[1] == 'not_0_5_1_i'
    assert output_bit_ids[-2] == 'not_0_5_62_o'
    assert output_bit_ids[-1] == 'not_0_5_63_o'

    assert constraints[0] == '(assert (= not_0_5_0_i not_0_5_0_o))'
    assert constraints[1] == '(assert (= not_0_5_1_i not_0_5_1_o))'
    assert constraints[-2] == '(assert (= not_0_5_62_i not_0_5_62_o))'
    assert constraints[-1] == '(assert (= not_0_5_63_i not_0_5_63_o))'
