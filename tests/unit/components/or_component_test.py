from claasp.components.or_component import OR
from claasp.cipher_modules.models.cp.cp_model import CpModel
from claasp.ciphers.permutations.gift_permutation import GiftPermutation
from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel


def test_algebraic_polynomials():
    gift = GiftPermutation(number_of_rounds=1)
    or_component = gift.get_component_from_id("or_0_4")
    algebraic = AlgebraicModel(gift)
    algebraic_polynomials = or_component.algebraic_polynomials(algebraic)

    assert str(algebraic_polynomials[0]) == "or_0_4_y0 + 1"
    assert str(algebraic_polynomials[1]) == "or_0_4_y1 + 1"
    assert str(algebraic_polynomials[-2]) == "or_0_4_y30 + 1"
    assert str(algebraic_polynomials[-1]) == "or_0_4_y31 + 1"


def test_cp_constraints():
    or_component = OR(0, 9, ['xor_0_7', 'key'],
                      [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], [12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23]], 12)
    declarations, constraints = or_component.cp_constraints()

    assert declarations == ['array[0..11] of var 0..1: or_0_9;', 'array[0..11] of var 0..1:pre_or_0_9_0;',
                            'array[0..11] of var 0..1:pre_or_0_9_1;']

    assert constraints[0] == 'constraint pre_or_0_9_0[0]=xor_0_7[0];'
    assert constraints[-2] == 'constraint pre_or_0_9_1[11]=key[23];'
    assert constraints[-1] == 'constraint or(pre_or_0_9_0, pre_or_0_9_1, or_0_9);'


def test_cp_xor_linear_mask_propagation_constraints():
    gift = GiftPermutation()
    or_component = gift.component_from(39, 6)
    cp = CpModel(gift)
    declarations, constraints = or_component.cp_xor_linear_mask_propagation_constraints(cp)

    assert declarations == ['array[0..31] of var int: p_or_39_6;', 'array[0..63] of var 0..1:or_39_6_i;',
                            'array[0..31] of var 0..1:or_39_6_o;']

    assert constraints[0] == 'constraint table(or_39_6_i[0]++or_39_6_i[32]++or_39_6_o[0]++p_or_39_6[0],and2inputs_LAT);'
    assert constraints[-2] == 'constraint table(or_39_6_i[31]++or_39_6_i[63]++or_39_6_o[31]++p_or_39_6[31],' \
                              'and2inputs_LAT);'
    assert constraints[-1] == 'constraint p[0] = sum(p_or_39_6);'


def test_generic_sign_linear_constraints():
    or_component = OR(31, 14, ['xor_0_7', 'key'],
                      [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], [12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23]], 12)
    input_tert = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    output = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]

    assert or_component.generic_sign_linear_constraints(input_tert, output) == 1


def test_smt_constraints():
    gift = GiftPermutation(number_of_rounds=3)
    or_component = gift.component_from(0, 4)
    output_bit_ids, constraints = or_component.smt_constraints()

    assert output_bit_ids[0] == 'or_0_4_0'
    assert output_bit_ids[1] == 'or_0_4_1'
    assert output_bit_ids[-2] == 'or_0_4_30'
    assert output_bit_ids[-1] == 'or_0_4_31'

    assert constraints[0] == '(assert (= or_0_4_0 (or xor_0_3_0 xor_0_1_0)))'
    assert constraints[1] == '(assert (= or_0_4_1 (or xor_0_3_1 xor_0_1_1)))'
    assert constraints[-2] == '(assert (= or_0_4_30 (or xor_0_3_30 xor_0_1_30)))'
    assert constraints[-1] == '(assert (= or_0_4_31 (or xor_0_3_31 xor_0_1_31)))'
