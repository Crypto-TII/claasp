from claasp.cipher_modules.models.cp.cp_model import CpModel
from claasp.cipher_modules.models.milp.milp_model import MilpModel
from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher


def test_cms_constraints():
    fancy = FancyBlockCipher(number_of_rounds=3)
    and_component = fancy.component_from(0, 8)
    output_bit_ids, constraints = and_component.cms_constraints()

    assert output_bit_ids[0] == 'and_0_8_0'
    assert output_bit_ids[1] == 'and_0_8_1'
    assert output_bit_ids[2] == 'and_0_8_2'

    assert constraints[-3] == '-and_0_8_11 xor_0_7_11'
    assert constraints[-2] == '-and_0_8_11 key_23'
    assert constraints[-1] == 'and_0_8_11 -xor_0_7_11 -key_23'


def test_cp_deterministic_truncated_xor_differential_constraints():
    fancy = FancyBlockCipher()
    and_component = fancy.component_from(0, 8)
    declarations, constraints = and_component.cp_deterministic_truncated_xor_differential_constraints()

    assert declarations == []

    assert constraints[0] == 'constraint if xor_0_7[0] == 0 /\\ key[12] == 0 then and_0_8[0] = 0 else ' \
                             'and_0_8[0] = 2 endif;'
    assert constraints[-1] == 'constraint if xor_0_7[11] == 0 /\\ key[23] == 0 then and_0_8[11] = 0 else ' \
                              'and_0_8[11] = 2 endif;'


def test_cp_xor_differential_propagation_constraints():
    fancy = FancyBlockCipher()
    cp = CpModel(fancy)
    and_component = fancy.component_from(0, 8)
    declarations, constraints = and_component.cp_xor_differential_propagation_constraints(cp)

    assert declarations == []

    assert constraints[0] == 'constraint table([xor_0_7[0]]++[key[12]]++[and_0_8[0]]++[p[0]],and2inputs_DDT);'
    assert constraints[-1] == 'constraint table([xor_0_7[11]]++[key[23]]++[and_0_8[11]]++[p[11]],and2inputs_DDT);'


def test_milp_xor_differential_propagation_constraints():
    simon = SimonBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    milp = MilpModel(simon)
    milp.init_model_in_sage_milp_class()
    and_component = simon.get_component_from_id("and_0_4")
    variables, constraints = and_component.milp_xor_differential_propagation_constraints(milp)

    assert str(variables[0]) == "('x[rot_0_1_0]', x_0)"
    assert str(variables[1]) == "('x[rot_0_1_1]', x_1)"
    assert str(variables[-2]) == "('x[and_0_4_14]', x_46)"
    assert str(variables[-1]) == "('x[and_0_4_15]', x_47)"

    assert str(constraints[0]) == "0 <= -1*x_32 + x_48"
    assert str(constraints[1]) == "0 <= -1*x_33 + x_49"
    assert str(constraints[-1]) == f"x_64 == 10*x_48 + 10*x_49 + 10*x_50 + 10*x_51 + 10*x_52 + 10*x_53 + 10*x_54 + " \
                                   f"10*x_55 + 10*x_56 + 10*x_57 + 10*x_58 + 10*x_59 + 10*x_60 + 10*x_61 + " \
                                   f"10*x_62 + 10*x_63"


def test_milp_xor_linear_mask_propagation_constraints():
    simon = SimonBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    milp = MilpModel(simon)
    milp.init_model_in_sage_milp_class()
    and_component = simon.get_component_from_id("and_0_4")
    variables, constraints = and_component.milp_xor_linear_mask_propagation_constraints(milp)

    assert str(variables[0]) == "('x[and_0_4_0_i]', x_0)"
    assert str(variables[1]) == "('x[and_0_4_1_i]', x_1)"
    assert str(variables[-2]) == "('x[and_0_4_14_o]', x_46)"
    assert str(variables[-1]) == "('x[and_0_4_15_o]', x_47)"

    assert str(constraints[0]) == "0 <= -1*x_16 + x_32"
    assert str(constraints[1]) == "0 <= -1*x_17 + x_33"
    assert str(constraints[-3]) == "0 <= -1*x_15 + x_47"
    assert str(constraints[-2]) == "x_48 == x_32 + x_33 + x_34 + x_35 + x_36 + x_37 + x_38 + x_39 + x_40 + x_41 + " \
                                   "x_42 + x_43 + x_44 + x_45 + x_46 + x_47"
    assert str(constraints[-1]) == "x_49 == 10*x_48"


def test_sat_constraints():
    fancy = FancyBlockCipher(number_of_rounds=3)
    and_component = fancy.component_from(0, 8)
    output_bit_ids, constraints = and_component.sat_constraints()

    assert output_bit_ids[0] == 'and_0_8_0'
    assert output_bit_ids[1] == 'and_0_8_1'
    assert output_bit_ids[2] == 'and_0_8_2'

    assert constraints[-3] == '-and_0_8_11 xor_0_7_11'
    assert constraints[-2] == '-and_0_8_11 key_23'
    assert constraints[-1] == 'and_0_8_11 -xor_0_7_11 -key_23'


def test_sat_xor_differential_propagation_constraints():
    fancy = FancyBlockCipher(number_of_rounds=3)
    and_component = fancy.component_from(0, 8)
    output_bit_ids, constraints = and_component.sat_xor_differential_propagation_constraints()

    assert output_bit_ids[0] == 'and_0_8_0'
    assert output_bit_ids[1] == 'and_0_8_1'
    assert output_bit_ids[2] == 'and_0_8_2'

    assert constraints[-3] == 'xor_0_7_11 key_23 -hw_and_0_8_11'
    assert constraints[-2] == '-xor_0_7_11 hw_and_0_8_11'
    assert constraints[-1] == '-key_23 hw_and_0_8_11'


def test_sat_xor_linear_mask_propagation_constraints():
    fancy = FancyBlockCipher(number_of_rounds=3)
    and_component = fancy.component_from(0, 8)
    output_bit_ids, constraints = and_component.sat_xor_linear_mask_propagation_constraints()

    assert output_bit_ids[0] == 'and_0_8_0_i'
    assert output_bit_ids[1] == 'and_0_8_1_i'
    assert output_bit_ids[2] == 'and_0_8_2_i'

    assert constraints[-3] == '-and_0_8_23_i hw_and_0_8_11_o'
    assert constraints[-2] == '-and_0_8_11_o hw_and_0_8_11_o'
    assert constraints[-1] == 'and_0_8_11_o -hw_and_0_8_11_o'


def test_smt_xor_differential_propagation_constraints():
    fancy = FancyBlockCipher(number_of_rounds=3)
    and_component = fancy.component_from(0, 8)
    output_bit_ids, constraints = and_component.smt_xor_differential_propagation_constraints()

    assert output_bit_ids[0] == 'and_0_8_0'
    assert output_bit_ids[1] == 'and_0_8_1'
    assert output_bit_ids[-2] == 'hw_and_0_8_10'
    assert output_bit_ids[-1] == 'hw_and_0_8_11'

    assert constraints[0] == '(assert (or (and (not xor_0_7_0) (not key_12) (not and_0_8_0) (not hw_and_0_8_0)) ' \
                             '(and xor_0_7_0 hw_and_0_8_0) (and key_12 hw_and_0_8_0)))'
    assert constraints[1] == '(assert (or (and (not xor_0_7_1) (not key_13) (not and_0_8_1) (not hw_and_0_8_1)) ' \
                             '(and xor_0_7_1 hw_and_0_8_1) (and key_13 hw_and_0_8_1)))'
    assert constraints[-2] == '(assert (or (and (not xor_0_7_10) (not key_22) (not and_0_8_10) (not hw_and_0_8_10)) ' \
                              '(and xor_0_7_10 hw_and_0_8_10) (and key_22 hw_and_0_8_10)))'
    assert constraints[-1] == '(assert (or (and (not xor_0_7_11) (not key_23) (not and_0_8_11) (not hw_and_0_8_11)) ' \
                              '(and xor_0_7_11 hw_and_0_8_11) (and key_23 hw_and_0_8_11)))'


def test_smt_xor_linear_mask_propagation_constraints():
    fancy = FancyBlockCipher(number_of_rounds=3)
    and_component = fancy.component_from(0, 8)
    output_bit_ids, constraints = and_component.smt_xor_linear_mask_propagation_constraints()

    assert output_bit_ids[0] == 'and_0_8_0_i'
    assert output_bit_ids[1] == 'and_0_8_1_i'
    assert output_bit_ids[-2] == 'hw_and_0_8_10_o'
    assert output_bit_ids[-1] == 'hw_and_0_8_11_o'

    assert constraints[0] == '(assert (or (and (not and_0_8_0_i) (not and_0_8_12_i) (not and_0_8_0_o) ' \
                             '(not hw_and_0_8_0_o)) (and and_0_8_0_o hw_and_0_8_0_o)))'
    assert constraints[1] == '(assert (or (and (not and_0_8_1_i) (not and_0_8_13_i) (not and_0_8_1_o) ' \
                             '(not hw_and_0_8_1_o)) (and and_0_8_1_o hw_and_0_8_1_o)))'
    assert constraints[-2] == '(assert (or (and (not and_0_8_10_i) (not and_0_8_22_i) (not and_0_8_10_o) ' \
                              '(not hw_and_0_8_10_o)) (and and_0_8_10_o hw_and_0_8_10_o)))'
    assert constraints[-1] == '(assert (or (and (not and_0_8_11_i) (not and_0_8_23_i) (not and_0_8_11_o) ' \
                              '(not hw_and_0_8_11_o)) (and and_0_8_11_o hw_and_0_8_11_o)))'
