from claasp.cipher_modules.models.cp.mzn_model import MznModel
from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
from claasp.cipher_modules.models.milp.milp_models.milp_xor_linear_model import MilpXorLinearModel
from claasp.ciphers.single_component_ciphers.and_cipher import AndCipher


def test_cms_constraints():
    cipher = AndCipher(word_bit_size=12, number_of_inputs=2)
    and_component = cipher.component_from(0, 0)
    output_bit_ids, constraints = and_component.cms_constraints()

    assert output_bit_ids[0] == 'and_0_0_0'
    assert output_bit_ids[1] == 'and_0_0_1'
    assert output_bit_ids[2] == 'and_0_0_2'

    assert constraints[-3] == '-and_0_0_11 plaintext_11'
    assert constraints[-2] == '-and_0_0_11 key_11'
    assert constraints[-1] == 'and_0_0_11 -plaintext_11 -key_11'


def test_cp_deterministic_truncated_xor_differential_constraints():
    cipher = AndCipher(word_bit_size=12, number_of_inputs=2)
    and_component = cipher.component_from(0, 0)
    declarations, constraints = and_component.cp_deterministic_truncated_xor_differential_constraints()

    assert declarations == []

    assert constraints[0] == 'constraint if plaintext[0] == 0 /\\ key[0] == 0 then and_0_0[0] = 0 else and_0_0[0] = 2 endif;'
    assert constraints[-1] == 'constraint if plaintext[11] == 0 /\\ key[11] == 0 then and_0_0[11] = 0 else and_0_0[11] = 2 endif;'


def test_cp_xor_differential_propagation_constraints():
    cipher = AndCipher(word_bit_size=12, number_of_inputs=2)
    cp = MznModel(cipher)
    and_component = cipher.component_from(0, 0)
    declarations, constraints = and_component.cp_xor_differential_propagation_constraints(cp)

    assert declarations == []

    assert constraints[0] == 'constraint table([plaintext[0]]++[key[0]]++[and_0_0[0]]++[p[0]],and2inputs_DDT);'
    assert constraints[-1] == 'constraint table([plaintext[11]]++[key[11]]++[and_0_0[11]]++[p[11]],and2inputs_DDT);'


def test_milp_xor_differential_propagation_constraints():
    cipher = AndCipher(word_bit_size=16, number_of_inputs=2)
    milp = MilpXorDifferentialModel(cipher)
    milp.init_model_in_sage_milp_class()
    and_component = cipher.get_component_from_id("and_0_0")
    variables, constraints = and_component.milp_xor_differential_propagation_constraints(milp)

    assert str(variables[0]) == "('x[plaintext_0]', x_0)"
    assert str(variables[1]) == "('x[plaintext_1]', x_1)"
    assert str(variables[-2]) == "('x[and_0_0_14]', x_46)"
    assert str(variables[-1]) == "('x[and_0_0_15]', x_47)"

    assert str(constraints[0]) == "0 <= -1*x_32 + x_48"
    assert str(constraints[1]) == "0 <= -1*x_33 + x_49"
    assert str(constraints[-1]) == f"x_64 == 100*x_48 + 100*x_49 + 100*x_50 + 100*x_51 + 100*x_52 + 100*x_53 + 100*x_54 + " \
                                   f"100*x_55 + 100*x_56 + 100*x_57 + 100*x_58 + 100*x_59 + 100*x_60 + 100*x_61 + " \
                                   f"100*x_62 + 100*x_63"


def test_milp_xor_linear_mask_propagation_constraints():
    cipher = AndCipher(word_bit_size=16, number_of_inputs=2)
    milp = MilpXorLinearModel(cipher)
    milp.init_model_in_sage_milp_class()
    and_component = cipher.get_component_from_id("and_0_0")
    variables, constraints = and_component.milp_xor_linear_mask_propagation_constraints(milp)

    assert str(variables[0]) == "('x[and_0_0_0_i]', x_0)"
    assert str(variables[1]) == "('x[and_0_0_1_i]', x_1)"
    assert str(variables[-2]) == "('x[and_0_0_14_o]', x_46)"
    assert str(variables[-1]) == "('x[and_0_0_15_o]', x_47)"

    assert str(constraints[0]) == "0 <= -1*x_16 + x_32"
    assert str(constraints[1]) == "0 <= -1*x_17 + x_33"
    assert str(constraints[-3]) == "0 <= -1*x_15 + x_47"
    assert str(constraints[-2]) == "x_48 == x_32 + x_33 + x_34 + x_35 + x_36 + x_37 + x_38 + x_39 + x_40 + x_41 + " \
                                   "x_42 + x_43 + x_44 + x_45 + x_46 + x_47"
    assert str(constraints[-1]) == "x_49 == 100*x_48"


def test_sat_constraints():
    cipher = AndCipher(word_bit_size=12, number_of_inputs=2)
    and_component = cipher.component_from(0, 0)
    output_bit_ids, constraints = and_component.sat_constraints()

    assert output_bit_ids[0] == 'and_0_0_0'
    assert output_bit_ids[1] == 'and_0_0_1'
    assert output_bit_ids[2] == 'and_0_0_2'

    assert constraints[-3] == '-and_0_0_11 plaintext_11'
    assert constraints[-2] == '-and_0_0_11 key_11'
    assert constraints[-1] == 'and_0_0_11 -plaintext_11 -key_11'


def test_sat_bitwise_deterministic_truncated_xor_differential_constraints():
    cipher = AndCipher(word_bit_size=12, number_of_inputs=2)
    and_component = cipher.component_from(0, 0)
    output_bit_ids, constraints = and_component.sat_bitwise_deterministic_truncated_xor_differential_constraints()

    assert output_bit_ids[0] == 'and_0_0_0_0'
    assert output_bit_ids[7] == 'and_0_0_7_0'
    assert output_bit_ids[14] == 'and_0_0_2_1'

    assert constraints[-14] == 'and_0_0_9_0 -and_0_0_9_1'
    assert constraints[-7] == 'plaintext_10_0 key_10_0 plaintext_10_1 key_10_1 -and_0_0_10_0'
    assert constraints[-1] == 'plaintext_11_0 key_11_0 plaintext_11_1 key_11_1 -and_0_0_11_0'
    

def test_sat_xor_differential_propagation_constraints():
    cipher = AndCipher(word_bit_size=12, number_of_inputs=2)
    and_component = cipher.component_from(0, 0)
    output_bit_ids, constraints = and_component.sat_xor_differential_propagation_constraints()

    assert output_bit_ids[0] == 'and_0_0_0'
    assert output_bit_ids[1] == 'and_0_0_1'
    assert output_bit_ids[2] == 'and_0_0_2'

    assert constraints[-3] == 'plaintext_11 key_11 -hw_and_0_0_11'
    assert constraints[-2] == '-plaintext_11 hw_and_0_0_11'
    assert constraints[-1] == '-key_11 hw_and_0_0_11'


def test_sat_xor_linear_mask_propagation_constraints():
    cipher = AndCipher(word_bit_size=12, number_of_inputs=2)
    and_component = cipher.component_from(0, 0)
    output_bit_ids, constraints = and_component.sat_xor_linear_mask_propagation_constraints()

    assert output_bit_ids[0] == 'and_0_0_0_i'
    assert output_bit_ids[1] == 'and_0_0_1_i'
    assert output_bit_ids[2] == 'and_0_0_2_i'

    assert constraints[-3] == '-and_0_0_23_i hw_and_0_0_11_o'
    assert constraints[-2] == '-and_0_0_11_o hw_and_0_0_11_o'
    assert constraints[-1] == 'and_0_0_11_o -hw_and_0_0_11_o'


def test_smt_xor_differential_propagation_constraints():
    cipher = AndCipher(word_bit_size=12, number_of_inputs=2)
    and_component = cipher.component_from(0, 0)
    output_bit_ids, constraints = and_component.smt_xor_differential_propagation_constraints()

    assert output_bit_ids[0] == 'and_0_0_0'
    assert output_bit_ids[1] == 'and_0_0_1'
    assert output_bit_ids[-2] == 'hw_and_0_0_10'
    assert output_bit_ids[-1] == 'hw_and_0_0_11'

    assert constraints[0] == '(assert (or (and (not plaintext_0) (not key_0) (not and_0_0_0) (not hw_and_0_0_0)) (and plaintext_0 hw_and_0_0_0) (and key_0 hw_and_0_0_0)))'
    assert constraints[1] == '(assert (or (and (not plaintext_1) (not key_1) (not and_0_0_1) (not hw_and_0_0_1)) (and plaintext_1 hw_and_0_0_1) (and key_1 hw_and_0_0_1)))'
    assert constraints[-2] == '(assert (or (and (not plaintext_10) (not key_10) (not and_0_0_10) (not hw_and_0_0_10)) (and plaintext_10 hw_and_0_0_10) (and key_10 hw_and_0_0_10)))'
    assert constraints[-1] == '(assert (or (and (not plaintext_11) (not key_11) (not and_0_0_11) (not hw_and_0_0_11)) (and plaintext_11 hw_and_0_0_11) (and key_11 hw_and_0_0_11)))'


def test_smt_xor_linear_mask_propagation_constraints():
    cipher = AndCipher(word_bit_size=12, number_of_inputs=2)
    and_component = cipher.component_from(0, 0)
    output_bit_ids, constraints = and_component.smt_xor_linear_mask_propagation_constraints()

    assert output_bit_ids[0] == 'and_0_0_0_i'
    assert output_bit_ids[1] == 'and_0_0_1_i'
    assert output_bit_ids[-2] == 'hw_and_0_0_10_o'
    assert output_bit_ids[-1] == 'hw_and_0_0_11_o'

    assert constraints[0] == '(assert (or (and (not and_0_0_0_i) (not and_0_0_12_i) (not and_0_0_0_o) (not hw_and_0_0_0_o)) (and and_0_0_0_o hw_and_0_0_0_o)))'
    assert constraints[1] == '(assert (or (and (not and_0_0_1_i) (not and_0_0_13_i) (not and_0_0_1_o) (not hw_and_0_0_1_o)) (and and_0_0_1_o hw_and_0_0_1_o)))'
    assert constraints[-2] == '(assert (or (and (not and_0_0_10_i) (not and_0_0_22_i) (not and_0_0_10_o) (not hw_and_0_0_10_o)) (and and_0_0_10_o hw_and_0_0_10_o)))'
    assert constraints[-1] == '(assert (or (and (not and_0_0_11_i) (not and_0_0_23_i) (not and_0_0_11_o) (not hw_and_0_0_11_o)) (and and_0_0_11_o hw_and_0_0_11_o)))'
