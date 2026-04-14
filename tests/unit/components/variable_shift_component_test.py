from claasp.components.variable_shift_component import VariableShift


def test_cms_constraints():
    variable_shift_component = VariableShift(0, 2, ['plaintext', 'key'], [list(range(32)), list(range(32))], 32, 1)
    output_bit_ids, constraints = variable_shift_component.cms_constraints()

    assert output_bit_ids[0] == 'var_shift_0_2_0'
    assert output_bit_ids[1] == 'var_shift_0_2_1'
    assert output_bit_ids[2] == 'var_shift_0_2_2'

    assert constraints[-3] == '-var_shift_0_2_31 state_3_var_shift_0_2_31'
    assert constraints[-2] == '-var_shift_0_2_31 -key_27'
    assert constraints[-1] == 'var_shift_0_2_31 -state_3_var_shift_0_2_31 key_27'


def test_cp_constraints():
    variable_shift_component = VariableShift(0, 2, ['plaintext', 'key'], [list(range(32)), list(range(32))], 32, 1)
    result = variable_shift_component.cp_constraints()
    declarations, constraints = result.declarations, result.constraints

    assert declarations == ['array[0..31] of var 0..1: pre_var_shift_0_2;', 'var int: shift_amount_var_shift_0_2;']

    assert constraints[0] == 'constraint pre_var_shift_0_2[0]=plaintext[0];'
    assert constraints[-3] == 'constraint pre_var_shift_0_2[31]=plaintext[31];'
    assert constraints[-2] == 'constraint bitArrayToInt([key[i]|i in 27..31],shift_amount_var_shift_0_2);'
    assert constraints[-1] == 'constraint var_shift_0_2=RShift(pre_var_shift_0_2,shift_amount_var_shift_0_2);'


def test_sat_constraints():
    variable_shift_component = VariableShift(0, 2, ['plaintext', 'key'], [list(range(32)), list(range(32))], 32, 1)
    output_bit_ids, constraints = variable_shift_component.sat_constraints()

    assert output_bit_ids[0] == 'var_shift_0_2_0'
    assert output_bit_ids[1] == 'var_shift_0_2_1'
    assert output_bit_ids[2] == 'var_shift_0_2_2'

    assert constraints[-3] == '-var_shift_0_2_31 state_3_var_shift_0_2_31'
    assert constraints[-2] == '-var_shift_0_2_31 -key_27'
    assert constraints[-1] == 'var_shift_0_2_31 -state_3_var_shift_0_2_31 key_27'


def test_smt_constraints():
    variable_shift_component = VariableShift(0, 2, ['plaintext', 'key'], [list(range(32)), list(range(32))], 32, 1)
    output_bit_ids, constraints = variable_shift_component.smt_constraints()

    assert output_bit_ids[0] == 'state_0_var_shift_0_2_0'
    assert output_bit_ids[1] == 'state_0_var_shift_0_2_1'
    assert output_bit_ids[-2] == 'var_shift_0_2_30'
    assert output_bit_ids[-1] == 'var_shift_0_2_31'

    assert constraints[0] == '(assert (ite key_31 (= state_0_var_shift_0_2_0 plaintext_1) (= state_0_var_shift_0_2_0 plaintext_0)))'
    assert constraints[1] == '(assert (ite key_31 (= state_0_var_shift_0_2_1 plaintext_2) (= state_0_var_shift_0_2_1 plaintext_1)))'
    assert constraints[-2] == '(assert (ite key_27 (not var_shift_0_2_30) (= var_shift_0_2_30 ' \
                              'state_3_var_shift_0_2_30)))'
    assert constraints[-1] == '(assert (ite key_27 (not var_shift_0_2_31) (= var_shift_0_2_31 ' \
                              'state_3_var_shift_0_2_31)))'
