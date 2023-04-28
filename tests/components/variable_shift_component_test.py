from claasp.ciphers.block_ciphers.raiden_block_cipher import RaidenBlockCipher


def test_cms_constraints():
    raiden = RaidenBlockCipher(number_of_rounds=3)
    variable_shift_component = raiden.component_from(0, 2)
    output_bit_ids, constraints = variable_shift_component.cms_constraints()

    assert output_bit_ids[0] == 'var_shift_0_2_0'
    assert output_bit_ids[1] == 'var_shift_0_2_1'
    assert output_bit_ids[2] == 'var_shift_0_2_2'

    assert constraints[-3] == '-var_shift_0_2_31 state_3_var_shift_0_2_31'
    assert constraints[-2] == '-var_shift_0_2_31 -key_91'
    assert constraints[-1] == 'var_shift_0_2_31 -state_3_var_shift_0_2_31 key_91'


def test_cp_constraints():
    raiden = RaidenBlockCipher(number_of_rounds=3)
    variable_shift_component = raiden.component_from(0, 2)
    declarations, constraints = variable_shift_component.cp_constraints()

    assert declarations == ['array[0..31] of var 0..1: pre_var_shift_0_2;', 'var int: shift_amount_var_shift_0_2;']

    assert constraints[0] == 'constraint pre_var_shift_0_2[0]=key[0];'
    assert constraints[-3] == 'constraint pre_var_shift_0_2[31]=key[31];'
    assert constraints[-2] == 'constraint bitArrayToInt([key[i]|i in 91..95],shift_amount_var_shift_0_2);'
    assert constraints[-1] == 'constraint var_shift_0_2=LShift(pre_var_shift_0_2,shift_amount_var_shift_0_2);'


def test_sat_constraints():
    raiden = RaidenBlockCipher(number_of_rounds=3)
    variable_shift_component = raiden.component_from(0, 2)
    output_bit_ids, constraints = variable_shift_component.sat_constraints()

    assert output_bit_ids[0] == 'var_shift_0_2_0'
    assert output_bit_ids[1] == 'var_shift_0_2_1'
    assert output_bit_ids[2] == 'var_shift_0_2_2'

    assert constraints[-3] == '-var_shift_0_2_31 state_3_var_shift_0_2_31'
    assert constraints[-2] == '-var_shift_0_2_31 -key_91'
    assert constraints[-1] == 'var_shift_0_2_31 -state_3_var_shift_0_2_31 key_91'


def test_smt_constraints():
    raiden = RaidenBlockCipher(number_of_rounds=3)
    variable_shift_component = raiden.component_from(0, 2)
    output_bit_ids, constraints = variable_shift_component.smt_constraints()

    assert output_bit_ids[0] == 'state_0_var_shift_0_2_0'
    assert output_bit_ids[1] == 'state_0_var_shift_0_2_1'
    assert output_bit_ids[-2] == 'var_shift_0_2_30'
    assert output_bit_ids[-1] == 'var_shift_0_2_31'

    assert constraints[0] == '(assert (ite key_95 (= state_0_var_shift_0_2_0 key_1) (= state_0_var_shift_0_2_0 key_0)))'
    assert constraints[1] == '(assert (ite key_95 (= state_0_var_shift_0_2_1 key_2) (= state_0_var_shift_0_2_1 key_1)))'
    assert constraints[-2] == '(assert (ite key_91 (not var_shift_0_2_30) (= var_shift_0_2_30 ' \
                              'state_3_var_shift_0_2_30)))'
    assert constraints[-1] == '(assert (ite key_91 (not var_shift_0_2_31) (= var_shift_0_2_31 ' \
                              'state_3_var_shift_0_2_31)))'
