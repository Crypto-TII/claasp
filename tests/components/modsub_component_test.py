from claasp.ciphers.block_ciphers.raiden_block_cipher import RaidenBlockCipher
from claasp.cipher_modules.models.cp.cp_model import CpModel


def test_cms_constraints():
    raiden = RaidenBlockCipher(number_of_rounds=3)
    modsub_component = raiden.component_from(0, 7)
    output_bit_ids, constraints = modsub_component.cms_constraints()

    assert output_bit_ids[0] == 'temp_carry_plaintext_32'
    assert output_bit_ids[1] == 'temp_carry_plaintext_33'
    assert output_bit_ids[2] == 'temp_carry_plaintext_34'

    assert constraints[-3] == 'modsub_0_7_31 -modadd_0_4_31 temp_input_plaintext_63'
    assert constraints[-2] == 'modsub_0_7_31 modadd_0_4_31 -temp_input_plaintext_63'
    assert constraints[-1] == '-modsub_0_7_31 -modadd_0_4_31 -temp_input_plaintext_63'


def test_cp_constraints():
    raiden = RaidenBlockCipher(number_of_rounds=3)
    modsub_component = raiden.component_from(0, 7)
    output_bit_ids, constraints = modsub_component.cp_constraints()

    assert output_bit_ids[0] == 'array[0..31] of var 0..1: constant_modsub_0_7= array1d(0..31,[0, 0, 0, 0, 0, 0, 0, ' \
                                '0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);'
    assert output_bit_ids[-1] == 'array[0..31] of var 0..1:minus_pre_modsub_0_7_1;'

    assert constraints[0] == 'constraint pre_modsub_0_7_0[0]=modadd_0_4[0];'
    assert constraints[1] == 'constraint pre_modsub_0_7_0[1]=modadd_0_4[1];'
    assert constraints[2] == 'constraint pre_modsub_0_7_0[2]=modadd_0_4[2];'
    assert constraints[-3] == 'constraint pre_minus_pre_modsub_0_7_1[31]=(pre_modsub_0_7_1[31] + 1) mod 2;'
    assert constraints[-2] == 'constraint modadd(pre_minus_pre_modsub_0_7_1, constant_modsub_0_7, ' \
                              'minus_pre_modsub_0_7_1);'
    assert constraints[-1] == 'constraint modadd(pre_modsub_0_7_0,minus_pre_modsub_0_7_1,modsub_0_7);'


def test_cp_xor_differential_propagation_constraints():
    raiden = RaidenBlockCipher(number_of_rounds=3)
    modsub_component = raiden.component_from(0, 7)
    cp_model = CpModel(raiden)
    output_bit_ids, constraints = modsub_component.cp_xor_differential_propagation_constraints(cp_model)
    
    assert output_bit_ids[0] == 'array[0..31] of var 0..1: pre_modsub_0_7_0;'
    assert output_bit_ids[-1] == 'array[0..31] of var 0..1: eq_modsub_0_7 = Eq(Shi_pre_modsub_0_7_1, Shi_pre_modsub_0_7_0, Shi_modsub_0_7);'

    assert constraints[0] == 'constraint pre_modsub_0_7_0[0] = modadd_0_4[0];'
    assert constraints[1] == 'constraint pre_modsub_0_7_0[1] = modadd_0_4[1];'
    assert constraints[2] == 'constraint pre_modsub_0_7_0[2] = modadd_0_4[2];'
    assert constraints[-3] == 'constraint pre_modsub_0_7_1[30] = plaintext[62];'
    assert constraints[-2] == 'constraint pre_modsub_0_7_1[31] = plaintext[63];'
    assert constraints[-1] == 'constraint forall(j in 0..31)(if eq_modsub_0_7[j] = 1 then (sum([pre_modsub_0_7_1[j], ' \
                              'pre_modsub_0_7_0[j], modsub_0_7[j]]) mod 2) = Shi_pre_modsub_0_7_0[j] else true endif) /\\ p[0] = 32-sum(eq_modsub_0_7);'


def test_sat_constraints():
    raiden = RaidenBlockCipher(number_of_rounds=3)
    modsub_component = raiden.component_from(0, 7)
    output_bit_ids, constraints = modsub_component.sat_constraints()

    assert output_bit_ids[0] == 'temp_carry_plaintext_32'
    assert output_bit_ids[1] == 'temp_carry_plaintext_33'
    assert output_bit_ids[2] == 'temp_carry_plaintext_34'
    assert constraints[-3] == 'modsub_0_7_31 -modadd_0_4_31 temp_input_plaintext_63'
    assert constraints[-2] == 'modsub_0_7_31 modadd_0_4_31 -temp_input_plaintext_63'
    assert constraints[-1] == '-modsub_0_7_31 -modadd_0_4_31 -temp_input_plaintext_63'


def test_smt_constraints():
    raiden = RaidenBlockCipher(number_of_rounds=3)
    modsub_component = raiden.component_from(0, 7)
    output_bit_ids, constraints = modsub_component.smt_constraints()

    assert output_bit_ids[0] == 'temp_carry_plaintext_32'
    assert output_bit_ids[1] == 'temp_carry_plaintext_33'
    assert output_bit_ids[-2] == 'modsub_0_7_30'
    assert output_bit_ids[-1] == 'modsub_0_7_31'

    assert constraints[0] == '(assert (= temp_carry_plaintext_32 (and (not plaintext_33) temp_carry_plaintext_33)))'
    assert constraints[1] == '(assert (= temp_carry_plaintext_33 (and (not plaintext_34) temp_carry_plaintext_34)))'
    assert constraints[-2] == '(assert (= modsub_0_7_30 (xor modadd_0_4_30 temp_input_plaintext_62 ' \
                              'carry_modsub_0_7_30)))'
    assert constraints[-1] == '(assert (= modsub_0_7_31 (xor modadd_0_4_31 temp_input_plaintext_63)))'
