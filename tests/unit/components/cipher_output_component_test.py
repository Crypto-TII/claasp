from claasp.cipher_modules.models.cp.cp_model import CpModel
from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher


def test_cp_constraints():
    speck = SpeckBlockCipher(number_of_rounds=3)
    output_component = speck.component_from(2, 12)
    declarations, constraints = output_component.cp_constraints()

    assert declarations == []

    assert constraints[0] == 'constraint cipher_output_2_12[0] = xor_2_8[0];'
    assert constraints[1] == 'constraint cipher_output_2_12[1] = xor_2_8[1];'
    assert constraints[-1] == 'constraint cipher_output_2_12[31] = xor_2_10[15];'


def test_cp_wordwise_deterministic_truncated_xor_differential_constraints():
    aes = AESBlockCipher(number_of_rounds=3)
    cp = CpModel(aes)
    output_component = aes.component_from(0, 35)
    declarations, constraints = output_component.cp_wordwise_deterministic_truncated_xor_differential_constraints(cp)

    assert declarations == []

    assert constraints[0] == 'constraint intermediate_output_0_35_value[0] = xor_0_31_value[0];'
    assert constraints[-1] == 'constraint intermediate_output_0_35_active[15] = xor_0_34_active[3];'
