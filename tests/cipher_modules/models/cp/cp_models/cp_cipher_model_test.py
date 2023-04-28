from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.cp.cp_models.cp_cipher_model import CpCipherModel
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list


def test_build_cipher_model():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=4)
    cp = CpCipherModel(speck)
    fixed_variables = [set_fixed_variables('key', 'equal', range(64), integer_to_bit_list(0, 64, 'little')),
                       set_fixed_variables('plaintext', 'equal', range(32), integer_to_bit_list(0, 32, 'little'))]
    cp.build_cipher_model(fixed_variables)
    assert len(cp.model_constraints) == 1156
    assert cp.model_constraints[2] == 'array[0..31] of var 0..1: plaintext;'
    assert cp.model_constraints[3] == 'array[0..63] of var 0..1: key;'
    assert cp.model_constraints[4] == 'array[0..15] of var 0..1: rot_0_0;'
