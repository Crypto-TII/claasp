from claasp.ciphers.block_ciphers.identity_block_cipher import IdentityBlockCipher


def test_identity_block_cipher():
    identity = IdentityBlockCipher()
    assert identity.type == 'block_cipher'
    assert identity.family_name == 'identity_block_cipher'
    assert identity.number_of_rounds == 1
    assert identity.id == 'identity_block_cipher_p32_k32_o32_r1'
    assert identity.file_name == 'identity_block_cipher_p32_k32_o32_r1.py'
    assert identity.component_from(0, 0).id == 'concatenate_0_0'

    identity = IdentityBlockCipher(block_bit_size=32, key_bit_size=16, number_of_rounds=2)
    assert identity.number_of_rounds == 2
    assert identity.id == 'identity_block_cipher_p32_k16_o32_r2'
    assert identity.component_from(1, 0).id == 'concatenate_1_0'

    identity = IdentityBlockCipher()
    plaintext = 0x00000000
    key = 0xffffffff
    ciphertext = 0x00000000
    assert identity.evaluate([plaintext, key]) == ciphertext

    identity = IdentityBlockCipher(block_bit_size=32, key_bit_size=16)
    plaintext = 0xffffffff
    key = 0xffff
    ciphertext = 0xffffffff
    assert identity.evaluate([plaintext, key]) == ciphertext
