from claasp.ciphers.toys.identity_cipher import IdentityCipher


def test_identity_cipher():
    identity = IdentityCipher()
    assert identity.type == 'permutation'
    assert identity.family_name == 'identity_cipher'
    assert identity.number_of_rounds == 1
    assert identity.id == 'identity_cipher_p32_o32_r1'
    assert identity.file_name == 'identity_cipher_p32_o32_r1.py'
    assert identity.component_from(0, 0).id == 'cipher_output_0_0'

    identity = IdentityCipher(block_bit_size=16)
    assert identity.number_of_rounds == 1
    assert identity.id == 'identity_cipher_p16_o16_r1'
    assert identity.component_from(0, 0).id == 'cipher_output_0_0'

    identity = IdentityCipher()
    plaintext = 0x00000000
    ciphertext = 0x00000000
    assert identity.evaluate([plaintext]) == ciphertext
    assert identity.evaluate_vectorized([plaintext], evaluate_api=True) == ciphertext

    identity = IdentityCipher(block_bit_size=16)
    plaintext = 0xffff
    ciphertext = 0xffff
    assert identity.evaluate([plaintext]) == ciphertext
    assert identity.evaluate_vectorized([plaintext], evaluate_api=True) == ciphertext
