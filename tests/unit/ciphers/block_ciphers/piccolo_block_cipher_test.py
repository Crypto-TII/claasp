from claasp.ciphers.block_ciphers.piccolo_block_cipher import PiccoloBlockCipher


def test_piccolo_block_cipher_80():
    """Test piccolo-80 with test vector from [SIHMAS2011]_."""
    key = 0x00112233445566778899
    plaintext = 0x0123456789abcdef
    expected_ciphertext = 0x8d2bff9935f84056

    piccolo = PiccoloBlockCipher()
    ciphertext = piccolo.evaluate([plaintext, key])

    assert ciphertext == expected_ciphertext