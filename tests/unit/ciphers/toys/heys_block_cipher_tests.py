"""No official conformance test vector is provided in the Heys tutorial reference."""

from claasp.ciphers.toys.heys_block_cipher import HeysBlockCipher


def test_heys_block_cipher():
    cipher = HeysBlockCipher()
    key = 0x0123456789ABCDEF0123
    plaintext = 0x1234
    ciphertext = 0xe582
    assert cipher.evaluate([plaintext, key]) == ciphertext