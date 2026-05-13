from claasp.ciphers.toys.heys_spn_cipher import Heys_SPN

def test_heys_spn():
    cipher = Heys_SPN()
    key = 0x0123456789ABCDEF0123
    plaintext = 0x1234
    ciphertext = 0xe582
    assert cipher.evaluate([plaintext, key]) == ciphertext