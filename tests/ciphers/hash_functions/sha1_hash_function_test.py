from claasp.ciphers.hash_functions.sha1_hash_function import SHA1HashFunction


def test_sha1_hash_function():
    sha1 = SHA1HashFunction()
    assert sha1.number_of_rounds == 80
    assert sha1.type == 'hash_function'
    assert sha1.family_name == 'SHA1'
    assert sha1.id == 'SHA1_k512_o160_r80'
    assert sha1.component_from(0, 0).id == 'constant_0_0'

    sha1 = SHA1HashFunction(number_of_rounds=4)
    assert sha1.number_of_rounds == 4
    assert sha1.id == 'SHA1_k512_o160_r4'
    assert sha1.component_from(3, 0).id == 'and_3_0'

    sha1 = SHA1HashFunction()
    plaintext = int('0x4368696172618000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                    '0000000000000000000000000000000030', 16)
    ciphertext = 0x04f0c8e0efe316e609390a3d98e97f5acc53c199
    assert sha1.evaluate([plaintext]) == ciphertext

    plaintext = int('0x68656c6c6f776f726c6480000000000000000000000000000000000000000000000000000000000000000000000000'
                    '0000000000000000000000000000000050', 16)
    ciphertext = 0x6adfb183a4a2c94a2f92dab5ade762a47889a5a1
    assert sha1.evaluate([plaintext]) == ciphertext

    plaintext = int('0x77657361776176657279626967616e696d616c61747468657a6f6f8000000000000000000000000000000000000000'
                    '00000000000000000000000000000000D8', 16)
    ciphertext = 0x3a8a662f3e65ef354784dcb6c35f38624596d500
    assert sha1.evaluate([plaintext]) == ciphertext

    plaintext = int('0x546865206170706c65206973206f6e20746865207461626c6580000000000000000000000000000000000000000000'
                    '00000000000000000000000000000000c8', 16)
    ciphertext = 0x11d6cc738400d6028a783839c2b53d1dc4d7a5bb
    assert sha1.evaluate([plaintext]) == ciphertext

    plaintext = int('0x492077616e7420736f6d652070616e63616b6573800000000000000000000000000000000000000000000000000000'
                    '00000000000000000000000000000000a0', 16)
    ciphertext = 0xa8b6079d4c7beecd288ec792f9adb81ee2287092
    assert sha1.evaluate([plaintext]) == ciphertext

    plaintext = int('0x6C657473686F7065666F72746865626573748000000000000000000000000000000000000000000000000000000000'
                    '0000000000000000000000000000000090', 16)
    ciphertext = 0x1c5fdb6b3f737e9fd8b2906a1f06d13dc21e794f
    assert sha1.evaluate([plaintext]) == ciphertext
