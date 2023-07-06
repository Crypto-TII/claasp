from claasp.ciphers.hash_functions.md5_hash_function import MD5HashFunction


def test_md5_hash_function():
    md5 = MD5HashFunction()
    assert md5.number_of_rounds == 64
    assert md5.type == 'hash_function'
    assert md5.family_name == 'MD5'
    assert md5.id == 'MD5_k512_o64_r64'
    assert md5.component_from(0, 0).id == 'constant_0_0'

    md5 = MD5HashFunction(number_of_rounds=4)
    assert md5.number_of_rounds == 4
    assert md5.id == 'MD5_k512_o64_r4'
    assert md5.component_from(3, 0).id == 'constant_3_0'

    md5 = MD5HashFunction()
    plaintext = int('0x5175656c2066657a20736768656d626f20636f70726520646176616e74692e80000000000000000000000000000000'
                    '00000000000000000000000000000000f8', 16)
    ciphertext = 0x3956fba8c05053e5a27040b8ab9a7545
    assert md5.evaluate([plaintext]) == ciphertext

    plaintext = int('0x5072616e7a6f206427616371756120666120766f6c746920736768656d62692e800000000000000000000000000000'
                    '0000000000000000000000000000000100', 16)
    ciphertext = 0x1a062465be03e510e6755e320664156c
    assert md5.evaluate([plaintext]) == ciphertext

    plaintext = int('0x4368652074656d70692062726576692c207a696f2c207175616e646f20736f6c66656767692e800000000000000000'
                    '0000000000000000000000000000000130', 16)
    ciphertext = 0xd90762a3fa2e1b39344295f56ce33098
    assert md5.evaluate([plaintext]) == ciphertext

    plaintext = int('0x5175616c636865206e6f74697a696120706176657365206d69206661207362616469676c696172652e800000000000'
                    '0000000000000000000000000000000148', 16)
    ciphertext = 0xc784565cb3c0991ea04e32314599c733
    assert md5.evaluate([plaintext]) == ciphertext

    plaintext = int('0x496e207175656c2063616d706f2073692074726f76616e2066756e67686920696e206162626f6e64616e7a612e8000'
                    '0000000000000000000000000000000168', 16)
    ciphertext = 0x6b0cebf5c4d3e731b56881011179725b
    assert md5.evaluate([plaintext]) == ciphertext

    plaintext = int('0x5175616c636865207661676f20696f6e65207469706f207a6f6c666f2c2062726f6d6f2c20736f64696f2e80000000'
                    '0000000000000000000000000000000158', 16)
    ciphertext = 0xa9be46cd1b651b325365939a2a4bc7e2
    assert md5.evaluate([plaintext]) == ciphertext
