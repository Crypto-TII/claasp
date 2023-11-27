from claasp.ciphers.hash_functions.sha2_hash_function import SHA2HashFunction


def test_sha2_hash_function():
    sha2 = SHA2HashFunction()
    assert sha2.number_of_rounds == 65
    assert sha2.type == 'hash_function'
    assert sha2.family_name == 'SHA2_family'
    assert sha2.id == 'SHA2_family_k512_o256_r65'
    assert sha2.component_from(0, 0).id == 'constant_0_0'

    sha2 = SHA2HashFunction(number_of_rounds=4)
    assert sha2.number_of_rounds == 4
    assert sha2.id == 'SHA2_family_k512_o256_r4'
    assert sha2.component_from(3, 0).id == 'constant_3_0'

    sha2 = SHA2HashFunction()
    plaintext = int('0x4368696172618000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                    '0000000000000000000000000000000030', 16)
    ciphertext = 0x0d8d2647a12b0d544989a6b03603b8b3c27e2c4e0be08671745366d1a8bc4d95
    assert sha2.evaluate([plaintext]) == ciphertext

    plaintext = int('0x68656C6C6F776F726C6480000000000000000000000000000000000000000000000000000000000000000000000000'
                    '0000000000000000000000000000000050', 16)
    ciphertext = 0x936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af
    assert sha2.evaluate([plaintext]) == ciphertext

    sha2 = SHA2HashFunction(output_bit_size=224)
    plaintext = int('0x686F77617265796F75646F696E67746F64617980000000000000000000000000000000000000000000000000000000'
                    '0000000000000000000000000000000098', 16)
    ciphertext = 0xc5341a30288d8e3cb4fac54943d13134790010aecd919e6784f3694f
    assert sha2.evaluate([plaintext]) == ciphertext

    sha2 = SHA2HashFunction(output_bit_size=512, number_of_rounds=80)
    plaintext = int('0x7965737465726461796977656E74746F74686562656163686576656E74686F756768696C696B657468656D6F756E74'
                    '61696E6D6F72658000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                    '0000000000000000000000000000000000000000000000000000000000000001b0', 16)
    ciphertext = int('0x2e894af7e3825b01e1d254a0ee6b186d2aebd11a6bc9a7446263357ddc1f9fea2194d9c2cdc6c5f554b428d403f30'
                     'a83df1c029f07c7835db52bc99735517ed1', 16)
    assert sha2.evaluate([plaintext]) == ciphertext

    sha2 = SHA2HashFunction(output_bit_size=384, number_of_rounds=80)
    plaintext = int('0x697472696564736F68617264616E64676F74736F666172627574696E746865656E6469746469646E746576656E6D61'
                    '747465728000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                    '000000000000000000000000000000000000000000000000000000000000000198', 16)
    ciphertext = 0xba94bfa051856d99251101d5bb718079e163f77f240ff03b5aac0232670589c2279bfb35888ef90970d19bc0c966602a
    assert sha2.evaluate([plaintext]) == ciphertext
