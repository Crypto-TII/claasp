from claasp.ciphers.permutations.ascon_sbox_sigma_no_matrix_permutation import AsconSboxSigmaNoMatrixPermutation


def test_ascon_sbox_sigma_no_matrix_permutation():
    ascon = AsconSboxSigmaNoMatrixPermutation()
    assert ascon.family_name == 'ascon_sbox_sigma_no_matrix'
    assert ascon.type == 'permutation'
    assert ascon.number_of_rounds == 12
    assert ascon.id == 'ascon_sbox_sigma_no_matrix_p320_o320_r12'
    assert ascon.component_from(0, 0).id == 'constant_0_0'

    ascon = AsconSboxSigmaNoMatrixPermutation(number_of_rounds=4)
    assert ascon.number_of_rounds == 4
    assert ascon.id == 'ascon_sbox_sigma_no_matrix_p320_o320_r4'
    assert ascon.component_from(3, 0).id == 'constant_3_0'

    ascon = AsconSboxSigmaNoMatrixPermutation(number_of_rounds=1)
    plaintext = 0x0
    ciphertext = 0x000964b00000004b000000009600021353ffffffffffff9012e580000000004b0000000000000000
    assert ascon.evaluate([plaintext]) == ciphertext

    ascon = AsconSboxSigmaNoMatrixPermutation(number_of_rounds=12)
    plaintext = 0x0
    ciphertext = 0x78ea7ae5cfebb1089b9bfb8513b560f76937f83e03d11a503fe53f36f2c1178c045d648e4def12c9
    assert ascon.evaluate([plaintext]) == ciphertext

    plaintext = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    ciphertext = 0x578668ca0d187c96bdb2538e9f04d72f39c36f2c39f907578bea1417e9baa8314f27fa9fd7588347
    assert ascon.evaluate([plaintext]) == ciphertext

    plaintext = 0x78ea7ae5cfebb1089b9bfb8513b560f76937f83e03d11a503fe53f36f2c1178c045d648e4def12c9
    ciphertext = 0x0e87fa7d4b40022e94f14f2525499af530a1d1621866701c4b419cf3ae4c9962b11ce0a087175b71
    assert ascon.evaluate([plaintext]) == ciphertext
