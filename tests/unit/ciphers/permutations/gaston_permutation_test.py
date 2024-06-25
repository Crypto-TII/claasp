from claasp.ciphers.permutations.gaston_permutation import GastonPermutation


def test_gaston_permutation():
    gaston = GastonPermutation(number_of_rounds=12)
    assert gaston.number_of_rounds == 12

    assert gaston.component_from(0, 0).id == 'rot_0_0'

    plaintext = 0x0
    ciphertext = 0x88B326096BEBC6356CA8FB64BC5CE6CAF1CE3840D819071354D70067438689B5F17FE863F958F32B
    assert gaston.evaluate([plaintext]) == ciphertext

    plaintext = 0x1F4AD9906DA6A2544B84D7F83F2BDDFA468A0853578A00E36C05A0506DF7F66E4EFB22112453C964
    ciphertext = 0x1BA89B5B5C4583B622135709AE53417D9847B975E9EC9F3DCE042DF2A402591D563EC68FC30307EA
    assert gaston.evaluate([plaintext]) == ciphertext

    plaintext = 0xFFFFFFFFFFFFFFFF0123456789ABCDEFFEDCBA9876543210AAAAAAAAAAAAAAAA0101010101010101
    ciphertext = 0x3117D51B14937067338F17F773C13F79DFB86E0868D252AB0D461D35EB863DE708BCE3E354C7231A
    assert gaston.evaluate([plaintext]) == ciphertext
    assert gaston.evaluate_vectorized([plaintext], evaluate_api=True) == ciphertext
