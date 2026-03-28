from claasp.ciphers.single_component_ciphers.permutation_cipher import PermutationCipher


def test_permutation_cipher_is_bijection_on_small_domain():
    cipher = PermutationCipher(bit_size=4, permutation_description=[3, 2, 1, 0])
    outputs = {cipher.evaluate([x]) for x in range(16)}
    assert cipher.type == "permutation"
    assert len(outputs) == 16
