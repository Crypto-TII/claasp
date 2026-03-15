from claasp.ciphers.block_ciphers.gost_block_cipher import GostBlockCipher


def test_gost_block_cipher():
    """
    Test Gost block cipher against the test vector from https://www.rfc-editor.org/rfc/rfc8891.pdf
    """
    gost = GostBlockCipher()
    assert gost.type == "block_cipher"
    assert gost.family_name == "gost"
    assert gost.number_of_rounds == 32
    assert gost.id == "gost_p64_k256_o64_r32"
    assert gost.component_from(0, 0).id == "modadd_0_0"

    gost = GostBlockCipher(number_of_rounds=4)
    assert gost.number_of_rounds == 4
    assert gost.id == "gost_p64_k256_o64_r4"
    assert gost.component_from(3, 0).id == "modadd_3_0"

    gost = GostBlockCipher()
    plaintext = 0xFEDCBA9876543210
    key = 0xFFEEDDCCBBAA99887766554433221100F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF
    ciphertext = 0x4EE901E5C2D8CA3D
    assert gost.evaluate([plaintext, key]) == ciphertext
    assert gost.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext
    assert gost.evaluate_vectorized_gpu([plaintext, key], evaluate_api=True) == ciphertext
