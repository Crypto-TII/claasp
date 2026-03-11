from claasp.ciphers.toys.and_block_cipher import AndBlockCipher


def test_and_block_cipher_component_id():
    assert AndBlockCipher(block_bit_size=12).component_from(0, 0).id == "and_0_0"
