from claasp.ciphers.toys.or_block_cipher import OrBlockCipher


def test_or_block_cipher_component_id():
    assert OrBlockCipher(block_bit_size=32).component_from(0, 0).id == "or_0_0"
