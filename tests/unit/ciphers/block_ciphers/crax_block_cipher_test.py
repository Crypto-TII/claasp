from claasp.ciphers.block_ciphers.crax_block_cipher import CraxBlockCipher


def test_crax_block_cipher():
    crax = CraxBlockCipher()
    assert crax.type == 'block_cipher'
    assert crax.family_name == 'crax'
    assert crax.number_of_rounds == 10
    assert crax.id == 'crax_p64_k128_o64_r10'
    assert crax.component_from(0, 0).id == 'constant_0_0'


def test_crax_block_cipher_reduced_rounds():
    crax = CraxBlockCipher(number_of_rounds=4)
    assert crax.number_of_rounds == 4
    assert crax.id == 'crax_p64_k128_o64_r4'


def test_crax_block_cipher_evaluate_tv1():
    # Test vector 1: zero plaintext and zero key.
    # Source: https://github.com/jedisct1/zig-lwbc32/blob/main/src/crax.zig
    crax = CraxBlockCipher()
    pt = 0x0000000000000000
    key = 0x00000000000000000000000000000000
    assert crax.evaluate([pt, key]) == 0x72edfac9453f5f4c


def test_crax_block_cipher_evaluate_tv2():
    # Test vector 2: incremental key, incremental plaintext.
    # Source: https://github.com/jedisct1/zig-lwbc32/blob/main/src/crax.zig
    crax = CraxBlockCipher()
    pt = 0x3322110077665544
    key = 0x03020100070605040b0a09080f0e0d0c
    assert crax.evaluate([pt, key]) == 0x6203c5be7ae77255
