from claasp.ciphers.block_ciphers.ballet_block_cipher import BalletBlockCipher

"""
Following are some testing vectors:
1. Ballet 128/128
plaintext = 0xe60e830ca56ec84814fbd2579993d435
key = 0xcd52c514213c9632514fb60a64840881
ciphertext = 0xc1c2e89c1581d166f3c87b5999f87a9f

2. Ballet 128/256
plaintext = 0xc419afdd747886b9f8e6890a3db19fa3
key = 0x8e1d7bede15b5fae9e67b09c734829149b5e7f8d02f49fccaa1437574d9f792b
ciphertext = 0x636f07e9df66d2ec34d0ad3bb87e0f79

3. Ballet 256/256
plaintext = 0xfdc0bf9c6bfeb2ffd160128e5190af6cdad291114d953986de472ad8be6ea8c7
key = 0x19f29ab90c31da41d2013ed7128338ad7eacb494fae0572801c30948454cb1ca
ciphertext = 0x2d07ee91d634c27f3155f9e575bdc634acaa611e3654c4ce06ea130e9bc394ee

Reference: http://www.jcr.cacrnet.org.cn/EN/10.13868/j.cnki.jcr.000335
"""

def test_ballet_block_cipher():
    ballet = BalletBlockCipher()
    assert ballet.type == 'block_cipher'
    assert ballet.family_name == 'ballet'
    assert ballet.number_of_rounds == 46
    assert ballet.id == 'ballet_p128_k128_o128_r46'
    assert ballet.component_from(0, 0).id == 'xor_0_0'

    ballet = BalletBlockCipher(number_of_rounds=4)
    assert ballet.number_of_rounds == 4
    assert ballet.id == 'ballet_p128_k128_o128_r4'
    assert ballet.component_from(3, 0).id == 'xor_3_0'

    ballet = BalletBlockCipher(block_bit_size=128, key_bit_size=128)
    plaintext = 0xe60e830ca56ec84814fbd2579993d435
    key = 0xcd52c514213c9632514fb60a64840881
    ciphertext = 0xc1c2e89c1581d166f3c87b5999f87a9f
    assert ballet.evaluate([plaintext, key]) == ciphertext
    assert ballet.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext

    ballet = BalletBlockCipher(block_bit_size=128, key_bit_size=256)
    plaintext = 0xc419afdd747886b9f8e6890a3db19fa3
    key = 0x8e1d7bede15b5fae9e67b09c734829149b5e7f8d02f49fccaa1437574d9f792b
    ciphertext = 0x636f07e9df66d2ec34d0ad3bb87e0f79
    assert ballet.evaluate([plaintext, key]) == ciphertext
    assert ballet.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext

    ballet = BalletBlockCipher(block_bit_size=256, key_bit_size=256)
    plaintext = 0xfdc0bf9c6bfeb2ffd160128e5190af6cdad291114d953986de472ad8be6ea8c7
    key = 0x19f29ab90c31da41d2013ed7128338ad7eacb494fae0572801c30948454cb1ca
    ciphertext = 0x2d07ee91d634c27f3155f9e575bdc634acaa611e3654c4ce06ea130e9bc394ee
    assert ballet.evaluate([plaintext, key]) == ciphertext
    assert ballet.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext
