import sys
from io import StringIO

from claasp.ciphers.toys.toy_cipherFOUR import ToyCipherFOUR

def test_toycipherFOUR():
    toy_cipher = ToyCipherFOUR()
    assert toy_cipher.number_of_rounds == 5

    plaintext = 0x1234
    key = 0x111122223333444455556666
    assert toy_cipher.evaluate([plaintext, key]) == 17897
    assert hex(toy_cipher.evaluate([plaintext, key])) == '0x45e9'

    expected_evaluation = """
Round_0

xor_0_0_input = 0x12341111
xor_0_0_output = 0x0325
sbox_0_1_input = 0x0
sbox_0_1_output = 0xc
sbox_0_2_input = 0x3
sbox_0_2_output = 0xb
sbox_0_3_input = 0x2
sbox_0_3_output = 0x6
sbox_0_4_input = 0x5
sbox_0_4_output = 0x0
linear_layer_0_5_input = 0xcb60
linear_layer_0_5_output = 0xca64
intermediate_output_0_6_input = 0xca64
intermediate_output_0_6_output = 0xca64

Round_1

xor_1_0_input = 0xca642222
xor_1_0_output = 0xe846
sbox_1_1_input = 0xe
sbox_1_1_output = 0x1
sbox_1_2_input = 0x8
sbox_1_2_output = 0x3
sbox_1_3_input = 0x4
sbox_1_3_output = 0x9
sbox_1_4_input = 0x6
sbox_1_4_output = 0xa
linear_layer_1_5_input = 0x139a
linear_layer_1_5_output = 0x305e
intermediate_output_1_6_input = 0x305e
intermediate_output_1_6_output = 0x305e

Round_2

xor_2_0_input = 0x305e3333
xor_2_0_output = 0x036d
sbox_2_1_input = 0x0
sbox_2_1_output = 0xc
sbox_2_2_input = 0x3
sbox_2_2_output = 0xb
sbox_2_3_input = 0x6
sbox_2_3_output = 0xa
sbox_2_4_input = 0xd
sbox_2_4_output = 0x7
linear_layer_2_5_input = 0xcba7
linear_layer_2_5_output = 0xe975
intermediate_output_2_6_input = 0xe975
intermediate_output_2_6_output = 0xe975

Round_3

xor_3_0_input = 0xe9754444
xor_3_0_output = 0xad31
sbox_3_1_input = 0xa
sbox_3_1_output = 0xf
sbox_3_2_input = 0xd
sbox_3_2_output = 0x7
sbox_3_3_input = 0x3
sbox_3_3_output = 0xb
sbox_3_4_input = 0x1
sbox_3_4_output = 0x5
linear_layer_3_5_input = 0xf7b5
linear_layer_3_5_output = 0xadef
intermediate_output_3_6_input = 0xadef
intermediate_output_3_6_output = 0xadef

Round_4

xor_4_0_input = 0xadef5555
xor_4_0_output = 0xf8ba
sbox_4_1_input = 0xf
sbox_4_1_output = 0x2
sbox_4_2_input = 0x8
sbox_4_2_output = 0x3
sbox_4_3_input = 0xb
sbox_4_3_output = 0x8
sbox_4_4_input = 0xa
sbox_4_4_output = 0xf
xor_4_5_input = 0x238f6666
xor_4_5_output = 0x45e9
cipher_output_4_6_input = 0x45e9
cipher_output_4_6_output = 0x45e9
"""

    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    evaluation = hex(toy_cipher.evaluate([0x1234, 0x111122223333444455556666], verbosity=True))
    sys.stdout = old_stdout
    assert evaluation == '0x45e9'
    assert result.getvalue() == expected_evaluation

    toy_cipher = ToyCipherFOUR(block_bit_size=16, key_bit_size=80, number_of_rounds=10)
    assert hex(toy_cipher.evaluate([0x5678, 0x22224444666688889999aaaa])) == '0xbeec'

    toy_cipher = ToyCipherFOUR(block_bit_size=16, key_bit_size=80,
                               sbox=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0],
                               permutations=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
                               number_of_rounds=5)
    assert toy_cipher.evaluate([0x9abc, 0x3333555577779999bbbbcccc]) == 61185




