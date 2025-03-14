import sys
from io import StringIO

from claasp.ciphers.toys.toyfeistel import ToyFeistel


def test_toyfeistel():
    toyfeistel = ToyFeistel()
    assert toyfeistel.number_of_rounds == 5

    plaintext = 0x3F
    key = 0x3F
    ciphertext = 0x8E
    assert toyfeistel.evaluate([plaintext, key]) == ciphertext

    assert hex(toyfeistel.evaluate([plaintext, key])) == '0x8e'
    expected_evaluation = """
Round_0

intermediate_output_0_0_input = 0x3
intermediate_output_0_0_output = 0x3
xor_0_1_input = 0xf3
xor_0_1_output = 0xc
sbox_0_2_input = 0xc
sbox_0_2_output = 0x7
xor_0_3_input = 0x73
xor_0_3_output = 0x4
intermediate_output_0_4_input = 0xf4
intermediate_output_0_4_output = 0xf4
rot_0_5_input = 0x3e
rot_0_5_output = 0xc7
xor_0_6_input = 0x3ec7
xor_0_6_output = 0xf9
constant_0_7_input = 0b0
constant_0_7_output = 0x1
xor_0_8_input = 0x91
xor_0_8_output = 0x8
intermediate_output_0_9_input = 0xf8
intermediate_output_0_9_output = 0xf8

Round_1

intermediate_output_1_0_input = 0xf
intermediate_output_1_0_output = 0xf
xor_1_1_input = 0x4f
xor_1_1_output = 0xb
sbox_1_2_input = 0xb
sbox_1_2_output = 0x3
xor_1_3_input = 0x3f
xor_1_3_output = 0xc
intermediate_output_1_4_input = 0x4c
intermediate_output_1_4_output = 0x4c
rot_1_5_input = 0xf8
rot_1_5_output = 0x1f
xor_1_6_input = 0xf81f
xor_1_6_output = 0xe7
constant_1_7_input = 0b0
constant_1_7_output = 0x2
xor_1_8_input = 0x72
xor_1_8_output = 0x5
intermediate_output_1_9_input = 0xe5
intermediate_output_1_9_output = 0xe5

Round_2

intermediate_output_2_0_input = 0xe
intermediate_output_2_0_output = 0xe
xor_2_1_input = 0xce
xor_2_1_output = 0x2
sbox_2_2_input = 0x2
sbox_2_2_output = 0xf
xor_2_3_input = 0xf4
xor_2_3_output = 0xb
intermediate_output_2_4_input = 0xcb
intermediate_output_2_4_output = 0xcb
rot_2_5_input = 0xe5
rot_2_5_output = 0xbc
xor_2_6_input = 0xe5bc
xor_2_6_output = 0x59
constant_2_7_input = 0b0
constant_2_7_output = 0x3
xor_2_8_input = 0x93
xor_2_8_output = 0xa
intermediate_output_2_9_input = 0x5a
intermediate_output_2_9_output = 0x5a

Round_3

intermediate_output_3_0_input = 0x5
intermediate_output_3_0_output = 0x5
xor_3_1_input = 0xb5
xor_3_1_output = 0xe
sbox_3_2_input = 0xe
sbox_3_2_output = 0xc
xor_3_3_input = 0xcc
xor_3_3_output = 0x0
intermediate_output_3_4_input = 0xb0
intermediate_output_3_4_output = 0xb0
rot_3_5_input = 0x5a
rot_3_5_output = 0x4b
xor_3_6_input = 0x5a4b
xor_3_6_output = 0x11
constant_3_7_input = 0b0
constant_3_7_output = 0x4
xor_3_8_input = 0x14
xor_3_8_output = 0x5
intermediate_output_3_9_input = 0x15
intermediate_output_3_9_output = 0x15

Round_4

intermediate_output_4_0_input = 0x1
intermediate_output_4_0_output = 0x1
xor_4_1_input = 0x01
xor_4_1_output = 0x1
sbox_4_2_input = 0x1
sbox_4_2_output = 0x9
xor_4_3_input = 0x9b
xor_4_3_output = 0x2
intermediate_output_4_4_input = 0x02
intermediate_output_4_4_output = 0x02
rot_4_5_input = 0x15
rot_4_5_output = 0xa2
xor_4_6_input = 0x15a2
xor_4_6_output = 0xb7
constant_4_7_input = 0b0
constant_4_7_output = 0x5
xor_4_8_input = 0x75
xor_4_8_output = 0x2
intermediate_output_4_9_input = 0xb2
intermediate_output_4_9_output = 0xb2
cipher_output_4_10_input = 0x20
cipher_output_4_10_output = 0x20
"""
    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    evaluation = hex(toyfeistel.evaluate([0x3F, 0x3E], verbosity=True))
    sys.stdout = old_stdout
    assert evaluation == '0x20'
    assert result.getvalue() == expected_evaluation
