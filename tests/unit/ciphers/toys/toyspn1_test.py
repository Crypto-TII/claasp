import sys
from io import StringIO

from claasp.ciphers.toys.toyspn1 import ToySPN1


def test_toyspn1():
    toyspn1 = ToySPN1()
    assert toyspn1.number_of_rounds == 2

    plaintext = 0x3F
    key = 0x3F
    ciphertext = 0x3F
    assert toyspn1.evaluate([plaintext, key]) == ciphertext

    assert hex(toyspn1.evaluate([plaintext, key])) == '0x3f'
    expected_evaluation = """
Round_0

intermediate_output_0_0_input = 0b111110
intermediate_output_0_0_output = 0b111110
xor_0_1_input = 0xffe
xor_0_1_output = 0b000001
sbox_0_2_input = 0b000
sbox_0_2_output = 0b000
sbox_0_3_input = 0b001
sbox_0_3_output = 0b101
rot_0_4_input = 0b000101
rot_0_4_output = 0b100010
intermediate_output_0_5_input = 0b100010
intermediate_output_0_5_output = 0b100010

Round_1

intermediate_output_1_0_input = 0b111110
intermediate_output_1_0_output = 0b111110
xor_1_1_input = 0x8be
xor_1_1_output = 0b011100
sbox_1_2_input = 0b011
sbox_1_2_output = 0b010
sbox_1_3_input = 0b100
sbox_1_3_output = 0b110
rot_1_4_input = 0b010110
rot_1_4_output = 0b001011
intermediate_output_1_5_input = 0b001011
intermediate_output_1_5_output = 0b001011
cipher_output_1_6_input = 0b001011
cipher_output_1_6_output = 0b001011
"""
    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    evaluation = hex(toyspn1.evaluate([0x3F, 0x3E], verbosity=True))
    sys.stdout = old_stdout
    assert evaluation == '0xb'
    assert result.getvalue() == expected_evaluation

    toyspn1 = ToySPN1(block_bit_size=9, key_bit_size=9, number_of_rounds=10)
    assert hex(toyspn1.evaluate([0x1FF, 0x1FE])) == '0x173'

    toyspn1 = ToySPN1(block_bit_size=8, key_bit_size=8,
                      sbox=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0], rotation_layer=-2,
                      number_of_rounds=10)
    assert hex(toyspn1.evaluate([0xFF, 0xFE])) == '0x6c'
