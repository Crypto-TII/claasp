import sys
from io import StringIO

from claasp.ciphers.toys.toyspn3 import ToySPN3


def test_toyspn3():
    toyspn3 = ToySPN3()
    assert toyspn1.number_of_rounds == 2

    plaintext = 0x3F
    key = 0xFFF
    ciphertext = 0x3F
    assert toyspn3.evaluate([plaintext, key]) == ciphertext

    assert hex(toyspn3.evaluate([plaintext, key])) == '0x3f'
    expected_evaluation = """
Round_0

intermediate_output_0_0_input = 0b111111
intermediate_output_0_0_output = 0b111111
xor_0_1_input = 0xfff
xor_0_1_output = 0b000000
sbox_0_2_input = 0b000
sbox_0_2_output = 0b000
sbox_0_3_input = 0b000
sbox_0_3_output = 0b000
rot_0_4_input = 0b000000
rot_0_4_output = 0b000000
intermediate_output_0_5_input = 0b000000
intermediate_output_0_5_output = 0b000000

Round_1

intermediate_output_1_0_input = 0b111110
intermediate_output_1_0_output = 0b111110
xor_1_1_input = 0x03e
xor_1_1_output = 0b111110
sbox_1_2_input = 0b111
sbox_1_2_output = 0b111
sbox_1_3_input = 0b110
sbox_1_3_output = 0b100
rot_1_4_input = 0b111100
rot_1_4_output = 0b011110
intermediate_output_1_5_input = 0b011110
intermediate_output_1_5_output = 0b011110
cipher_output_1_6_input = 0b011110
cipher_output_1_6_output = 0b011110
"""
    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    evaluation = hex(toyspn3.evaluate([0x3F, 0xFFE], verbosity=True))
    sys.stdout = old_stdout
    assert evaluation == '0x1e'
    assert result.getvalue() == expected_evaluation

    toyspn3 = ToySPN3(block_bit_size=9, number_of_rounds=10)
    assert hex(toyspn3.evaluate([0x1FF, 0x3FFFFFFFFFFFFFFFFFFFFFE])) == '0xfe'

    toyspn3 = ToySPN3(block_bit_size=8,
                      sbox=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0], rotation_layer=-2,
                      number_of_rounds=10)
    assert hex(toyspn3.evaluate([0xFF, 0xFFFFFFFFFFFFFFFFFFFE])) == '0xc3'
