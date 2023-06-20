reset()
from claasp.cipher_modules.statistical_tests.nist_statistical_tests import StatisticalTests
from claasp.ciphers.toys.toyspn2 import ToySPN2 as ToySPN

block_and_key_bit_size = 32
max_number_of_rounds = 30
cipher = ToySPN(
    block_bit_size=block_and_key_bit_size,
    key_bit_size=block_and_key_bit_size,
    sbox=[12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2],
    number_of_rounds=max_number_of_rounds,
    rotation_layer=1)

sequence_bit_size = 8192 # 8 * (32^2)
unit_bit_size = block_and_key_bit_size ** 2
number_of_units_per_sequence = int(sequence_bit_size/unit_bit_size)
number_of_sequences = 100
#
sts = StatisticalTests(cipher)
sts.run_avalanche_nist_statistics_test(input_index=0,
    number_of_samples_in_one_line=number_of_units_per_sequence, number_of_lines=number_of_sequences,
    flag_chart=True)