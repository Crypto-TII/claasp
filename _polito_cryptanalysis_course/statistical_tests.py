from claasp.cipher_modules.statistical_tests.dataset_generator import DatasetGenerator
from claasp.cipher_modules.statistical_tests.nist_statistical_tests import StatisticalTests
from claasp.ciphers.toys.toyspn3 import ToySPN3 as ToySPN
block_and_key_bit_size = 24
max_number_of_rounds = 30
cipher = ToySPN(
    block_bit_size=block_and_key_bit_size,
    key_bit_size=block_and_key_bit_size,
    sbox=[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
    number_of_rounds=max_number_of_rounds,
    rotation_layer=1)
dg = DatasetGenerator(cipher)
sequence_bit_size = 4608 # 8 * (24^2)
unit_bit_size = block_and_key_bit_size ** 2
number_of_units_per_sequence = int(sequence_bit_size/unit_bit_size)
number_of_sequences = 100
# number of samples is actually the number of units in the full dataset
datasets = dg.generate_avalanche_dataset(
    input_index=0,
    number_of_samples=number_of_units_per_sequence * number_of_sequences)

print(f'{number_of_units_per_sequence * number_of_sequences * block_and_key_bit_size**2 = }')
f = open("test_overlapping_ascii.bin","wb")
# for dataset_r in datasets: # dataset corresponding to each round
#     for d in dataset_r: # bytes read from dataset
#         # print(f'{d:08b}', end='')
#         f.write(f'{d:08b}')
#     print()

print(f'{len(datasets[20])*8 = }')
for d in datasets[20]: # bytes read from dataset
    # print(f'{d:08b}', end='')
    f.write(int(d).to_bytes(1, "big"))
f.close()


sts = StatisticalTests(cipher)
# number_of_samples_in_one_line is the number of units in a bit sequence (bitstream)
# number_of_lines is the number of bit sequences (bitstreams)
sts.run_avalanche_nist_statistics_test(input_index=0,
    number_of_samples_in_one_line=number_of_units_per_sequence,
    number_of_lines=number_of_sequences,
    flag_chart=True)
