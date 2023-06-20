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
datasets = dg.generate_avalanche_dataset(input_index=0, number_of_samples=16*100)

def hammingWeight(n):
  """
  :type n: int
  :rtype: int
  """
  one_count = 0
  for i in n:
     if i == "1":
        one_count+=1
  return one_count

round = 0
for dataset in datasets:
    dataset_ascii = ""
    for d in dataset: # bytes read from dataset
        dataset_ascii = dataset_ascii + f'{d:08b}'
        # print(f'{d:08b}', end='')
        # f.write(f'{d:08b}')
    # print()
    number_of_ones = hammingWeight(dataset_ascii)
    number_of_zeros = len(dataset_ascii) - number_of_ones
    ratio = number_of_ones / len(dataset_ascii)
    # print(f'{number_of_ones = }')
    # print(f'{number_of_zeros = }')
    print(f'{round = } - {ratio = }')
    round = round + 1