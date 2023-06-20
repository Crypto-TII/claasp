reset()
from claasp.ciphers.toys.toyspn2 import ToySPN2 as ToySPN

block_and_key_bit_size = 32
max_number_of_rounds = 30
cipher = ToySPN(
    block_bit_size=block_and_key_bit_size,
    key_bit_size=block_and_key_bit_size,
    sbox=[12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2],
    number_of_rounds=max_number_of_rounds,
    rotation_layer=1)

d = cipher.diffusion_tests(number_of_samples=1000000)
apvs =  d["test_results"]["plaintext"]["round_output"]["avalanche_weight_vectors"]["differences"][0]["output_vectors"]
for i in range(len(apvs)):
    print(f'Round {i}: criterion satisfied? {apvs[i]["criterion_satisfied"]} - total avalanche weight = {apvs[i]["total"]}')

apvs =  d["test_results"]["plaintext"]["round_output"]["avalanche_entropy_vectors"]["differences"][0]["output_vectors"]
for i in range(len(apvs)):
    print(f'Round {i}: criterion satisfied? {apvs[i]["criterion_satisfied"]} - total avalanche entropy = {apvs[i]["total"]}')


