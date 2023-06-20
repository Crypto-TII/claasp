# from util import *
# from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
# import numpy as np


# def load_toy_spn(plain_size, key_size, number_of_rounds):
#     from claasp.ciphers.toys.toyspn2 import ToySPN2
#     return ToySPN2(block_bit_size=plain_size, key_bit_size=key_size, number_of_rounds = number_of_rounds)

# def black_box_neural_network_test(cipher):
#     test_result = cipher.neural_network_blackbox_distinguisher_tests()
#     print(f'The test was run with the following parameters..\n{test_result["neural_network_blackbox_distinguisher_tests"]}')
#     print(test_result['neural_network_blackbox_distinguisher_tests']['test_results'])
#     return test_result

def find_good_input_difference_for_neural_distinguisher(cipher, scenario = 'single-key'):
    cipher_inputs = cipher.inputs
    if scenario == 'single-key' :
        positions = [x == 'plaintext' for x in cipher_inputs]
    elif scenario == 'related-key':
        positions = [True for x in cipher_inputs]
    differences, scores, highest_round = cipher.find_good_input_difference_for_neural_distinguisher(difference_positions = positions, verbose=True, nb_samples=10**3)
    print("The highest reached round for which a significant bias score was found was", highest_round)
    print("The best differences found by the optimizer are...")
    for i in range(1, 11):
        print(hex(differences[-i]), ", with score", scores[-i])
    return differences[-1], highest_round




from claasp.ciphers.toys.toyspn2 import ToySPN2 as ToySPN

block_and_key_bit_size = 32
max_number_of_rounds = 30
cipher = ToySPN(
    block_bit_size=block_and_key_bit_size,
    key_bit_size=block_and_key_bit_size,
    sbox=[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
    number_of_rounds=max_number_of_rounds,
    rotation_layer=1)

print("="*10,  "Finding good input differences for neural cryptanalysis of TOYSPN2... ", "="*10)
# Runs our algorithm; returns a list of input differences and their respective scores (sorted),
# as well as the maximum number of rounds that was reached.
best_difference, highest_round = find_good_input_difference_for_neural_distinguisher(cipher)

print("="*10,  "Training a neural distinguisher for TOYSPN2... ", "="*10)
from claasp.cipher_modules.neural_network_tests import neural_staged_training

if cipher.inputs[0]=='key':
    inputs = [0, best_difference]
else:
    inputs = [best_difference, 0]

# Word_size is input_bit_size//2 instead of input_bit_size, this will be changed later but that is the way it is for now.
neural_staged_training(cipher, inputs, starting_round = highest_round, word_size=32, training_samples=10**6, testing_samples=10**5)