reset()
# from claasp.ciphers.toys.toyspn2 import ToySPN2 as ToySPN
#
# block_and_key_bit_size = 8
# max_number_of_rounds = 2
# cipher = ToySPN(
#     block_bit_size=block_and_key_bit_size,
#     key_bit_size=block_and_key_bit_size,
#     sbox=[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
#     number_of_rounds=max_number_of_rounds,
#     rotation_layer=1)
#
# cipher.neural_network_blackbox_distinguisher_tests(nb_samples=100, hidden_layers=[32, 32, 32], number_of_epochs=1)

from claasp.ciphers.toys.toyspn2 import ToySPN2

# cipher = ToySPN2(block_bit_size=9, key_bit_size=9, number_of_rounds=3)
# BB = cipher.neural_network_blackbox_distinguisher_tests(nb_samples=10, hidden_layers=[32, 32, 32], number_of_epochs=1)

from claasp.ciphers.toys.toyspn2 import ToySPN2
toy = ToySPN2(block_bit_size=48, key_bit_size=48, number_of_rounds = 16)
d, scores, round = toy.find_good_input_difference_for_neural_distinguisher(verbose=True, difference_positions = [True, False], nb_samples=10**3)

from claasp.cipher_modules.neural_network_tests import neural_staged_training
neural_staged_training(toy, [64, 0], round, training_samples=10**6, testing_samples = 10**5, word_size = 24)