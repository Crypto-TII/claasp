# reset()
# from claasp.ciphers.toys.toyspn2 import ToySPN2 as ToySPN
#
# block_and_key_bit_size = 8
# max_number_of_rounds = 30
# cipher = ToySPN(
#     block_bit_size=block_and_key_bit_size,
#     key_bit_size=block_and_key_bit_size,
#     sbox=[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
#     number_of_rounds=max_number_of_rounds,
#     rotation_layer=1)
#
# cipher.neural_network_blackbox_distinguisher_tests(nb_samples=10000, hidden_layers=[32, 32, 32], number_of_epochs=10)


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

from claasp.ciphers.toys.toyspn2 import ToySPN2 as ToySPN

block_and_key_bit_size = 32
max_number_of_rounds = 20
cipher = ToySPN(
    block_bit_size=block_and_key_bit_size,
    key_bit_size=block_and_key_bit_size,
    sbox=[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
    number_of_rounds=max_number_of_rounds,
    rotation_layer=1)

BB = cipher.neural_network_blackbox_distinguisher_tests(nb_samples=10000, hidden_layers=[32, 32, 32], number_of_epochs=10)

accuracies = BB["neural_network_blackbox_distinguisher_tests"]["test_results"]["plaintext"]["round_output"]["accuracies"]
for i in range(len(accuracies)):
    print(f'Round {i} - Accuracy: {accuracies[i]["value_accuracy"]}')