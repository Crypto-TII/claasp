reset()
from claasp.ciphers.toys.toyspn2 import ToySPN2 as ToySPN

block_and_key_bit_size = 32
max_number_of_rounds = 12
cipher = ToySPN(
    block_bit_size=block_and_key_bit_size,
    key_bit_size=block_and_key_bit_size,
    sbox=[12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2],
    number_of_rounds=max_number_of_rounds,
    rotation_layer=1)

from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
fixed_values = []
fixed_values.append(set_fixed_variables('key', 'equal', list(range(block_and_key_bit_size)), integer_to_bit_list(0, block_and_key_bit_size, 'big')))
fixed_values.append(set_fixed_variables('plaintext', 'not_equal', list(range(block_and_key_bit_size)), integer_to_bit_list(0, block_and_key_bit_size, 'big')))

from claasp.cipher_modules.models.sat.sat_models.sat_xor_linear_model import SatXorLinearModel
model = SatXorLinearModel(cipher)

linear_trail = model.find_lowest_weight_xor_linear_trail(fixed_values)
correlation_weight = linear_trail["total_weight"]
# w = -log_2(corr)
# corr = 2^-w
correlation = sqrt(2 ** (-correlation_weight))
bias = correlation / 2
probability = bias + 1/2
probability_weight = -log(probability,2).n()
number_known_plaintext = 1 / (bias ** 2)
print(f'{correlation_weight = }')
print(f'{correlation = }')
print(f'{bias = }')
print(f'{probability = }')
print(f'{log(number_known_plaintext,2).n() = }')
