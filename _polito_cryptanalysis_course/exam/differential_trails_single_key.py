reset()
from claasp.ciphers.toys.toyspn2 import ToySPN2 as ToySPN

block_and_key_bit_size = 32
max_number_of_rounds = 15
cipher = ToySPN(
    block_bit_size=block_and_key_bit_size,
    key_bit_size=block_and_key_bit_size,
    # sbox=[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
    sbox=[12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2],
    number_of_rounds=max_number_of_rounds,
    rotation_layer=1)

from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
fixed_values = []
fixed_values.append(set_fixed_variables('key', 'equal', list(range(block_and_key_bit_size)), integer_to_bit_list(0, block_and_key_bit_size, 'big')))
fixed_values.append(set_fixed_variables('plaintext', 'not_equal', list(range(block_and_key_bit_size)), integer_to_bit_list(0, block_and_key_bit_size, 'big')))

# from claasp.cipher_modules.models.cp.cp_models.cp_xor_differential_trail_search_model import CpXorDifferentialTrailSearchModel
# model = CpXorDifferentialTrailSearchModel(cipher)

# from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
# model = MilpXorDifferentialModel(cipher)

from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
model = SatXorDifferentialModel(cipher)

# differential_trail = model.find_one_xor_differential_trail_with_fixed_weight(30, fixed_values)
differential_trail = model.find_lowest_weight_xor_differential_trail(fixed_values)
