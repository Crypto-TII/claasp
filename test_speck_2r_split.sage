import sys
import os

# Priority 1: Current Directory (where we are running the script)
sys.path.insert(0, os.getcwd())

from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.milp.milp_models.Gurobi.monomial_prediction import MilpMonomialPredictionModel

# 1. Initialize Speck Block Cipher
# 32-bit block (2 output words of 16 bits), 64-bit key, 2 rounds
# 6 rounds for the user test
cipher = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=6)

# Use independent keys (remove key schedule constraints)
print("Removing key schedule to simulate independent round keys...")
cipher = cipher.remove_key_schedule()

print(f"Cipher: {cipher.id}")
print(f"State size: {cipher.output_bit_size} bits")
print(f"Inputs: {cipher.inputs}")
print(f"Number of rounds: {cipher.number_of_rounds}")

# 2. Create Model
milp = MilpMonomialPredictionModel(cipher)

# 32-bit state: [Left Word (16 bits) | Right Word (16 bits)]
# Bits 25, 26 are bits 9 and 10 of the Right Word.
inactive_bits = [25, 26]
cube = [f"p{i}" for i in range(32) if i not in inactive_bits]
print(f"Cube dimension: {len(cube)}")
print(f"\nCube: {cube}")

# Target output bit 15
output_bit = 15

# Solve using divide and conquer split at round 2
# res = BooleanPolynomial
res = milp.find_coefficient_of_cube_by_divide_and_conquer(
    output_bit_index=output_bit,
    middle_round=2,
    cube=cube,
    verbosity=True
)

print(f"\nSuperpoly: {res}")

print("Test completed.")
"""

from claasp.ciphers.stream_ciphers.trivium_stream_cipher import TriviumStreamCipher
cipher = TriviumStreamCipher(keystream_bit_len=1, number_of_initialization_clocks=199)

milp = MilpMonomialPredictionModel(cipher) 
cube = ["i53"]
#cube = ['i9', 'i19', 'i29', 'i39', 'i49', 'i59', 'i69', 'i79']
coeff =  milp.find_coefficient_of_cube_by_divide_and_conquer(
    output_bit_index=0,
    middle_round=1,
    cube=cube,
    verbosity=True)
print(coeff)
res1 = milp.find_keycoeff_of_cube_monomial_of_specific_output_bit(0, cube)
print(f"Result 1: {res1}")
"""