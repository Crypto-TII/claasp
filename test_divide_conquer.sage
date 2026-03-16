import sys
import os

sys.path.insert(0, os.getcwd())

import claasp


from claasp.ciphers.permutations.gaston_permutation import GastonPermutation
from claasp.cipher_modules.models.milp.milp_models.Gurobi.monomial_prediction import MilpMonomialPredictionModel




cipher = GastonPermutation(number_of_rounds=3)

print(f"Cipher: {cipher.id}")


# 2. Create Model
milp = MilpMonomialPredictionModel(cipher)


cube = [f"p{i}" for i in range(256,264)]

print(f"\nCube ): {cube}")
print(f"Cube dimension: {len(cube)}")



coeff = milp.find_coefficient_of_cube_by_divide_and_conquer(
    output_bit_index=61,
    middle_round=1,
    cube=cube,
    verbosity=True
)
print(f"D&C coeff: {coeff}")

res1 = milp.find_keycoeff_of_cube_monomial_of_specific_output_bit(61, cube)
print(f"Result 1: {res1}")