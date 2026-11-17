from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.cipher_modules.models.utils import set_fixed_variables
from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_model import (
    MznXorDifferentialModel, and_xor_differential_probability_ddt)

speck = SimonBlockCipher(number_of_rounds=2)
mzn = MznXorDifferentialModel(speck)
trails = mzn.find_all_xor_differential_trails_with_fixed_weight(1, solver_name='Chuffed', solve_external=True)

assert len(trails) == 6

trails = mzn.find_all_xor_differential_trails_with_fixed_weight(1, solver_name='chuffed', solve_external=False)

assert len(trails) == 6