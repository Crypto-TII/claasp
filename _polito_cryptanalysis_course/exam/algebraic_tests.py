reset()
from claasp.ciphers.toys.toyspn2 import ToySPN2 as ToySPN

block_and_key_bit_size = 32
max_number_of_rounds = 1
cipher = ToySPN(
    block_bit_size=block_and_key_bit_size,
    key_bit_size=block_and_key_bit_size,
    sbox=[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
    number_of_rounds=max_number_of_rounds,
    rotation_layer=1)

from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
algebraic=AlgebraicModel(cipher)
s = algebraic.polynomial_system()
print(f'{s.nvariables() = }')
print(f'{s.maximal_degree() = }')
print(f'number of polynomials = {len(s)}')
