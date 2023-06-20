from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
from claasp.ciphers.toys.toyspn1 import ToySPN1
toyspn1 =ToySPN1()
algebraic=AlgebraicModel(toyspn1)
polynomial_system = algebraic.polynomial_system()
print((f'{polynomial_system.nvariables() = }'))
print((f'{polynomial_system.maximal_degree() = }'))
print((f'number of equations = {len(polynomial_system)}'))