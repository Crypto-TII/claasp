from sage.crypto.sbox import SBox
from claasp.ciphers.toys.toyspn1 import ToySPN1
from claasp.utils.utils import pprint_dictionary
toyspn1 = ToySPN1(number_of_rounds=2)

# pprint_dictionary(toyspn1.as_python_dictionary())
sbox_component = toyspn1.component_from(0, 2)
sbox_toyspn1 = SBox(sbox_component.description)
print(f'{sbox_toyspn1 = }:')
print('DDT:')
print(f'{sbox_toyspn1.difference_distribution_table()}')
