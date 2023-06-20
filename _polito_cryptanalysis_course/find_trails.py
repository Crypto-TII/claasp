
from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
from claasp.cipher_modules.models.utils import set_fixed_variables
from claasp.ciphers.toys.toyspn2 import ToySPN2

cipher = ToySPN2(number_of_rounds=2)
sat = SatXorDifferentialModel(cipher)
plaintext = set_fixed_variables(component_id = 'plaintext',
                                constraint_type = 'not_equal',
                                bit_positions = range(6),
                                bit_values=(0,) * 6)
key = set_fixed_variables(component_id = 'key',
                          constraint_type = 'equal',
                          bit_positions = range(6),
                          bit_values = (0,) * 6)
trail = sat.find_lowest_weight_xor_differential_trail(fixed_values=[plaintext, key])
trail['total_weight']