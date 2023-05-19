from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.sat.sat_models.sat_cipher_model import SatCipherModel
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
from claasp.name_mappings import CIPHER


def test_satisfiable_compounded_xor_differential_creator_tests():
    intermediate_output_0_5_pair1_pair2_values = [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    intermediate_output_0_5_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_0_5_pair1_pair2",
                                                              constraint_type="equal", bit_positions=list(range(16)),
                                                              bit_values=intermediate_output_0_5_pair1_pair2_values)
    intermediate_output_1_11_pair1_pair2_values = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    intermediate_output_1_11_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_1_11_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(16)),
                                                               bit_values=intermediate_output_1_11_pair1_pair2_values)
    intermediate_output_2_11_pair1_pair2_values = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1]
    intermediate_output_2_11_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_2_11_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(16)),
                                                               bit_values=intermediate_output_2_11_pair1_pair2_values)
    intermediate_output_3_11_pair1_pair2_values = [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]
    intermediate_output_3_11_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_3_11_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(16)),
                                                               bit_values=intermediate_output_3_11_pair1_pair2_values)
    intermediate_output_4_11_pair1_pair2_values = [0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    intermediate_output_4_11_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_4_11_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(16)),
                                                               bit_values=intermediate_output_4_11_pair1_pair2_values)
    intermediate_output_5_11_pair1_pair2_values = [0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    intermediate_output_5_11_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_5_11_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(16)),
                                                               bit_values=intermediate_output_5_11_pair1_pair2_values)
    intermediate_output_6_11_pair1_pair2_values = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    intermediate_output_6_11_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_6_11_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(16)),
                                                               bit_values=intermediate_output_6_11_pair1_pair2_values)
    intermediate_output_7_11_pair1_pair2_values = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    intermediate_output_7_11_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_7_11_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(16)),
                                                               bit_values=intermediate_output_7_11_pair1_pair2_values)
    intermediate_output_8_11_pair1_pair2_values = [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]
    intermediate_output_8_11_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_8_11_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(16)),
                                                               bit_values=intermediate_output_8_11_pair1_pair2_values)
    intermediate_output_9_11_pair1_pair2_values = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    intermediate_output_9_11_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_9_11_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(16)),
                                                               bit_values=intermediate_output_9_11_pair1_pair2_values)
    intermediate_output_10_11_pair1_pair2_values = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    intermediate_output_10_11_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_10_11_pair1_pair2",
                                                                constraint_type="equal", bit_positions=list(range(16)),
                                                                bit_values=intermediate_output_10_11_pair1_pair2_values)
    intermediate_output_11_11_pair1_pair2_values = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    intermediate_output_11_11_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_11_11_pair1_pair2",
                                                                constraint_type="equal", bit_positions=list(range(16)),
                                                                bit_values=intermediate_output_11_11_pair1_pair2_values)
    intermediate_output_12_11_pair1_pair2_values = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    intermediate_output_12_11_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_12_11_pair1_pair2",
                                                                constraint_type="equal", bit_positions=list(range(16)),
                                                                bit_values=intermediate_output_12_11_pair1_pair2_values)
    intermediate_output_13_11_pair1_pair2_values = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]
    intermediate_output_13_11_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_13_11_pair1_pair2",
                                                                constraint_type="equal", bit_positions=list(range(16)),
                                                                bit_values=intermediate_output_13_11_pair1_pair2_values)
    input_difference_xor_0_20_values = [0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 1, 0, 0, 0]
    input_difference_xor_0_20 = set_fixed_variables(component_id="input_difference_xor_0_20", constraint_type="equal",
                                                    bit_positions=list(range(32)),
                                                    bit_values=input_difference_xor_0_20_values)
    intermediate_output_0_6_pair1_pair2_values = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                  0, 0, 0, 0, 0, 0, 0, 0, 0]
    intermediate_output_0_6_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_0_6_pair1_pair2",
                                                              constraint_type="equal", bit_positions=list(range(32)),
                                                              bit_values=intermediate_output_0_6_pair1_pair2_values)
    intermediate_output_1_12_pair1_pair2_values = [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
                                                   0, 0, 0, 0, 0, 0, 0, 0, 0]
    intermediate_output_1_12_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_1_12_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(32)),
                                                               bit_values=intermediate_output_1_12_pair1_pair2_values)
    intermediate_output_2_12_pair1_pair2_values = [1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0,
                                                   0, 1, 0, 1, 1, 0, 0, 0, 0]
    intermediate_output_2_12_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_2_12_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(32)),
                                                               bit_values=intermediate_output_2_12_pair1_pair2_values)
    intermediate_output_3_12_pair1_pair2_values = [0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0,
                                                   0, 1, 0, 1, 1, 0, 1, 0, 0]
    intermediate_output_3_12_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_3_12_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(32)),
                                                               bit_values=intermediate_output_3_12_pair1_pair2_values)
    intermediate_output_4_12_pair1_pair2_values = [1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                                                   0, 1, 0, 1, 0, 0, 0, 0, 1]
    intermediate_output_4_12_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_4_12_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(32)),
                                                               bit_values=intermediate_output_4_12_pair1_pair2_values)
    intermediate_output_5_12_pair1_pair2_values = [0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1,
                                                   0, 0, 0, 0, 0, 0, 1, 0, 1]
    intermediate_output_5_12_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_5_12_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(32)),
                                                               bit_values=intermediate_output_5_12_pair1_pair2_values)
    intermediate_output_6_12_pair1_pair2_values = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0,
                                                   0, 0, 0, 0, 0, 0, 0, 0, 0]
    intermediate_output_6_12_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_6_12_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(32)),
                                                               bit_values=intermediate_output_6_12_pair1_pair2_values)
    intermediate_output_7_12_pair1_pair2_values = [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                   0, 0, 0, 0, 0, 0, 0, 0, 0]
    intermediate_output_7_12_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_7_12_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(32)),
                                                               bit_values=intermediate_output_7_12_pair1_pair2_values)
    intermediate_output_8_12_pair1_pair2_values = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                   0, 0, 0, 0, 0, 0, 0, 0, 0]
    intermediate_output_8_12_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_8_12_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(32)),
                                                               bit_values=intermediate_output_8_12_pair1_pair2_values)
    intermediate_output_9_12_pair1_pair2_values = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                   0, 0, 0, 0, 0, 0, 0, 0, 0]
    intermediate_output_9_12_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_9_12_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(32)),
                                                               bit_values=intermediate_output_9_12_pair1_pair2_values)
    intermediate_output_10_12_pair1_pair2_values = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                    0, 0, 0, 0, 0, 0, 0, 0, 0]
    intermediate_output_10_12_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_10_12_pair1_pair2",
                                                                constraint_type="equal", bit_positions=list(range(32)),
                                                                bit_values=intermediate_output_10_12_pair1_pair2_values)
    intermediate_output_11_12_pair1_pair2_values = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
                                                    0, 0, 0, 0, 0, 0, 0, 0, 0]
    intermediate_output_11_12_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_11_12_pair1_pair2",
                                                                constraint_type="equal", bit_positions=list(range(32)),
                                                                bit_values=intermediate_output_11_12_pair1_pair2_values)
    intermediate_output_12_12_pair1_pair2_values = [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                    1, 0, 0, 0, 0, 0, 0, 1, 0]
    intermediate_output_12_12_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_12_12_pair1_pair2",
                                                                constraint_type="equal", bit_positions=list(range(32)),
                                                                bit_values=intermediate_output_12_12_pair1_pair2_values)
    cipher_output_13_12_pair1_pair2_values = [1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0,
                                              0, 0, 0, 1, 0, 1, 0]
    cipher_output_13_12_pair1_pair2 = set_fixed_variables(component_id="cipher_output_13_12_pair1_pair2",
                                                          constraint_type="equal", bit_positions=list(range(32)),
                                                          bit_values=cipher_output_13_12_pair1_pair2_values)

    speck = SpeckBlockCipher(number_of_rounds=14)
    speck.create_compounded_cipher()
    sat = SatCipherModel(speck)
    key_pair1_pair2 = set_fixed_variables(
        component_id='input_difference_xor_0_21',
        constraint_type='equal',
        bit_positions=list(range(64)),
        bit_values=integer_to_bit_list(0x0a80088000681000, 64, 'big'))
    fixed_variables = [intermediate_output_0_5_pair1_pair2, intermediate_output_1_11_pair1_pair2,
                       intermediate_output_2_11_pair1_pair2, intermediate_output_3_11_pair1_pair2,
                       intermediate_output_4_11_pair1_pair2, intermediate_output_5_11_pair1_pair2,
                       intermediate_output_6_11_pair1_pair2, intermediate_output_7_11_pair1_pair2,
                       intermediate_output_8_11_pair1_pair2, intermediate_output_9_11_pair1_pair2,
                       intermediate_output_10_11_pair1_pair2, intermediate_output_11_11_pair1_pair2,
                       intermediate_output_12_11_pair1_pair2, intermediate_output_13_11_pair1_pair2,
                       input_difference_xor_0_20, intermediate_output_0_6_pair1_pair2,
                       intermediate_output_1_12_pair1_pair2, intermediate_output_2_12_pair1_pair2,
                       intermediate_output_3_12_pair1_pair2, intermediate_output_4_12_pair1_pair2,
                       intermediate_output_5_12_pair1_pair2, intermediate_output_6_12_pair1_pair2,
                       intermediate_output_7_12_pair1_pair2, intermediate_output_8_12_pair1_pair2,
                       intermediate_output_9_12_pair1_pair2, intermediate_output_10_12_pair1_pair2,
                       intermediate_output_11_12_pair1_pair2, intermediate_output_12_12_pair1_pair2,
                       cipher_output_13_12_pair1_pair2, key_pair1_pair2]
    sat.build_cipher_model(fixed_variables=fixed_variables)
    assert sat.solve(CIPHER, solver_name="cryptominisat")["status"] == "SATISFIABLE"


def test_unsatisfiable_compounded_xor_differential_creator_tests():
    """ The following is an incompatible trail presented in Table 28 of [Sad2020]_."""
    intermediate_output_0_5_pair1_pair2_values = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1]
    intermediate_output_0_5_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_0_5_pair1_pair2",
                                                              constraint_type="equal", bit_positions=list(range(16)),
                                                              bit_values=intermediate_output_0_5_pair1_pair2_values)
    intermediate_output_1_11_pair1_pair2_values = [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]
    intermediate_output_1_11_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_1_11_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(16)),
                                                               bit_values=intermediate_output_1_11_pair1_pair2_values)
    intermediate_output_2_11_pair1_pair2_values = [0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    intermediate_output_2_11_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_2_11_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(16)),
                                                               bit_values=intermediate_output_2_11_pair1_pair2_values)
    intermediate_output_3_11_pair1_pair2_values = [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    intermediate_output_3_11_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_3_11_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(16)),
                                                               bit_values=intermediate_output_3_11_pair1_pair2_values)
    intermediate_output_4_11_pair1_pair2_values = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    intermediate_output_4_11_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_4_11_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(16)),
                                                               bit_values=intermediate_output_4_11_pair1_pair2_values)
    intermediate_output_5_11_pair1_pair2_values = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    intermediate_output_5_11_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_5_11_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(16)),
                                                               bit_values=intermediate_output_5_11_pair1_pair2_values)
    intermediate_output_6_11_pair1_pair2_values = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    intermediate_output_6_11_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_6_11_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(16)),
                                                               bit_values=intermediate_output_6_11_pair1_pair2_values)
    intermediate_output_7_11_pair1_pair2_values = [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]
    intermediate_output_7_11_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_7_11_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(16)),
                                                               bit_values=intermediate_output_7_11_pair1_pair2_values)
    intermediate_output_8_11_pair1_pair2_values = [0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0]
    intermediate_output_8_11_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_8_11_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(16)),
                                                               bit_values=intermediate_output_8_11_pair1_pair2_values)
    intermediate_output_9_11_pair1_pair2_values = [0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]
    intermediate_output_9_11_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_9_11_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(16)),
                                                               bit_values=intermediate_output_9_11_pair1_pair2_values)
    intermediate_output_10_11_pair1_pair2_values = [1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0]
    intermediate_output_10_11_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_10_11_pair1_pair2",
                                                                constraint_type="equal", bit_positions=list(range(16)),
                                                                bit_values=intermediate_output_10_11_pair1_pair2_values)
    intermediate_output_11_11_pair1_pair2_values = [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0]
    intermediate_output_11_11_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_11_11_pair1_pair2",
                                                                constraint_type="equal", bit_positions=list(range(16)),
                                                                bit_values=intermediate_output_11_11_pair1_pair2_values)
    intermediate_output_12_11_pair1_pair2_values = [1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0]
    intermediate_output_12_11_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_12_11_pair1_pair2",
                                                                constraint_type="equal", bit_positions=list(range(16)),
                                                                bit_values=intermediate_output_12_11_pair1_pair2_values)
    intermediate_output_13_11_pair1_pair2_values = [0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1]
    intermediate_output_13_11_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_13_11_pair1_pair2",
                                                                constraint_type="equal", bit_positions=list(range(16)),
                                                                bit_values=intermediate_output_13_11_pair1_pair2_values)
    input_difference_xor_0_20_values = [0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1,
                                        0, 0, 0, 0, 1]
    input_difference_xor_0_20 = set_fixed_variables(component_id="input_difference_xor_0_20", constraint_type="equal",
                                                    bit_positions=list(range(32)),
                                                    bit_values=input_difference_xor_0_20_values)
    intermediate_output_0_6_pair1_pair2_values = [0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
                                                  0, 1, 0, 1, 0, 0, 0, 0, 0]
    intermediate_output_0_6_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_0_6_pair1_pair2",
                                                              constraint_type="equal", bit_positions=list(range(32)),
                                                              bit_values=intermediate_output_0_6_pair1_pair2_values)
    intermediate_output_1_12_pair1_pair2_values = [0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
                                                   0, 0, 0, 0, 0, 0, 0, 0, 1]
    intermediate_output_1_12_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_1_12_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(32)),
                                                               bit_values=intermediate_output_1_12_pair1_pair2_values)
    intermediate_output_2_12_pair1_pair2_values = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                   0, 0, 0, 0, 0, 0, 0, 0, 0]
    intermediate_output_2_12_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_2_12_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(32)),
                                                               bit_values=intermediate_output_2_12_pair1_pair2_values)
    intermediate_output_3_12_pair1_pair2_values = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                   0, 0, 0, 0, 0, 0, 0, 0, 0]
    intermediate_output_3_12_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_3_12_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(32)),
                                                               bit_values=intermediate_output_3_12_pair1_pair2_values)
    intermediate_output_4_12_pair1_pair2_values = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                   0, 0, 0, 0, 0, 0, 0, 0, 0]
    intermediate_output_4_12_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_4_12_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(32)),
                                                               bit_values=intermediate_output_4_12_pair1_pair2_values)
    intermediate_output_5_12_pair1_pair2_values = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                   0, 0, 0, 0, 0, 0, 0, 0, 0]
    intermediate_output_5_12_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_5_12_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(32)),
                                                               bit_values=intermediate_output_5_12_pair1_pair2_values)
    intermediate_output_6_12_pair1_pair2_values = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                   0, 0, 0, 0, 0, 0, 0, 0, 0]
    intermediate_output_6_12_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_6_12_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(32)),
                                                               bit_values=intermediate_output_6_12_pair1_pair2_values)
    intermediate_output_7_12_pair1_pair2_values = [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                   0, 0, 1, 0, 0, 0, 0, 0, 0]
    intermediate_output_7_12_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_7_12_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(32)),
                                                               bit_values=intermediate_output_7_12_pair1_pair2_values)
    intermediate_output_8_12_pair1_pair2_values = [1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
                                                   0, 0, 0, 0, 0, 0, 0, 0, 0]
    intermediate_output_8_12_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_8_12_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(32)),
                                                               bit_values=intermediate_output_8_12_pair1_pair2_values)
    intermediate_output_9_12_pair1_pair2_values = [1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0,
                                                   1, 0, 1, 0, 0, 0, 0, 0, 0]
    intermediate_output_9_12_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_9_12_pair1_pair2",
                                                               constraint_type="equal", bit_positions=list(range(32)),
                                                               bit_values=intermediate_output_9_12_pair1_pair2_values)
    intermediate_output_10_12_pair1_pair2_values = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0,
                                                    1, 0, 0, 0, 0, 0, 0, 0, 0]
    intermediate_output_10_12_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_10_12_pair1_pair2",
                                                                constraint_type="equal", bit_positions=list(range(32)),
                                                                bit_values=intermediate_output_10_12_pair1_pair2_values)
    intermediate_output_11_12_pair1_pair2_values = [1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0,
                                                    0, 0, 1, 0, 0, 0, 0, 0, 0]
    intermediate_output_11_12_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_11_12_pair1_pair2",
                                                                constraint_type="equal", bit_positions=list(range(32)),
                                                                bit_values=intermediate_output_11_12_pair1_pair2_values)
    intermediate_output_12_12_pair1_pair2_values = [1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0,
                                                    1, 0, 0, 0, 0, 0, 0, 1, 0]
    intermediate_output_12_12_pair1_pair2 = set_fixed_variables(component_id="intermediate_output_12_12_pair1_pair2",
                                                                constraint_type="equal", bit_positions=list(range(32)),
                                                                bit_values=intermediate_output_12_12_pair1_pair2_values)
    cipher_output_13_12_pair1_pair2_values = [1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0,
                                              1, 1, 1, 1, 1, 1, 0]
    cipher_output_13_12_pair1_pair2 = set_fixed_variables(component_id="cipher_output_13_12_pair1_pair2",
                                                          constraint_type="equal", bit_positions=list(range(32)),
                                                          bit_values=cipher_output_13_12_pair1_pair2_values)

    speck = SpeckBlockCipher(number_of_rounds=14)
    speck.create_compounded_cipher()
    sat = SatCipherModel(speck)
    key_pair1_pair2 = set_fixed_variables(
        component_id='input_difference_xor_0_21',
        constraint_type='equal',
        bit_positions=list(range(64)),
        bit_values=integer_to_bit_list(0x0001400008800025, 64, 'big'))
    fixed_variables = [intermediate_output_0_5_pair1_pair2, intermediate_output_1_11_pair1_pair2,
                       intermediate_output_2_11_pair1_pair2, intermediate_output_3_11_pair1_pair2,
                       intermediate_output_4_11_pair1_pair2, intermediate_output_5_11_pair1_pair2,
                       intermediate_output_6_11_pair1_pair2, intermediate_output_7_11_pair1_pair2,
                       intermediate_output_8_11_pair1_pair2, intermediate_output_9_11_pair1_pair2,
                       intermediate_output_10_11_pair1_pair2, intermediate_output_11_11_pair1_pair2,
                       intermediate_output_12_11_pair1_pair2, intermediate_output_13_11_pair1_pair2,
                       input_difference_xor_0_20, intermediate_output_0_6_pair1_pair2,
                       intermediate_output_1_12_pair1_pair2, intermediate_output_2_12_pair1_pair2,
                       intermediate_output_3_12_pair1_pair2, intermediate_output_4_12_pair1_pair2,
                       intermediate_output_5_12_pair1_pair2, intermediate_output_6_12_pair1_pair2,
                       intermediate_output_7_12_pair1_pair2, intermediate_output_8_12_pair1_pair2,
                       intermediate_output_9_12_pair1_pair2, intermediate_output_10_12_pair1_pair2,
                       intermediate_output_11_12_pair1_pair2, intermediate_output_12_12_pair1_pair2,
                       cipher_output_13_12_pair1_pair2, key_pair1_pair2]

    sat.build_cipher_model(fixed_variables=fixed_variables)
    assert sat.solve(CIPHER, solver_name="cryptominisat")["status"] == "UNSATISFIABLE"