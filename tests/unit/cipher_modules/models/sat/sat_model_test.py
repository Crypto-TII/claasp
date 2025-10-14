import pytest

from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
from claasp.cipher_modules.models.sat.sat_model import SatModel
from claasp.cipher_modules.models.sat.sat_models.sat_cipher_model import SatCipherModel
from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel
from claasp.cipher_modules.models.sat.solvers import CRYPTOMINISAT, CRYPTOMINISAT_EXT, KISSAT_EXT, PARKISSAT_EXT


def test_solve():
    # testing with system solver
    tea = TeaBlockCipher(number_of_rounds=32)
    sat = SatCipherModel(tea)
    sat.build_cipher_model()
    solution = sat.solve("cipher", solver_name=CRYPTOMINISAT_EXT)
    assert str(solution["cipher"]) == "tea_p64_k128_o64_r32"
    assert eval(solution["components_values"]["modadd_0_3"]["value"]) >= 0
    assert eval(solution["components_values"]["cipher_output_31_16"]["value"]) >= 0
    # testing with sage solver
    simon = SimonBlockCipher(number_of_rounds=32)
    sat = SatCipherModel(simon)
    sat.build_cipher_model()
    solution = sat.solve("cipher", solver_name=CRYPTOMINISAT)
    assert str(solution["cipher"]) == "simon_p32_k64_o32_r32"
    assert eval(solution["components_values"]["rot_0_3"]["value"]) >= 0
    assert eval(solution["components_values"]["cipher_output_31_13"]["value"]) >= 0


def test_fix_variables_value_constraints():
    fixed_variables = [
        {
            "component_id": "plaintext",
            "constraint_type": "equal",
            "bit_positions": [0, 1, 2, 3],
            "bit_values": [1, 0, 1, 1],
        },
        {
            "component_id": "ciphertext",
            "constraint_type": "not_equal",
            "bit_positions": [0, 1, 2, 3],
            "bit_values": [1, 1, 1, 0],
        },
    ]
    assert SatModel.fix_variables_value_constraints(fixed_variables) == [
        "plaintext_0",
        "-plaintext_1",
        "plaintext_2",
        "plaintext_3",
        "-ciphertext_0 -ciphertext_1 -ciphertext_2 ciphertext_3",
    ]

    speck = SpeckBlockCipher(number_of_rounds=3)
    sat = SatXorDifferentialModel(speck)
    fixed_values = [set_fixed_variables('plaintext', 'equal', range(32), [(speck.get_all_components_ids()[-1], list(range(32)))])]
    trail = sat.find_one_xor_differential_trail(fixed_values=fixed_values)
    assert trail['components_values']['plaintext']['value'] == trail['components_values'][speck.get_all_components_ids()[-1]]['value']

    fixed_values = [set_fixed_variables('plaintext', 'not_equal', range(32), [(speck.get_all_components_ids()[-1], list(range(32)))])]
    trail = sat.find_one_xor_differential_trail(fixed_values=fixed_values)
    assert trail['components_values']['plaintext']['value'] != trail['components_values'][speck.get_all_components_ids()[-1]]['value']

    fixed_values = [set_fixed_variables('plaintext', 'equal', range(32), [0]*31+[1])]
    fixed_values.append(set_fixed_variables(speck.get_all_components_ids()[-1], 'equal', range(32), [0]*31+[1]))
    fixed_values.append(set_fixed_variables('plaintext', 'not_equal', range(32), [(speck.get_all_components_ids()[-1], list(range(32)))]))
    trail = sat.find_one_xor_differential_trail(fixed_values=fixed_values)
    assert trail['status'] == 'UNSATISFIABLE'


def test_build_xor_differential_sat_model_from_dictionary():
    component_model_types = []
    speck = SpeckBlockCipher(number_of_rounds=3)

    plaintext = set_fixed_variables(
        component_id="plaintext",
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=integer_to_bit_list(0x00400000, 32, "big"),
    )

    cipher_output = set_fixed_variables(
        component_id="cipher_output_2_12",
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=integer_to_bit_list(0x8000840A, 32, "big"),
    )

    key = set_fixed_variables(
        component_id="key", constraint_type="equal", bit_positions=range(64), bit_values=(0,) * 64
    )

    for component in speck.get_all_components():
        print(component.id)
        component_model_type = {
            "component_id": component.id,
            "component_object": component,
            "model_type": "sat_xor_differential_propagation_constraints",
        }
        component_model_types.append(component_model_type)
    sat_model = SatCipherModel(speck)
    sat_model.build_generic_sat_model_from_dictionary([plaintext, key, cipher_output], component_model_types)
    variables, constraints = sat_model.weight_constraints(3)
    sat_model._variables_list.extend(variables)
    sat_model._model_constraints.extend(constraints)
    result = sat_model._solve_with_external_sat_solver("xor_differential", PARKISSAT_EXT, ["-c=6"])
    assert result["status"] == "SATISFIABLE"


def test_build_generic_sat_model_from_dictionary():
    component_model_types = []
    speck = SpeckBlockCipher(number_of_rounds=3)

    plaintext = set_fixed_variables(
        component_id="plaintext",
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=integer_to_bit_list(0x00400000, 32, "big"),
    )

    key = set_fixed_variables(
        component_id="key", constraint_type="equal", bit_positions=range(64), bit_values=(0,) * 64
    )

    for component in speck.get_all_components():
        component_model_type = {
            "component_id": component.id,
            "component_object": component,
            "model_type": "sat_xor_differential_propagation_constraints",
        }
        component_model_types.append(component_model_type)

    for component_model_type in component_model_types:
        if component_model_type["component_id"] in [
            "xor_2_10",
            "rot_2_9",
            "xor_2_8",
            "modadd_2_7",
            "rot_2_6",
            "xor_2_5",
            "rot_2_4",
            "xor_2_3",
            "modadd_2_2",
            "rot_2_1",
            "constant_2_0",
            "cipher_output_2_12",
            "intermediate_output_2_11",
        ]:
            component_model_type["model_type"] = "sat_bitwise_deterministic_truncated_xor_differential_constraints"

    sat_model = SatCipherModel(speck)
    sat_model.build_generic_sat_model_from_dictionary([plaintext, key], component_model_types)
    result = sat_model._solve_with_external_sat_solver("xor_differential", KISSAT_EXT, [])
    assert result["status"] == "SATISFIABLE"


def test_model_constraints():
    with pytest.raises(Exception):
        speck = SpeckBlockCipher(number_of_rounds=4)
        sat = SatModel(speck)
        sat.model_constraints()


def test_weight_constraints():
    speck = SpeckBlockCipher(number_of_rounds=3)
    sat = SatXorDifferentialModel(speck)
    sat.build_xor_differential_trail_model()
    assert len(sat.weight_constraints(7)) == 2
