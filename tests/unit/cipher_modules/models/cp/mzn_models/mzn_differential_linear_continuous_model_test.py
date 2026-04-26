from claasp.cipher_modules.models.cp.mzn_models.mzn_differential_linear_continuous_model import MznDifferentialLinearContinuousModel
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.cp.mzn_model import MznModel
from claasp.cipher_modules.models.cp.minizinc_utils.mzn_continuous_predicates import get_continuous_operations
from minizinc import Model, Solver, Instance
import re

def test_cp_modadd_test_vectors():
    cipher = SpeckBlockCipher(number_of_rounds=1)
    model = MznModel(cipher)

    modadd_component = cipher.component_from_id("modadd_0_1")
    declarations, constraints = modadd_component.cp_continuous_differential_propagation_constraints(model)

    mzn_model = Model()
    mzn_model.add_string(get_continuous_operations())

    mzn_model.add_string("\n".join(declarations) + "\n" + "\n".join(constraints))

    solver = Solver.lookup("scip")

    instance = Instance(solver, mzn_model)

    instance["n"] = 16

    instance["x1_modadd_0_1"] = [
        -1.0, -1.0, -1.0, -1.0,
        -1.0, -1.0, -1.0, -1.0,
        -1.0, -1.0,  1.0, -1.0,
        -1.0, -1.0, -1.0, -1.0
    ]

    instance["x2_modadd_0_1"] = [
        -1.0,  1.0, -1.0,  1.0,
        -1.0, -1.0, -1.0, -1.0,
        -1.0, -1.0, -1.0, -1.0,
        -1.0, -1.0, -1.0, -1.0
    ]

    result = instance.solve()
    out = result["modadd_0_1"]

    print("\n=========== RESULTADO continuous_modadd ===============")
    for i, v in enumerate(out):
        print(f"output_diff[{i}] = {v:.6f}")
    print("======================================================\n")

    expected = [-0.0, 0.5, -0.0, 0.9843749998357616, -0.9687499996715224, -0.9375000001123921, -0.8750000002247842, -0.7500000001623421, -0.5000000000000004, -0.0, 1.0, -1.0, -1.0, -1.0, -1.0, -1.0]

    for i in range(16):
        assert abs(out[i] - expected[i]) < 1e-4

def test_cp_xor_test_vectors():
    cipher = SpeckBlockCipher(number_of_rounds=1)
    model = MznModel(cipher)

    for c in cipher.get_all_components():
        print(c.id, c.description)

    xor_component = cipher.component_from_id("xor_0_4")
    declarations, constraints = xor_component.cp_continuous_differential_propagation_constraints(model)

    mzn_model = Model()
    mzn_model.add_string(get_continuous_operations())
    mzn_model.add_string("\n".join(declarations) + "\n" + "\n".join(constraints))

    solver = Solver.lookup("scip")
    instance = Instance(solver, mzn_model)

    instance["n"] = 16

    # x1_xor_0_1
    instance["x1_xor_0_4"] = [
        -0.0, 0.5, -0.0, 0.984375,
        -0.96875, -0.9375, -0.875, -0.75,
        -0.5, -0.0, 1.0, -1.0,
        -1.0, -1.0, -1.0, -1.0
    ]

    # x2_xor_0_1
    instance["x2_xor_0_4"] = [
        -1.0, 1.0, -1.0, -1.0,
        -1.0, -1.0, -1.0, -1.0,
        -1.0, -1.0, -1.0, -1.0,
        -1.0, -1.0, -1.0, 1.0
    ]

    result = instance.solve()
    out = result["xor_0_4"]

    print("\n=========== RESULTADO continuous_xor ===============")
    for i, v in enumerate(out):
        print(f"output_diff[{i}] = {v:.6f}")
    print("===================================================\n")

    expected = [
         0.0, -0.5,  0.0,  0.984375,
        -0.96875, -0.9375, -0.875, -0.75,
        -0.5,  0.0,  1.0, -1.0,
        -1.0, -1.0, -1.0,  1.0
    ]

    for i in range(16):
        assert abs(out[i] - expected[i]) < 1e-4

def test_cp_rotate_test_vectors():
    cipher = SpeckBlockCipher(number_of_rounds=1)
    model = MznModel(cipher)

    test_cases = [
        {
            "component_id": "rot_0_0",   
            "input": [
                -1.0, -1.0, -1.0,  1.0,
                -1.0, -1.0, -1.0, -1.0,
                -1.0, -1.0, -1.0, -1.0,
                -1.0, -1.0, -1.0, -1.0
            ],
            "expected": [
                -1.0, -1.0, -1.0, -1.0,
                -1.0, -1.0, -1.0, -1.0,
                -1.0, -1.0,  1.0, -1.0,
                -1.0, -1.0, -1.0, -1.0
            ]
        },
        {
            "component_id": "rot_0_3",  
            "input": [
                -1.0,  1.0, -1.0,  1.0,
                -1.0, -1.0, -1.0, -1.0,
                -1.0, -1.0, -1.0, -1.0,
                -1.0, -1.0, -1.0, -1.0
            ],
            "expected": [
                -1.0,  1.0, -1.0, -1.0,
                -1.0, -1.0, -1.0, -1.0,
                -1.0, -1.0, -1.0, -1.0,
                -1.0, -1.0, -1.0,  1.0
            ]
        }
    ]

    for case in test_cases:
        rot_component = cipher.component_from_id(case["component_id"])

        declarations, constraints = (
            rot_component.cp_continuous_differential_propagation_constraints(model)
        )

        mzn_model = Model()
        mzn_model.add_string(get_continuous_operations())
        mzn_model.add_string("\n".join(declarations) + "\n" + "\n".join(constraints))

        solver = Solver.lookup("scip")
        instance = Instance(solver, mzn_model)

        instance["n"] = 16
        instance[f"x1_{case['component_id']}"] = case["input"]

        result = instance.solve()
        out = result[case["component_id"]]

        print(f"\n=== RESULTADO {case['component_id']} ===")
        for i, v in enumerate(out):
            print(f"output[{i}] = {v}")
        print("=====================================\n")

        for i in range(16):
            assert abs(out[i] - case["expected"][i]) < 1e-6

def test_generic_cp_modadd_test_vectors():
    cipher = SpeckBlockCipher(number_of_rounds=1)
    model = MznModel(cipher)

    modadd_component = cipher.component_from_id("modadd_0_1")

    component_and_model_types = [
        {
            "component_object": modadd_component,
            "model_type": "cp_continuous_differential_propagation_constraints"
        }
    ]

    model.build_generic_cp_model_from_dictionary(
        component_and_model_types=component_and_model_types
    )

    mzn_model = Model()
    mzn_model.add_string(get_continuous_operations())
    mzn_model.add_string(
        "\n".join(model._variables_list)
        + "\n"
        + "\n".join(model._model_constraints)
    )

    solver = Solver.lookup("scip")
    instance = Instance(solver, mzn_model)

    instance["n"] = 16

    instance["x1_modadd_0_1"] = [
        -1.0, -1.0, -1.0, -1.0,
        -1.0, -1.0, -1.0, -1.0,
        -1.0, -1.0,  1.0, -1.0,
        -1.0, -1.0, -1.0, -1.0
    ]

    instance["x2_modadd_0_1"] = [
        -1.0,  1.0, -1.0,  1.0,
        -1.0, -1.0, -1.0, -1.0,
        -1.0, -1.0, -1.0, -1.0,
        -1.0, -1.0, -1.0, -1.0
    ]

    result = instance.solve()
    out = result["modadd_0_1"]

    expected = [
        -0.0, 0.5, -0.0, 0.9843749998,
        -0.9687499997, -0.9375000001,
        -0.8750000002, -0.7500000001,
        -0.5000000000, -0.0, 1.0,
        -1.0, -1.0, -1.0, -1.0, -1.0
    ]

    for i in range(16):
        assert abs(out[i] - expected[i]) < 1e-4

def test_generic_cp_full_round_pipeline():
    cipher = SpeckBlockCipher(number_of_rounds=1)
    model = MznModel(cipher)

    rot_left = cipher.component_from_id("rot_0_0")      
    modadd = cipher.component_from_id("modadd_0_1")     
    rot_right = cipher.component_from_id("rot_0_3")    
    xor = cipher.component_from_id("xor_0_4")         

    component_and_model_types = [
        {"component_object": rot_left,  "model_type": "cp_continuous_differential_propagation_constraints"},
        {"component_object": modadd,    "model_type": "cp_continuous_differential_propagation_constraints"},
        {"component_object": rot_right, "model_type": "cp_continuous_differential_propagation_constraints"},
        {"component_object": xor,       "model_type": "cp_continuous_differential_propagation_constraints"},
    ]

    model.build_generic_cp_model_from_dictionary(
        component_and_model_types=component_and_model_types,
    )

    mzn_model = Model()
    mzn_model.add_string(get_continuous_operations())

    mzn_model.add_string(
        "\n".join(model._variables_list)
        + "\n"
        + "\n".join(model._model_constraints)
    )

    mzn_model.add_string("""
        constraint x1_modadd_0_1 = rot_0_0;
        constraint x1_xor_0_4    = modadd_0_1;
        constraint x2_xor_0_4    = rot_0_3;
    """)

    solver = Solver.lookup("scip")
    instance = Instance(solver, mzn_model)

    instance["n"] = 16

    instance["x1_rot_0_0"] = [
        -1.0, -1.0, -1.0,  1.0,
        -1.0, -1.0, -1.0, -1.0,
        -1.0, -1.0, -1.0, -1.0,
        -1.0, -1.0, -1.0, -1.0
    ]

    instance["x1_rot_0_3"] = [
        -1.0,  1.0, -1.0,  1.0,
        -1.0, -1.0, -1.0, -1.0,
        -1.0, -1.0, -1.0, -1.0,
        -1.0, -1.0, -1.0, -1.0
    ]

    instance["x2_modadd_0_1"] = instance["x1_rot_0_3"]
    result = instance.solve()
    assert result is not None

    expected_left = [
        -0.0,  0.5, -0.0,  0.9843749998357616,
        -0.9687499996715224, -0.9375000001123921,
        -0.8750000002247842, -0.7500000001623421,
        -0.5000000000000004, -0.0, 1.0, -1.0,
        -1.0, -1.0, -1.0, -1.0
    ]

    expected_right = [
         0.0, -0.5,  0.0,  0.984375,
        -0.96875, -0.9375, -0.875, -0.75,
        -0.5,  0.0,  1.0, -1.0,
        -1.0, -1.0, -1.0,  1.0
    ]

    out_left = result["modadd_0_1"]
    out_right = result["xor_0_4"]

    for i in range(16):
        assert abs(out_left[i] - expected_left[i]) < 1e-4
        assert abs(out_right[i] - expected_right[i]) < 1e-4

def test_full_search_continuous_propagation_only():
    """
    The expected values correspond to the continuous correlations of the
    differential-linear part reported in Table 4 from [BGGMP2023]_.
    """
    cipher = SpeckBlockCipher(
        block_bit_size=32,
        key_bit_size=64,
        number_of_rounds=1)
    
    plaintext_size = cipher.inputs_bit_size[0] 
    key_size = cipher.inputs_bit_size[1]

    model = MznDifferentialLinearContinuousModel(cipher)
    
    input_left = [-1.0, -1.0, -1.0,  1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0]
    input_right = [-1.0,  1.0, -1.0,  1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0]

    key = [-1.0] * key_size
    fixed_inputs = [
        {
            "component_id": "plaintext",
            "bit_positions": list(range(0, plaintext_size//2)),
            "bit_values": input_left
        },
        {
            "component_id": "plaintext",
            "bit_positions": list(range(plaintext_size//2, plaintext_size)),
            "bit_values": input_right
        },
        {
            "component_id": "key",
            "bit_positions": list(range(key_size)),
            "bit_values": key
        }
    ]   
    
    
    result = model.find_one_continuous_correlations(
        fixed_values=fixed_inputs,
        solver_name="scip"
    )

    assert result["status"] == "SATISFIED"
    values = result["components_values"] 
    cipher_out = values["cipher_output_0_6"]["value"]

    expected_cipher = [
        0.0, 0.5, 0.0, 0.984375, -0.96875, -0.9375, -0.875, -0.75,
        -0.5, -0.0, 1.0, -1.0, -1.0, -1.0, -1.0, -1.0,
        0.0, -0.5, 0.0, 0.984375, -0.96875, -0.9375, -0.875, -0.75,
        -0.5, -0.0, 1.0, -1.0, -1.0, -1.0, -1.0, 1.0
    ]

    tol_error = 1e-4

    for i in range(plaintext_size):
        assert abs(cipher_out[i] - expected_cipher[i]) < tol_error


def test_full_search_continuous_propagation_two_rounds():
    """
    The expected values correspond to the continuous correlations of the
    differential-linear part reported in Table 4 from [BGGMP2023]_.
    """
    cipher = SpeckBlockCipher(
        block_bit_size=32,
        key_bit_size=64,
        number_of_rounds=2
    )

    plaintext_size = cipher.inputs_bit_size[0] 
    key_size = cipher.inputs_bit_size[1]

    model = MznDifferentialLinearContinuousModel(cipher)

    input_left = [
        -1.0, -1.0, -1.0,  1.0,
        -1.0, -1.0, -1.0, -1.0,
        -1.0, -1.0, -1.0, -1.0,
        -1.0, -1.0, -1.0, -1.0
    ]

    input_right = [
        -1.0,  1.0, -1.0,  1.0,
        -1.0, -1.0, -1.0, -1.0,
        -1.0, -1.0, -1.0, -1.0,
        -1.0, -1.0, -1.0, -1.0
    ]

    key = [-1.0] * key_size

    fixed_inputs = [
        {
            "component_id": "plaintext",
            "bit_positions": list(range(0, plaintext_size//2)),
            "bit_values": input_left
        },
        {
            "component_id": "plaintext",
            "bit_positions": list(range(plaintext_size//2, plaintext_size)),
            "bit_values": input_right
        },
        {
            "component_id": "key",
            "bit_positions": list(range(key_size)),
            "bit_values": key
        }
    ] 

    result = model.find_one_continuous_correlations(
        fixed_values=fixed_inputs,
        solver_name="scip"
    )

    assert result["status"] == "SATISFIED"
    values = result["components_values"]
    cipher_out = values["cipher_output_1_12"]["value"]
    cipher_intermediate_out = values["intermediate_output_0_6"]["value"]


    expected_intermediate_cipher = [
        0.0, 0.5, 0.0, 0.984375, -0.96875, -0.9375, -0.875, -0.75,
        -0.5, -0.0, 1.0, -1.0, -1.0, -1.0, -1.0, -1.0,
        0.0, -0.5, 0.0, 0.984375, -0.96875, -0.9375, -0.875, -0.75,
        -0.5, -0.0, 1.0, -1.0, -1.0, -1.0, -1.0, 1.0
    ]

    expected_output_cipher = [
        0.0, 0.125904, 0.0, 0.849684, -0.730319, -0.521594, -0.163504, 0.0,
        -0.00340, -0.0, -0.877274, -0.785400, -0.631694, -0.382812, 0.0, 0.5,
        0.0, -0.123896, 0.0, 0.796585, -0.639005, -0.391206, -0.081797, 0.0, 0.003400,
        0.0, -0.877274, -0.785400, -0.631695, 0.382810, 0.0, 0.25
    ]

    tol_error = 1e-4

    for i in range(plaintext_size):
        assert abs(cipher_out[i] - expected_output_cipher[i]) < tol_error
        assert abs(cipher_intermediate_out[i] - expected_intermediate_cipher[i]) < tol_error

def test_find_lowest_continuous_propagation():
    cipher = SpeckBlockCipher(
        block_bit_size=32,
        key_bit_size=64,
        number_of_rounds=2)
    
    plaintext_size = cipher.inputs_bit_size[0] 
    key_size = cipher.inputs_bit_size[1]

    model = MznDifferentialLinearContinuousModel(cipher)
    
    input_left = [-1.0, -1.0, -1.0,  -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0]
    input_right = [-1.0,  -1.0, -1.0,  1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0]

    key = [-1.0] * key_size

    fixed_inputs = [
        {
            "component_id": "plaintext",
            "bit_positions": list(range(0, plaintext_size//2)),
            "bit_values": input_left
        },
        {
            "component_id": "plaintext",
            "bit_positions": list(range(plaintext_size//2, plaintext_size)),
            "bit_values": input_right
        },
        {
            "component_id": "key",
            "bit_positions": list(range(key_size)),
            "bit_values": key
        }
    ]   
    
    
    result = model.find_lowest_continuous_correlation(
        fixed_values=fixed_inputs,
        solver_name="scip"
    )
    assert abs(result["differential_linear_correlation"]) > 0.0
    assert -1.0 <= result["differential_linear_correlation"] <= 1.0

    print(result["differential_linear_correlation"])
    print(result["output_mask"])
    print(result["correlation_log2_approximation"])


def test_find_lowest_continuous_propagation_with_fixed_masks():
    """
    The correlation values correspond to the continuous differential-linear
    correlations reported in Table 4 of [BGGMP2023]_.

    Only the total correlation of the continuous part is verified here.

    This method replicates the behavior of the find_lowest_continuous_correlation method, but using fixed output masks instead of searching over them.
    """
    cipher = SpeckBlockCipher(
        block_bit_size=32,
        key_bit_size=64,
        number_of_rounds=2)
    
    plaintext_size = cipher.inputs_bit_size[0] 
    key_size = cipher.inputs_bit_size[1]

    model = MznDifferentialLinearContinuousModel(cipher)
    
    input_left = [-1.0, -1.0, -1.0,  1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0]
    input_right = [-1.0,  1.0, -1.0,  1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0]

    key = [-1.0] * key_size

    fixed_inputs = [
        {
            "component_id": "plaintext",
            "bit_positions": list(range(0, plaintext_size//2)),
            "bit_values": input_left
        },
        {
            "component_id": "plaintext",
            "bit_positions": list(range(plaintext_size//2, plaintext_size)),
            "bit_values": input_right
        },
        {
            "component_id": "key",
            "bit_positions": list(range(key_size)),
            "bit_values": key
        }
    ]   
    
    mask_bits = [0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,  
                 0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0]  

    model.build_differential_linear_continuous_trail_model(
        fixed_values=fixed_inputs
    )

    model._build_linear_mask_correlation_constraints()
    model._build_difflin_corr_constraints()

    for bit_idx, bit_val in enumerate(mask_bits):
        model._model_constraints.append(
            f"constraint output_mask[{bit_idx}] = {bit_val};"
        )

    cipher_output_id = model._get_cipher_output_id()

    model._model_constraints.append(
        f"solve :: float_search({cipher_output_id}, 1e-12, smallest, indomain_min, complete) "
        "minimize correlation_log2_approximation;"
    )

    result = model.solve_for_ARX("scip")
    result = model._parse_result(result, "scip")

    correlation = result["differential_linear_correlation"]
    log2_absolute_value = result["correlation_log2_absolute_value"]

    tol_err_correlation_expected = 1e-6
    tol_exponent_expected = 0.1

    expected_differential_linear_correlation = 0.7454814092873888
    expected_correlation_log2_approximation = 0.42   

    assert abs(correlation - expected_differential_linear_correlation) < tol_err_correlation_expected
    assert abs(log2_absolute_value - expected_correlation_log2_approximation) < tol_exponent_expected




