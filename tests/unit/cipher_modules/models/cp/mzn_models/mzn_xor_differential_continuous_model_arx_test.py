from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.cp.mzn_model import MznModel
from minizinc import Model, Solver, Instance

def test_cp_modadd_test_vectors():
    cipher = SpeckBlockCipher(number_of_rounds=1)
    model = MznModel(cipher)

    modadd_component = cipher.get_component_from_id("modadd_0_1")
    declarations, constraints = modadd_component.cp_continuous_differential_propagation_constraints(model)

    mzn_model = Model()
    mzn_model.add_file("/home/sage/tii-claasp/continuous_operations.mzn")

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

    xor_component = cipher.get_component_from_id("xor_0_4")
    declarations, constraints = xor_component.cp_continuous_differential_propagation_constraints(model)

    mzn_model = Model()
    mzn_model.add_file("/home/sage/tii-claasp/continuous_operations.mzn")
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
        rot_component = cipher.get_component_from_id(case["component_id"])

        declarations, constraints = (
            rot_component.cp_continuous_differential_propagation_constraints(model)
        )

        mzn_model = Model()
        mzn_model.add_file("/home/sage/tii-claasp/continuous_operations.mzn")
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

    modadd_component = cipher.get_component_from_id("modadd_0_1")

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
    mzn_model.add_file("/home/sage/tii-claasp/continuous_operations.mzn")
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

    rot_left = cipher.get_component_from_id("rot_0_0")      
    modadd = cipher.get_component_from_id("modadd_0_1")     
    rot_right = cipher.get_component_from_id("rot_0_3")    
    xor = cipher.get_component_from_id("xor_0_4")         

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
    mzn_model.add_file("/home/sage/tii-claasp/continuous_operations.mzn")

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
