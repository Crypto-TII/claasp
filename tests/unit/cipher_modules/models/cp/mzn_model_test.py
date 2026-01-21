import pytest

from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
from claasp.cipher_modules.models.cp.mzn_model import MznModel
from claasp.ciphers.block_ciphers.raiden_block_cipher import RaidenBlockCipher
from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_model import MznXorDifferentialModel
from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_model_arx_optimized import (
    MznXorDifferentialModelARXOptimized,
)
from claasp.cipher_modules.models.cp.mzn_models.mzn_cipher_model_arx_optimized import MznCipherModelARXOptimized
from claasp.cipher_modules.models.cp.mzn_models.mzn_deterministic_truncated_xor_differential_model_arx_optimized import (
    MznDeterministicTruncatedXorDifferentialModelARXOptimized,
)
from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_linear_model import MznXorLinearModel
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list, get_bit_bindings
from minizinc import Model, Solver, Instance, Status


def test_solver_names():
    speck = SpeckBlockCipher(number_of_rounds=3)
    mzn = MznModel(speck)
    solver_names = mzn.solver_names()
    assert isinstance(solver_names, list)
    assert len(solver_names) > 0
    # Check that each entry has the required keys
    for solver in solver_names:
        assert 'solver_brand_name' in solver
        assert 'solver_name' in solver
        assert 'keywords' not in solver  # verbose=False by default
    
    # Test verbose mode
    verbose_solver_names = mzn.solver_names(verbose=True)
    assert isinstance(verbose_solver_names, list)
    # External solvers should have keywords when verbose=True
    external_solvers = [s for s in verbose_solver_names if 'keywords' in s]
    assert len(external_solvers) > 0


@pytest.mark.filterwarnings("ignore::DeprecationWarning:")
def test_build_mix_column_truncated_table():
    aes = AESBlockCipher(number_of_rounds=3)
    mzn = MznModel(aes)
    mix_column = aes.component_from(0, 21)
    assert (
        mzn.build_mix_column_truncated_table(mix_column) == "array[0..93, 1..8] of int: "
        "mix_column_truncated_table_mix_column_0_21 = array2d(0..93, 1..8, ["
        "0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,0,0,1,0,1,1,1,1,0,0,1,1,0,1,1,1,0,0,1,1,1,0,1,1,0,0,1,1,1,1,0,"
        "1,0,0,1,1,1,1,1,0,0,0,1,1,1,1,1,1,0,1,0,0,1,1,1,1,0,1,0,1,0,1,1,1,0,1,0,1,1,0,1,1,0,1,0,1,1,1,"
        "0,1,0,1,0,1,1,1,1,0,0,1,0,1,1,1,1,1,0,1,1,0,0,1,1,1,0,1,1,0,1,0,1,1,0,1,1,0,1,1,0,1,0,1,1,0,1,"
        "1,1,0,0,1,1,0,1,1,1,1,0,1,1,1,0,0,1,1,0,1,1,1,0,1,0,1,0,1,1,1,0,1,1,0,0,1,1,1,0,1,1,1,0,1,1,1,"
        "1,0,0,1,0,1,1,1,1,0,1,0,0,1,1,1,1,0,1,1,0,1,1,1,1,1,0,0,0,1,1,1,1,1,0,1,0,1,1,1,1,1,1,0,0,1,1,"
        "1,1,1,1,1,1,0,0,0,1,1,1,1,1,0,0,1,0,1,1,1,1,0,0,1,1,0,1,1,1,0,0,1,1,1,0,1,1,0,0,1,1,1,1,0,1,0,"
        "0,1,1,1,1,1,1,0,1,0,0,1,1,1,1,0,1,0,1,0,1,1,1,0,1,0,1,1,0,1,1,0,1,0,1,1,1,0,1,0,1,0,1,1,1,1,1,"
        "0,1,1,0,0,1,1,1,0,1,1,0,1,0,1,1,0,1,1,0,1,1,0,1,0,1,1,0,1,1,1,1,0,1,1,1,0,0,1,1,0,1,1,1,0,1,0,"
        "1,0,1,1,1,0,1,1,1,0,1,1,1,1,0,0,1,0,1,1,1,1,0,1,1,0,1,1,1,1,1,0,1,0,1,1,1,1,1,1,1,1,0,0,0,1,1,"
        "1,1,1,0,0,1,0,1,1,1,1,0,0,1,1,0,1,1,1,0,0,1,1,1,0,1,1,0,0,1,1,1,1,1,1,0,1,0,0,1,1,1,1,0,1,0,1,"
        "0,1,1,1,0,1,0,1,1,0,1,1,0,1,0,1,1,1,1,1,0,1,1,0,0,1,1,1,0,1,1,0,1,0,1,1,0,1,1,0,1,1,1,1,0,1,1,"
        "1,0,0,1,1,0,1,1,1,0,1,1,1,0,1,1,1,1,0,1,1,0,1,1,1,1,1,1,1,1,0,0,0,1,1,1,1,1,0,0,1,0,1,1,1,1,0,"
        "0,1,1,0,1,1,1,0,0,1,1,1,1,1,1,0,1,0,0,1,1,1,1,0,1,0,1,0,1,1,1,0,1,0,1,1,1,1,1,0,1,1,0,0,1,1,1,"
        "0,1,1,0,1,1,1,1,0,1,1,1,0,1,1,1,0,1,1,1,1,1,1,1,1,0,0,0,1,1,1,1,1,0,0,1,0,1,1,1,1,0,0,1,1,1,1,"
        "1,1,0,1,0,0,1,1,1,1,0,1,0,1,1,1,1,1,0,1,1,0,1,1,1,1,0,1,1,1,1,1,1,1,1,0,0,0,1,1,1,1,1,0,0,1,1,"
        "1,1,1,1,0,1,0,1,1,1,1,1,0,1,1,1,1,1,1,1,1,0,0,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1]);"
    )


def test_find_possible_number_of_active_sboxes():
    midori = MidoriBlockCipher()
    mzn = MznModel(midori)
    model = mzn.find_possible_number_of_active_sboxes(9)
    assert model == {3, 4}


def test_fix_variables_value_constraints():
    raiden = RaidenBlockCipher(number_of_rounds=1)
    mzn = MznXorDifferentialModelARXOptimized(raiden)
    mzn.build_xor_differential_trail_model()
    fixed_variables = [
        {"component_id": "key", "constraint_type": "equal", "bit_positions": [0, 1, 2, 3], "bit_values": [0, 1, 0, 1]}
    ]

    constraint_key_y_0 = "constraint key_y0 = 0;"
    assert mzn.fix_variables_value_constraints_for_ARX(fixed_variables)[0] == constraint_key_y_0

    fixed_variables = [
        {
            "component_id": "plaintext",
            "constraint_type": "sum",
            "bit_positions": [0, 1, 2, 3],
            "operator": ">",
            "value": "0",
        }
    ]

    assert (
        mzn.fix_variables_value_constraints_for_ARX(fixed_variables)[0]
        == "constraint plaintext_y0+plaintext_y1+plaintext_y2+plaintext_y3>0;"
    )

    raiden = RaidenBlockCipher(number_of_rounds=1)
    mzn = MznDeterministicTruncatedXorDifferentialModelARXOptimized(raiden)
    mzn.build_deterministic_truncated_xor_differential_trail_model()

    fixed_variables = [
        {"component_id": "key", "constraint_type": "equal", "bit_positions": [0, 1, 2, 3], "bit_values": [0, 1, 0, 1]}
    ]

    assert mzn.fix_variables_value_constraints_for_ARX(fixed_variables)[0] == constraint_key_y_0

    raiden = RaidenBlockCipher(number_of_rounds=1)
    mzn = MznCipherModelARXOptimized(raiden)
    mzn.build_cipher_model()

    fixed_variables = [
        {"component_id": "key", "constraint_type": "equal", "bit_positions": [0, 1, 2, 3], "bit_values": [0, 1, 0, 1]}
    ]

    assert mzn.fix_variables_value_constraints_for_ARX(fixed_variables)[0] == constraint_key_y_0

    speck = SpeckBlockCipher(number_of_rounds=3)
    mzn = MznXorDifferentialModel(speck)
    fixed_values = [set_fixed_variables('plaintext','equal',range(32),[(speck.get_all_components_ids()[-1],list(range(32)))])]
    trail = mzn.find_one_xor_differential_trail(fixed_values=fixed_values)
    assert trail['components_values']['plaintext']['value'] == trail['components_values'][speck.get_all_components_ids()[-1]]['value']

    mzn.initialise_model()
    fixed_values = [set_fixed_variables('plaintext','not_equal',range(32),[(speck.get_all_components_ids()[-1],list(range(32)))])]
    trail = mzn.find_one_xor_differential_trail(fixed_values=fixed_values)
    assert trail['components_values']['plaintext']['value'] != trail['components_values'][speck.get_all_components_ids()[-1]]['value']

    mzn.initialise_model()
    fixed_values = [set_fixed_variables('plaintext','equal',range(32),[0]*31+[1])]
    fixed_values.append(set_fixed_variables(speck.get_all_components_ids()[-1],'equal',range(32),[0]*31+[1]))
    fixed_values.append(set_fixed_variables('plaintext','not_equal',range(32),[(speck.get_all_components_ids()[-1],list(range(32)))]))
    trail = mzn.find_one_xor_differential_trail(fixed_values=fixed_values)
    assert trail['status'] == 'UNSATISFIABLE'


def test_model_constraints():
    with pytest.raises(Exception):
        speck = SpeckBlockCipher(number_of_rounds=4)
        mzn = MznModel(speck)
        mzn.model_constraints()

def test_build_generic_cp_model_from_dictionary_xor_differential():

    """
    Differential ARX validation for Speck.

    The input and output differences used in the tests are taken from
    Table 4 (Differential Characteristics for Speck32/48/64) of:

    Kai Fu et al., "MILP-Based Automatic Search Algorithms for
    Differential and Linear Trails for Speck", https://eprint.iacr.org/2016/407.pdf
    """
    speck = SpeckBlockCipher(number_of_rounds=3)
    model = MznXorDifferentialModelARXOptimized(speck)
    component_and_model_types = []
    fixed_variables = []

    fixed_variables.append(
        set_fixed_variables(
            component_id="plaintext",
            constraint_type="equal",
            bit_positions=list(range(32)),
            bit_values=integer_to_bit_list(0x02110A04, 32, 'big')
        )
    )

    fixed_variables.append(
        set_fixed_variables(
            component_id="cipher_output_2_12",
            constraint_type="equal",
            bit_positions=list(range(32)),
            bit_values=integer_to_bit_list(0x80008000, 32, 'big')
        )
    )

    for component in speck.get_all_components():
        component_and_model_types.append({
            "component_object": component,
            "model_type": "minizinc_xor_differential_propagation_constraints"
        })
    model.build_generic_cp_model_from_dictionary(component_and_model_types, fixed_variables)

    weight=6
    constraints = model.weight_constraints(weight)
    model._model_constraints.extend(constraints)
    model.init_constraints()
    model._model_constraints.extend(model.objective_generator())
    model._model_constraints.extend(model.weight_constraints())

    result = model.solve_for_ARX(solver_name="cp-sat")

    total_weight = MznXorDifferentialModelARXOptimized._get_total_weight(result)

    trail = model._parse_result(
        result,
        "cp-sat",
        total_weight,
        "xor_differential",
        model._variables_list,
        model.cipher_id,
        model.probability_vars,
    )

    status = trail["status"]

    assert status in {
        "SATISFIABLE",
        "OPTIMAL",
        "OPTIMAL_SOLUTION",
        "ALL_SOLUTIONS",
    }

    assert "total_weight" in trail
    assert float(trail["total_weight"]) == 6

def test_build_generic_cp_model_from_dictionary_xor_linear():
    """
    Linear validation for Speck.

    The linear input/output masks used in the tests are taken from
    Table 6 of:

    Kai Fu et al., "MILP-Based Automatic Search Algorithms for
    Differential and Linear Trails for Speck", https://eprint.iacr.org/2016/407.pdf
    """
    speck = SpeckBlockCipher(
        block_bit_size=32,
        key_bit_size=64,
        number_of_rounds=3)
    model = MznXorLinearModel(speck)
    
    plaintext = set_fixed_variables(
        component_id='plaintext',
        constraint_type='equal',
        bit_positions=range(32),
        bit_values=integer_to_bit_list(0x03805224, 32, 'big')
    )

    output = set_fixed_variables(
        component_id="cipher_output_2_12",
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=integer_to_bit_list(0x40A000C1, 32, 'big')
    )

    model.initialise_model()

    cipher_without_key_schedule = model._cipher.remove_key_schedule()
    model._cipher = cipher_without_key_schedule
    model.bit_bindings, model.bit_bindings_for_intermediate_output = get_bit_bindings(
        model._cipher, lambda record: f"{record[0]}_{record[2]}[{record[1]}]"
    )

    component_and_model_types = []
    for component in model._cipher.get_all_components():
        component_and_model_types.append({
            "component_object": component,
            "model_type": "cp_xor_linear_mask_propagation_constraints"
        })
    model.build_generic_cp_model_from_dictionary(component_and_model_types, [plaintext, output])

    constraints = model.branch_xor_linear_constraints()
    model._model_constraints.extend(constraints)
    weight = 5
    variables, constraints = model.weight_xor_linear_constraints(weight)
    model._variables_list.extend(variables)
    model._model_constraints.extend(constraints)
    variables, constraints = model.input_xor_linear_constraints()
    model._model_prefix.extend(variables)
    model._variables_list.extend(constraints)
    model._model_constraints.extend(model.final_xor_linear_constraints(weight))
    model._model_constraints = model._model_prefix + model._variables_list + model._model_constraints

    result = model.solve(model_type="xor_linear_one_solution", solver_name="cp-sat")
    
    trail = result if isinstance(result, dict) else result.to_dict()

    status = trail["status"]

    assert status in {
        Status.SATISFIED,
        Status.OPTIMAL_SOLUTION,
        Status.ALL_SOLUTIONS,
        "SATISFIABLE",
        "OPTIMAL",
    }

    assert "total_weight" in trail
    assert float(trail["total_weight"]) == 5.0

def test_build_generic_cp_model_with_unknown_component_type():

    cipher = SpeckBlockCipher(number_of_rounds=1)
    model = MznXorDifferentialModel(cipher)

    component = cipher.get_all_components()[0]
    component._type = "UNKNOWN_COMPONENT_TYPE"

    component_and_model_types = [{
        "component_object": component,
        "model_type": "cp_xor_differential_propagation_constraints"
    }]

    model.build_generic_cp_model_from_dictionary(component_and_model_types)

    assert model._model_constraints is not None

def test_get_command_for_solver_process_invalid_solver_name():
    cipher = SpeckBlockCipher(number_of_rounds=1)
    model = MznXorDifferentialModel(cipher)

    error_raised = False

    try:
        model.get_command_for_solver_process(
            model_type="xor_differential_one_solution",
            solver_name="invalid_solver",
            num_of_processors=None,
            timelimit=None
        )
    except NameError:
        error_raised = True

    assert error_raised is True


def test_mzn_model_rejects_invalid_solver_type():
    cipher = SpeckBlockCipher(number_of_rounds=1)

    error_raised = False

    try:
        MznXorDifferentialModel(cipher, sat_or_milp="invalid")
    except TypeError:
        error_raised = True

    assert error_raised is True

