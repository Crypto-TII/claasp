import pytest

from claasp.components.permutation_component import Permutation
from claasp.cipher_modules.models.milp.milp_model import MilpModel
from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import (
    MilpBitwiseDeterministicTruncatedXorDifferentialModel,
)
from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import (
    MilpWordwiseDeterministicTruncatedXorDifferentialModel,
)
from claasp.ciphers.single_component_ciphers.permutation_cipher import PermutationCipher
from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel


PERMUTATION = [1, 3, 2, 0]


def make_permutation_component():
    return Permutation(0, 0, ["input"], [[0, 1, 2, 3]], 4, PERMUTATION)


def test_constructor_builds_permutation_component():
    permutation_component = make_permutation_component()

    assert permutation_component.id == "permutation_0_0"
    assert permutation_component.type == "permutation"
    assert permutation_component.description == [[1, 3, 2, 0], 1]


def test_cp_constraints():
    permutation_component = make_permutation_component()
    declarations, constraints = permutation_component.cp_constraints()

    assert declarations == []
    assert constraints == [
        "constraint permutation_0_0[0] = input[3];",
        "constraint permutation_0_0[1] = input[0];",
        "constraint permutation_0_0[2] = input[2];",
        "constraint permutation_0_0[3] = input[1];",
    ]


def test_cp_xor_linear_mask_propagation_constraints():
    permutation_component = make_permutation_component()
    declarations, constraints = permutation_component.cp_xor_linear_mask_propagation_constraints()

    assert declarations == [
        "array[0..3] of var 0..1:permutation_0_0_i;",
        "array[0..3] of var 0..1:permutation_0_0_o;",
    ]
    assert constraints == [
        "constraint permutation_0_0_o[0]=permutation_0_0_i[3];",
        "constraint permutation_0_0_o[1]=permutation_0_0_i[0];",
        "constraint permutation_0_0_o[2]=permutation_0_0_i[2];",
        "constraint permutation_0_0_o[3]=permutation_0_0_i[1];",
    ]


def test_sat_constraints():
    permutation_component = make_permutation_component()
    output_bit_ids, constraints = permutation_component.sat_constraints()

    assert output_bit_ids == [
        "permutation_0_0_0",
        "permutation_0_0_1",
        "permutation_0_0_2",
        "permutation_0_0_3",
    ]
    assert constraints == [
        "permutation_0_0_0 -input_3",
        "input_3 -permutation_0_0_0",
        "permutation_0_0_1 -input_0",
        "input_0 -permutation_0_0_1",
        "permutation_0_0_2 -input_2",
        "input_2 -permutation_0_0_2",
        "permutation_0_0_3 -input_1",
        "input_1 -permutation_0_0_3",
    ]


def test_cms_constraints_match_sat_constraints():
    permutation_component = make_permutation_component()

    sat_variables, sat_constraints = permutation_component.sat_constraints()
    cms_variables, cms_constraints = permutation_component.cms_constraints()

    assert cms_variables == sat_variables
    assert cms_constraints == sat_constraints


def test_cms_xor_wrappers_match_cms_constraints():
    permutation_component = make_permutation_component()

    cms_variables, cms_constraints = permutation_component.cms_constraints()
    cms_diff_variables, cms_diff_constraints = permutation_component.cms_xor_differential_propagation_constraints()
    cms_lin_variables, cms_lin_constraints = permutation_component.cms_xor_linear_mask_propagation_constraints()

    assert cms_diff_variables == cms_variables
    assert cms_diff_constraints == cms_constraints
    assert cms_lin_variables == cms_variables
    assert cms_lin_constraints == cms_constraints


def test_smt_constraints():
    permutation_component = make_permutation_component()
    output_bit_ids, constraints = permutation_component.smt_constraints()

    assert output_bit_ids == [
        "permutation_0_0_0",
        "permutation_0_0_1",
        "permutation_0_0_2",
        "permutation_0_0_3",
    ]
    assert constraints == [
        "(assert (= permutation_0_0_0 input_3))",
        "(assert (= permutation_0_0_1 input_0))",
        "(assert (= permutation_0_0_2 input_2))",
        "(assert (= permutation_0_0_3 input_1))",
    ]


def test_sat_semi_deterministic_wrapper_matches_bitwise():
    permutation_component = make_permutation_component()

    bitwise_variables, bitwise_constraints = (
        permutation_component.sat_bitwise_deterministic_truncated_xor_differential_constraints()
    )
    semi_variables, semi_constraints = permutation_component.sat_semi_deterministic_truncated_xor_differential_constraints()

    assert semi_variables == bitwise_variables
    assert semi_constraints == bitwise_constraints


def test_cp_deterministic_wrapper_matches_trail():
    permutation_component = make_permutation_component()

    trail_declarations, trail_constraints = permutation_component.cp_deterministic_truncated_xor_differential_trail_constraints()
    det_declarations, det_constraints = permutation_component.cp_deterministic_truncated_xor_differential_constraints()

    assert det_declarations == trail_declarations
    assert det_constraints == trail_constraints


def test_cp_semi_deterministic_wrapper_matches_trail():
    permutation_component = make_permutation_component()

    trail_declarations, trail_constraints = permutation_component.cp_deterministic_truncated_xor_differential_trail_constraints()
    semi_declarations, semi_constraints = permutation_component.cp_semi_deterministic_truncated_xor_differential_constraints()

    assert semi_declarations == trail_declarations
    assert semi_constraints == trail_constraints


def test_smt_xor_differential_wrapper_matches_smt_constraints():
    permutation_component = make_permutation_component()

    smt_variables, smt_constraints = permutation_component.smt_constraints()
    diff_variables, diff_constraints = permutation_component.smt_xor_differential_propagation_constraints(None)

    assert diff_variables == smt_variables
    assert diff_constraints == smt_constraints


def test_smt_xor_linear_mask_propagation_constraints():
    permutation_component = make_permutation_component()
    variables, constraints = permutation_component.smt_xor_linear_mask_propagation_constraints()

    assert variables == [
        "permutation_0_0_0_i",
        "permutation_0_0_1_i",
        "permutation_0_0_2_i",
        "permutation_0_0_3_i",
        "permutation_0_0_0_o",
        "permutation_0_0_1_o",
        "permutation_0_0_2_o",
        "permutation_0_0_3_o",
    ]
    assert constraints == [
        "(assert (= permutation_0_0_0_o permutation_0_0_3_i))",
        "(assert (= permutation_0_0_1_o permutation_0_0_0_i))",
        "(assert (= permutation_0_0_2_o permutation_0_0_2_i))",
        "(assert (= permutation_0_0_3_o permutation_0_0_1_i))",
    ]


def test_cp_wordwise_deterministic_truncated_constraints():
    DummyModel = type("DummyModel", (), {"word_size": 4})
    component = Permutation(0, 0, ["input"], [[0, 1, 2, 3, 4, 5, 6, 7]], 8, [1, 0], word_size=4)

    declarations, constraints = component.cp_wordwise_deterministic_truncated_xor_differential_constraints(DummyModel())

    assert declarations == []
    assert constraints == [
        "constraint if ((input_active[1] == 0)) then permutation_0_0_active[0] = 0 /\\ permutation_0_0_value[0] = 0 elsepermutation_0_0_active[0] = 3 /\\ permutation_0_0_value[0] = -2 endif;",
        "constraint if ((input_active[0] == 0)) then permutation_0_0_active[1] = 0 /\\ permutation_0_0_value[1] = 0 elsepermutation_0_0_active[1] = 3 /\\ permutation_0_0_value[1] = -2 endif;",
    ]


def test_cp_wordwise_deterministic_truncated_constraints_raises_on_cross_word_mix():
    DummyModel = type("DummyModel", (), {"word_size": 4})
    component = Permutation(0, 0, ["input"], [[0, 1, 2, 3, 4, 5, 6, 7]], 8, [0, 1, 2, 4, 3, 5, 6, 7])

    with pytest.raises(ValueError, match="unsupported in wordwise model"):
        component.cp_wordwise_deterministic_truncated_xor_differential_constraints(DummyModel())


def test_cp_xor_differential_wrapper_matches_cp_constraints():
    permutation_component = make_permutation_component()

    cp_declarations, cp_constraints = permutation_component.cp_constraints()
    wrapper_declarations, wrapper_constraints = permutation_component.cp_xor_differential_propagation_constraints(None)

    assert wrapper_declarations == cp_declarations
    assert wrapper_constraints == cp_constraints


def test_algebraic_polynomials():
    cipher = PermutationCipher(bit_size=4, permutation_description=[1, 3, 2, 0])
    permutation_component = cipher.component_from_id("permutation_0_0")
    algebraic = AlgebraicModel(cipher)
    algebraic_polynomials = permutation_component.algebraic_polynomials(algebraic)

    assert str(algebraic_polynomials) == '[permutation_0_0_y0 + permutation_0_0_x3,' \
                                         ' permutation_0_0_y1 + permutation_0_0_x0,' \
                                         ' permutation_0_0_y2 + permutation_0_0_x2,' \
                                         ' permutation_0_0_y3 + permutation_0_0_x1]'


def test_validation_zero_word_size():
    with pytest.raises(ValueError, match="word_size must be a positive integer"):
        Permutation(0, 0, ["input"], [[0, 1, 2, 3]], 4, [1, 3, 2, 0], word_size=0)


def test_validation_negative_word_size():
    with pytest.raises(ValueError, match="word_size must be a positive integer"):
        Permutation(0, 0, ["input"], [[0, 1, 2, 3]], 4, [1, 3, 2, 0], word_size=-1)


def test_validation_non_integer_word_size():
    with pytest.raises(ValueError, match="word_size must be an integer"):
        Permutation(0, 0, ["input"], [[0, 1, 2, 3]], 4, [1, 3, 2, 0], word_size=1.5)


def test_validation_output_bit_size_not_divisible_by_word_size():
    with pytest.raises(ValueError, match="output_bit_size .* divisible by word_size"):
        Permutation(0, 0, ["input"], [[0, 1, 2, 3, 4]], 5, [0], word_size=2)


def test_validation_permutation_description_wrong_length():
    # Expected length is 4 (8 bits / 2-bit words), but providing 3 entries.
    with pytest.raises(ValueError, match="permutation_description length .* does not match expected length"):
        Permutation(0, 0, ["input"], [[0, 1, 2, 3, 4, 5, 6, 7]], 8, [0, 1, 2], word_size=2)


def test_validation_permutation_description_duplicates():
    with pytest.raises(ValueError, match="not a valid permutation: .*duplicate values"):
        Permutation(0, 0, ["input"], [[0, 1, 2, 3]], 4, [0, 1, 1, 0])


def test_validation_permutation_description_out_of_range():
    with pytest.raises(ValueError, match="not a valid permutation: .*out-of-range values"):
        Permutation(0, 0, ["input"], [[0, 1, 2, 3]], 4, [0, 1, 2, 5])


def test_validation_permutation_description_missing_values():
    with pytest.raises(ValueError, match="not a valid permutation: .*missing values"):
        Permutation(0, 0, ["input"], [[0, 1, 2, 3]], 4, [0, 1, 2, 2])


def test_validation_word_size_valid():
    """Test that valid word_size > 1 works correctly."""
    permutation_component = Permutation(0, 0, ["input"], [[0, 1, 2, 3, 4, 5, 6, 7]], 8, [1, 0], word_size=4)
    assert permutation_component.description == [[1, 0], 4]


def test_milp_and_vectorized_helpers():
    cipher = PermutationCipher(bit_size=4, permutation_description=[1, 3, 2, 0])
    permutation_component = cipher.component_from_id("permutation_0_0")
    milp = MilpModel(cipher)
    milp.init_model_in_sage_milp_class()

    variables, constraints = permutation_component.milp_constraints(milp)
    assert len(variables) == 8
    assert len(constraints) == 4
    assert permutation_component.milp_xor_differential_propagation_constraints(milp) == (variables, constraints)
    assert permutation_component.milp_xor_linear_mask_propagation_constraints(milp) == (variables, constraints)
    assert permutation_component.get_bit_based_vectorized_python_code(["component_input"], False) == [
        "  permutation_0_0 = bit_vector_permutation([component_input ], [1, 3, 2, 0], 1)"
    ]
    assert permutation_component.get_byte_based_vectorized_python_code(["component_input"]) == [
        "  permutation_0_0 = byte_vector_permutation(['component_input'], [1, 3, 2, 0], 1, 4)"
    ]


def test_milp_bitwise_deterministic_truncated_constraints():
    cipher = PermutationCipher(bit_size=4, permutation_description=[1, 3, 2, 0])
    permutation_component = cipher.component_from_id("permutation_0_0")
    milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
    milp.init_model_in_sage_milp_class()

    variables, constraints = permutation_component.milp_bitwise_deterministic_truncated_xor_differential_constraints(
        milp
    )

    assert len(variables) == 8
    assert len(constraints) == 4


def test_milp_bitwise_deterministic_truncated_binary_constraints():
    cipher = PermutationCipher(bit_size=4, permutation_description=[1, 3, 2, 0])
    permutation_component = cipher.component_from_id("permutation_0_0")
    milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
    milp.init_model_in_sage_milp_class()

    variables, constraints = (
        permutation_component.milp_bitwise_deterministic_truncated_xor_differential_binary_constraints(milp)
    )

    assert len(variables) == 8
    # 8 linking constraints + 4 permutation equalities for a 4-bit component.
    assert len(constraints) == 12


def test_milp_wordwise_deterministic_truncated_constraints():
    component = Permutation(0, 0, ["input"], [[0, 1, 2, 3, 4, 5, 6, 7]], 8, [1, 0], word_size=4)
    cipher = PermutationCipher(bit_size=8, permutation_description=[1, 0], word_size=4)
    milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(cipher)
    milp.init_model_in_sage_milp_class()

    variables, constraints = component.milp_wordwise_deterministic_truncated_xor_differential_constraints(milp)

    assert len(variables) == 24
    assert len(constraints) == 12