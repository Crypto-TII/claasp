from claasp.components.modular_component import Modular, generic_sign_linear_constraints


def make_modular_component(number_of_inputs=2, operation="modadd"):
    input_id_links = [f"in{i}" for i in range(number_of_inputs)]
    input_bit_positions = [list(range(4 * i, 4 * (i + 1))) for i in range(number_of_inputs)]
    return Modular(0, 0, input_id_links, input_bit_positions, 4, operation, 16)


def test_constructor_infers_operand_count_from_inputs():
    two_input = make_modular_component(number_of_inputs=2, operation="modadd")
    three_input = make_modular_component(number_of_inputs=3, operation="modadd")

    assert two_input.id == "modadd_0_0"
    assert two_input.type == "word_operation"
    assert two_input.description == ["MODADD", 2, 16]
    assert three_input.description == ["MODADD", 3, 16]


def test_cms_xor_differential_propagation_constraints_delegates_to_sat():
    component = make_modular_component()
    marker = object()

    component.sat_xor_differential_propagation_constraints = lambda model: marker

    assert component.cms_xor_differential_propagation_constraints(model="dummy") is marker


def test_cp_deterministic_trail_alias_matches_base_constraints():
    component = make_modular_component(number_of_inputs=3)

    direct = component.cp_deterministic_truncated_xor_differential_constraints()
    alias = component.cp_deterministic_truncated_xor_differential_trail_constraints()

    assert alias == direct


def test_cp_deterministic_truncated_constraints_build_chain_for_three_inputs():
    component = make_modular_component(number_of_inputs=3)
    result = component.cp_deterministic_truncated_xor_differential_constraints()
    declarations, constraints = result.declarations, result.constraints

    assert "array[0..3] of var 0..2: pre_modadd_0_0_0;" in declarations
    assert "array[0..3] of var 0..2: pre_modadd_0_0_1;" in declarations
    assert "array[0..3] of var 0..2: pre_modadd_0_0_2;" in declarations
    assert "array[0..3] of var 0..1: pre_modadd_0_0_3;" in declarations

    assert "constraint modular_addition_word(pre_modadd_0_0_2, pre_modadd_0_0_1, pre_modadd_0_0_3);" in constraints
    assert "constraint modular_addition_word(pre_modadd_0_0_3, pre_modadd_0_0_0, modadd_0_0);" in constraints


def test_generic_sign_linear_constraints_edge_patterns():
    assert generic_sign_linear_constraints([0, 0, 0, 0, 1, 0, 0, 0], [1, 1, 0, 0]) == -1
    assert generic_sign_linear_constraints([0, 0, 0, 0, 1, 0, 0, 0], [1, 0, 0, 0]) == 1