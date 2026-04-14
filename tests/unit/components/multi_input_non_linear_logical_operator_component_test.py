from claasp.components.multi_input_non_linear_logical_operator_component import MultiInputNonlinearLogicalOperator
from claasp.cipher_modules.models.cp.cp_build_state import CpBuildState


def make_component(number_of_inputs=2, operation="and"):
    input_id_links = [f"in{i}" for i in range(number_of_inputs)]
    input_bit_positions = [list(range(4 * i, 4 * (i + 1))) for i in range(number_of_inputs)]
    return MultiInputNonlinearLogicalOperator(0, 0, input_id_links, input_bit_positions, 4, operation)


def test_constructor_infers_operand_count_from_inputs():
    two_input = make_component(number_of_inputs=2, operation="and")
    three_input = make_component(number_of_inputs=3, operation="and")

    assert two_input.id == "and_0_0"
    assert two_input.type == "word_operation"
    assert two_input.description == ["AND", 2]
    assert three_input.description == ["AND", 3]


def test_cms_delegates_to_sat_methods():
    component = make_component()
    cms_marker = object()
    diff_marker = object()
    linear_marker = object()

    component.sat_constraints = lambda: cms_marker
    component.sat_xor_differential_propagation_constraints = lambda model=None: diff_marker
    component.sat_xor_linear_mask_propagation_constraints = lambda model=None: linear_marker

    assert component.cms_constraints() is cms_marker
    assert component.cms_xor_differential_propagation_constraints(model="dummy") is diff_marker
    assert component.cms_xor_linear_mask_propagation_constraints(model="dummy") is linear_marker


def test_cp_deterministic_truncated_constraints_base_logic():
    component = make_component()
    result = component.cp_deterministic_truncated_xor_differential_constraints()
    declarations, constraints = result.declarations, result.constraints

    assert declarations == []
    assert constraints[0] == "constraint if in0[0] == 0 /\\ in1[4] == 0 then and_0_0[0] = 0 else and_0_0[0] = 2 endif;"
    assert constraints[-1] == "constraint if in0[3] == 0 /\\ in1[7] == 0 then and_0_0[3] = 0 else and_0_0[3] = 2 endif;"


def test_cp_deterministic_trail_alias_matches_base_constraints():
    component = make_component(number_of_inputs=3)

    direct = component.cp_deterministic_truncated_xor_differential_constraints()
    alias = component.cp_deterministic_truncated_xor_differential_trail_constraints()

    assert alias == direct


def test_cp_xor_differential_updates_model_counter_and_probability_map():
    component = make_component(number_of_inputs=3)
    state = CpBuildState()
    result = component.cp_xor_differential_propagation_constraints(None, state)

    assert result.declarations == []
    assert result.constraints[0] == "constraint table([in0[0]]++[in1[4]]++[in2[8]]++[and_0_0[0]]++[p[0]],and3inputs_DDT);"
    assert result.constraints[-1] == "constraint table([in0[3]]++[in1[7]]++[in2[11]]++[and_0_0[3]]++[p[3]],and3inputs_DDT);"
    assert state.next_probability_index == 4
    assert state.component_probability_map["and_0_0"] == [1, 2, 3, 4]


def test_cp_wordwise_deterministic_constraints_use_model_word_size():
    class DummyModel:
        word_size = 2

    component = make_component(number_of_inputs=2)
    result = component.cp_wordwise_deterministic_truncated_xor_differential_constraints(DummyModel())
    declarations, constraints = result.declarations, result.constraints

    assert declarations == []
    assert constraints[0] == "constraint if in0_active[0] == 0 /\\ in1_active[2] == 0 then and_0_0_active[0] = 0 /\\ and_0_0_value[0] = 0 else and_0_0_active[0] = 3 /\\ and_0_0_value[0] = -2 endif;"
    assert constraints[-1] == "constraint if in0_active[1] == 0 /\\ in1_active[3] == 0 then and_0_0_active[1] = 0 /\\ and_0_0_value[1] = 0 else and_0_0_active[1] = 3 /\\ and_0_0_value[1] = -2 endif;"
