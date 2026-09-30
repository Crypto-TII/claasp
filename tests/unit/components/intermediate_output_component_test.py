from sage.numerical.mip import MixedIntegerLinearProgram

from claasp.components.intermediate_output_component import IntermediateOutput


class DummyCpModel:
    bit_bindings_for_intermediate_output = {
        "intermediate_output_0_0": {
            "intermediate_output_0_0_i[0]": ["intermediate_output_0_0_o[0]"],
            "intermediate_output_0_0_i[1]": ["branch_0_o[0]", "branch_1_o[0]"],
            "intermediate_output_0_0_i[2]": ["branch_2_o[0]", "branch_3_o[0]", "branch_4_o[0]"],
            "intermediate_output_0_0_i[3]": ["intermediate_output_0_0_o[3]"],
        }
    }


class DummySatModel:
    bit_bindings_for_intermediate_output = {
        "intermediate_output_0_0": {
            "intermediate_output_0_0_i": ["intermediate_output_0_0_o"],
            "fork_bit_i": ["branch_0_o", "branch_1_o"],
            "wide_bit_i": ["branch_2_o", "branch_3_o", "branch_4_o"],
        }
    }


class DummySmtModel:
    bit_bindings_for_intermediate_output = {
        "intermediate_output_0_0": {
            "intermediate_output_0_0_i": ["intermediate_output_0_0_o"],
            "fork_bit_i": ["branch_0_o", "branch_1_o"],
            "wide_bit_i": ["branch_2_o", "branch_3_o", "branch_4_o"],
        }
    }


class DummyMilpModel:
    def __init__(self):
        self._model = MixedIntegerLinearProgram(maximization=False, solver="GLPK")
        self.binary_variable = self._model.new_variable(binary=True)
        self.intermediate_output_names = []
        self.bit_bindings_for_intermediate_output = {
            "intermediate_output_0_0": {
                "intermediate_output_0_0_0_i": ["intermediate_output_0_0_0_o"],
                "intermediate_output_0_0_1_i": ["branch_0_o", "branch_1_o"],
                "intermediate_output_0_0_2_i": ["branch_2_o", "branch_3_o", "branch_4_o"],
                "intermediate_output_0_0_3_i": ["intermediate_output_0_0_3_o"],
            }
        }


def make_component():
    return IntermediateOutput(0, 0, ["input"], [[0, 1, 2, 3]], 4, "round_output")


def test_cp_constraints():
    component = make_component()
    declarations, constraints = component.cp_constraints()

    assert declarations == []
    assert constraints == [
        "constraint intermediate_output_0_0[0] = input[0];",
        "constraint intermediate_output_0_0[1] = input[1];",
        "constraint intermediate_output_0_0[2] = input[2];",
        "constraint intermediate_output_0_0[3] = input[3];",
    ]


def test_cp_xor_linear_mask_propagation_constraints():
    component = make_component()
    declarations, constraints = component.cp_xor_linear_mask_propagation_constraints(DummyCpModel())

    assert declarations == [
        "array[0..3] of var 0..1: intermediate_output_0_0_i;",
        "array[0..3] of var 0..1: intermediate_output_0_0_o;",
    ]
    assert constraints[:4] == [
        "constraint intermediate_output_0_0_o[0] = intermediate_output_0_0_i[0];",
        "constraint intermediate_output_0_0_o[1] = intermediate_output_0_0_i[1];",
        "constraint intermediate_output_0_0_o[2] = intermediate_output_0_0_i[2];",
        "constraint intermediate_output_0_0_o[3] = intermediate_output_0_0_i[3];",
    ]
    assert constraints[4:] == [
        "constraint intermediate_output_0_0_i[0] = intermediate_output_0_0_o[0];",
        "constraint intermediate_output_0_0_i[1] = (branch_0_o[0] + branch_1_o[0]) mod 2;",
        "constraint intermediate_output_0_0_i[2] = (branch_2_o[0] + branch_3_o[0] + branch_4_o[0]) mod 2;",
        "constraint intermediate_output_0_0_i[3] = intermediate_output_0_0_o[3];",
    ]


def test_milp_xor_linear_mask_propagation_constraints():
    component = make_component()
    model = DummyMilpModel()
    variables, constraints = component.milp_xor_linear_mask_propagation_constraints(model)
    variable_strings = [str(variable) for variable in variables]
    constraint_strings = [str(constraint) for constraint in constraints]

    assert variable_strings[0] == "('x[intermediate_output_0_0_0_i]', x_0)"
    assert variable_strings[1] == "('x[intermediate_output_0_0_1_i]', x_1)"
    assert variable_strings[4] == "('x[intermediate_output_0_0_0_o]', x_4)"
    assert "('x[branch_0_o]', x_8)" in variable_strings
    assert variable_strings[-1] == "('x[intermediate_output_0_0_3_o]', x_7)"

    assert constraint_strings[0] == "x_4 == x_0"
    assert constraint_strings[3] == "x_7 == x_3"
    assert constraint_strings[4] == "x_0 == x_4"
    assert "1 <= 1 + x_1 - x_8 + x_9" in constraint_strings
    assert any(
        constraint.startswith("1 <= 3")
        and "x_10" in constraint
        and "x_11" in constraint
        and "x_12" in constraint
        and "x_2" in constraint
        for constraint in constraint_strings
    )
    assert constraint_strings[-1] == "x_3 == x_7"


def test_sat_xor_linear_mask_propagation_constraints():
    component = make_component()
    variables, constraints = component.sat_xor_linear_mask_propagation_constraints(DummySatModel())

    assert variables[0] == "intermediate_output_0_0_0_i"
    assert variables[1] == "intermediate_output_0_0_1_i"
    assert variables[-2] == "intermediate_output_0_0_2_o"
    assert variables[-1] == "intermediate_output_0_0_3_o"

    assert constraints[0] == "intermediate_output_0_0_0_i -intermediate_output_0_0_0_o"
    assert constraints[1] == "intermediate_output_0_0_0_o -intermediate_output_0_0_0_i"
    assert constraints[8] == "intermediate_output_0_0_i -intermediate_output_0_0_o"
    assert constraints[9] == "intermediate_output_0_0_o -intermediate_output_0_0_i"
    assert constraints[10] == "-fork_bit_i branch_0_o branch_1_o"
    assert "-inter_0_wide_bit_i branch_2_o branch_3_o" in constraints
    assert "wide_bit_i inter_0_wide_bit_i -branch_4_o" in constraints


def test_smt_xor_linear_mask_propagation_constraints():
    component = make_component()
    variables, constraints = component.smt_xor_linear_mask_propagation_constraints(DummySmtModel())

    assert variables[0] == "intermediate_output_0_0_0_o"
    assert variables[1] == "intermediate_output_0_0_1_o"
    assert variables[-2] == "intermediate_output_0_0_2_i"
    assert variables[-1] == "intermediate_output_0_0_3_i"

    assert constraints[:4] == [
        "(assert (= intermediate_output_0_0_0_o intermediate_output_0_0_0_i))",
        "(assert (= intermediate_output_0_0_1_o intermediate_output_0_0_1_i))",
        "(assert (= intermediate_output_0_0_2_o intermediate_output_0_0_2_i))",
        "(assert (= intermediate_output_0_0_3_o intermediate_output_0_0_3_i))",
    ]
    assert constraints[4] == "(assert (= intermediate_output_0_0_i intermediate_output_0_0_o))"
    assert constraints[5] == "(assert (= fork_bit_i (xor branch_0_o branch_1_o)))"
    assert constraints[6] == "(assert (= wide_bit_i (xor branch_2_o branch_3_o branch_4_o)))"
