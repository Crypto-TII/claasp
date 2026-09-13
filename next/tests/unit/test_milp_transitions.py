from claasp_next.representations.constraints.milp import ModularAddLinearMILPModel, VariableKind


def test_modular_add_linear_milp_has_explicit_domains_and_fixed_masks():
    lowering = ModularAddLinearMILPModel(4)
    model = lowering.milp_model(left_mask=3, right_mask=5, output_mask=6)

    assert len(model.variables) == 4 * 4 + 3
    assert sum(variable.kind is VariableKind.INTEGER for variable in model.variables) == 3
    assert len(model.constraints) == 1 + 3 + 2 * 2 * 3 + 3 * 4
