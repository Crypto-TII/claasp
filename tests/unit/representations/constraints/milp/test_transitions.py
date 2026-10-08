from itertools import product

from claasp.representations.constraints.milp import ModularAddLinearMILPModel, VariableKind
from claasp.semantics.cryptanalysis import ModularAddLinearSemantics


def test_modular_add_linear_milp_has_explicit_domains_and_fixed_masks():
    lowering = ModularAddLinearMILPModel(4)
    model = lowering.milp_model(left_mask=3, right_mask=5, output_mask=6)

    assert len(model.variables) == 4 * 4 + 3
    assert sum(variable.kind is VariableKind.INTEGER for variable in model.variables) == 3
    assert len(model.constraints) == 1 + 3 + 2 * 2 * 4 + 3 * 4


def test_modular_add_linear_milp_matches_every_two_bit_mask_transition():
    semantics = ModularAddLinearSemantics(2)

    for left, right, output in product(range(4), repeat=3):
        lowering = ModularAddLinearMILPModel(2)
        model = lowering.milp_model(
            left_mask=left,
            right_mask=right,
            output_mask=output,
        )
        assignments = []
        for weight_0, weight_1 in product(range(2), repeat=2):
            for parity_1 in range(3):
                assignment = {
                    **{
                        f"{prefix}_{bit}": (value >> (1 - bit)) & 1
                        for prefix, value in (
                            ("left", left),
                            ("right", right),
                            ("output", output),
                        )
                        for bit in range(2)
                    },
                    "weight_0": weight_0,
                    "weight_1": weight_1,
                    "parity_1": parity_1,
                }
                if model.is_feasible(assignment):
                    assignments.append(assignment)

        transition = semantics.xor_linear(left, right, output)
        assert bool(assignments) == transition.is_possible
        if transition.is_possible:
            encoded_weights = {
                assignment["weight_0"] + assignment["weight_1"]
                for assignment in assignments
            }
            assert encoded_weights == {transition.weight}
