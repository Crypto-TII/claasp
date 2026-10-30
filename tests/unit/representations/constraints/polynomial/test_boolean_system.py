from itertools import product

import pytest

from claasp.primitives import BitVectorSBox, ModularAdd, ModularSubtract, Speck
from claasp.representations.constraints.polynomial import BooleanEquationSystem


@pytest.mark.parametrize(
    "primitive",
    [BitVectorSBox(2, [0, 1, 3, 2]), ModularAdd(word_bit_size=2), ModularSubtract(word_bit_size=2)],
)
def test_local_equations_have_exactly_the_concrete_graph_solutions(primitive):
    system = BooleanEquationSystem.from_primitive(primitive)
    solutions = []
    for bits in product((0, 1), repeat=len(system.variables)):
        assignment = dict(zip(system.variables, bits))
        if all(equation.evaluate(assignment) == 0 for equation in system.equations):
            inputs = {
                name: sum(
                    assignment[var] << (len(names) - 1 - index) for index, var in enumerate(names)
                )
                for name, names in system.inputs
            }
            output = sum(
                poly.evaluate(assignment) << (len(system.outputs) - 1 - index)
                for index, poly in enumerate(system.outputs)
            )
            assert output == primitive.evaluate(**inputs)
            solutions.append(tuple(inputs.items()))
    input_bits = sum(len(names) for _, names in system.inputs)
    assert len(solutions) == len(set(solutions)) == 1 << input_bits


def test_wide_arx_system_retains_quadratic_carries():
    system = BooleanEquationSystem.from_primitive(Speck(number_of_rounds=7))
    assert max(poly.degree for poly in system.equations) == 2
    assert len(system.equations) < 3000
    assert set(system.rounds) == set(range(1, 8))


def test_singular_export_includes_field_equations_and_rejects_unknown_variables():
    system = BooleanEquationSystem.from_primitive(BitVectorSBox(2, [0, 1, 3, 2]))
    program = system.singular_program(fixed_variables={"v0": 1})
    assert "v0^2+v0" in program and "v0+1" in program
    assert "CLAASP_BASIS_END" in program
    with pytest.raises(ValueError):
        system.singular_program(fixed_variables={"unknown;quit": 1})


def test_user_constructed_system_cannot_inject_singular_commands():
    with pytest.raises(ValueError, match="identifiers"):
        BooleanEquationSystem((), (), ("v0);quit;",), (), ())
    from claasp.representations.constraints.polynomial import BooleanPolynomial

    with pytest.raises(ValueError, match="unregistered"):
        BooleanEquationSystem((BooleanPolynomial.variable("unknown"),), (1,), ("v0",), (), ())
