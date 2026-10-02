from itertools import product

import pytest

from claasp import Bit, Primitive, ValueType
from claasp.analysis import (
    AnalysisProblem,
    Equal,
    FixedValue,
    HammingWeight,
    MinimizeWeight,
    Nonzero,
    NotEqual,
)
from claasp.analysis.boolean import lower_boolean_problem
from claasp.components import Add
from claasp.drivers.solvers import SatResult, SatStatus


def _xor_primitive():
    primitive = Primitive("xor", {"left": ValueType(Bit(), (1,)), "key": ValueType(Bit(), (1,))})
    primitive.add_round()
    output = primitive.add_component(Add((primitive.input("left"), primitive.input("key"))))
    primitive.set_output(output)
    return primitive


def _satisfying_assignments(formula):
    for values in product((0, 1), repeat=formula.variable_count):
        assignment = dict(zip(formula.variables, values))
        if formula.is_satisfied(assignment):
            yield assignment


class _ExhaustiveSolver:
    def solve(self, formula):
        assignment = next(_satisfying_assignments(formula), None)
        status = SatStatus.SATISFIABLE if assignment is not None else SatStatus.UNSATISFIABLE
        return SatResult(status, assignment, 0.0, "", "")


def test_fixed_values_and_graph_level_projection_need_no_solver_names():
    primitive = _xor_primitive()
    problem = AnalysisProblem(
        primitive,
        (FixedValue(primitive.input("left"), 1), FixedValue(primitive.output, 0)),
        {"recovered_key": primitive.input("key")},
    )
    solutions = list(_satisfying_assignments(lower_boolean_problem(problem)))
    assert len(solutions) == 1
    assert solutions[0]["key_0"] == 1


def test_equality_inequality_nonzero_and_weight_constraints_lower_to_cnf():
    primitive = _xor_primitive()
    equal = AnalysisProblem(primitive, (Equal(primitive.input("left"), primitive.input("key")),))
    assert len(list(_satisfying_assignments(lower_boolean_problem(equal)))) == 2
    unequal = AnalysisProblem(
        primitive, (NotEqual(primitive.input("left"), primitive.input("key")),)
    )
    assert len(list(_satisfying_assignments(lower_boolean_problem(unequal)))) == 2
    nonzero = AnalysisProblem(primitive, (Nonzero(primitive.input("left")),))
    assert all(item["left_0"] for item in _satisfying_assignments(lower_boolean_problem(nonzero)))
    weight = AnalysisProblem(primitive, (HammingWeight(primitive.input("left"), 1, 1),))
    assert all(item["left_0"] for item in _satisfying_assignments(lower_boolean_problem(weight)))


def test_objectives_are_portable_but_plain_minisat_lowering_rejects_optimization():
    primitive = _xor_primitive()
    problem = AnalysisProblem(primitive, objective=MinimizeWeight(primitive.input("key")))
    with pytest.raises(NotImplementedError, match="optimization-capable"):
        lower_boolean_problem(problem)


def test_recovery_api_validates_user_facing_input_names():
    primitive = _xor_primitive()
    with pytest.raises(ValueError, match="unknown primitive input"):
        primitive.analyze().recover_input("missing", known_inputs={"left": 0}, output=0)
    with pytest.raises(ValueError, match="must not also be fixed"):
        primitive.analyze().recover_input("key", known_inputs={"left": 0, "key": 0}, output=0)


def test_fixed_value_rejects_wrong_sequence_length():
    primitive = _xor_primitive()
    problem = AnalysisProblem(primitive, (FixedValue(primitive.input("left"), (0, 1)),))
    with pytest.raises(ValueError, match="length"):
        lower_boolean_problem(problem)


def test_solution_enumeration_blocks_projected_values_and_honors_limit():
    primitive = _xor_primitive()
    problem = AnalysisProblem(
        primitive,
        (FixedValue(primitive.output, 0),),
        {"key": primitive.input("key")},
    )
    results = primitive.analyze().enumerate_solutions(problem, limit=5, solver=_ExhaustiveSolver())
    assert {result.value("key") for result in results} == {0, 1}
    assert len(results) == 2
    assert all(result.provenance.realization is primitive.realization for result in results)
    assert all(result.provenance.driver.name == "_ExhaustiveSolver" for result in results)
    assert all(result.reproducibility["realization"] == "default" for result in results)


def test_solution_enumeration_requires_a_positive_limit_and_projection():
    primitive = _xor_primitive()
    with pytest.raises(ValueError, match="positive"):
        primitive.analyze().enumerate_solutions(
            AnalysisProblem(primitive, projections={"key": primitive.input("key")}),
            limit=0,
            solver=_ExhaustiveSolver(),
        )
    with pytest.raises(ValueError, match="projection"):
        primitive.analyze().enumerate_solutions(
            AnalysisProblem(primitive), limit=1, solver=_ExhaustiveSolver()
        )
