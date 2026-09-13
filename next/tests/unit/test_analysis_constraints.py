from itertools import product

import pytest

from claasp_next import Bit, Cipher, ValueType
from claasp_next.analysis import (
    AnalysisProblem,
    Equal,
    FixedValue,
    HammingWeight,
    MinimizeWeight,
    Nonzero,
    NotEqual,
)
from claasp_next.analysis.boolean import lower_boolean_problem
from claasp_next.components import Add
from claasp_next.drivers.solvers import SatResult, SatStatus


def _xor_cipher():
    cipher = Cipher("xor", {"left": ValueType(Bit(), (1,)), "key": ValueType(Bit(), (1,))})
    cipher.add_round()
    output = cipher.add_component(Add((cipher.input("left"), cipher.input("key"))))
    cipher.set_output(output)
    return cipher


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
    cipher = _xor_cipher()
    problem = AnalysisProblem(
        cipher,
        (FixedValue(cipher.input("left"), 1), FixedValue(cipher.output, 0)),
        {"recovered_key": cipher.input("key")},
    )
    solutions = list(_satisfying_assignments(lower_boolean_problem(problem)))
    assert len(solutions) == 1
    assert solutions[0]["key_0"] == 1


def test_equality_inequality_nonzero_and_weight_constraints_lower_to_cnf():
    cipher = _xor_cipher()
    equal = AnalysisProblem(cipher, (Equal(cipher.input("left"), cipher.input("key")),))
    assert len(list(_satisfying_assignments(lower_boolean_problem(equal)))) == 2
    unequal = AnalysisProblem(cipher, (NotEqual(cipher.input("left"), cipher.input("key")),))
    assert len(list(_satisfying_assignments(lower_boolean_problem(unequal)))) == 2
    nonzero = AnalysisProblem(cipher, (Nonzero(cipher.input("left")),))
    assert all(item["left_0"] for item in _satisfying_assignments(lower_boolean_problem(nonzero)))
    weight = AnalysisProblem(cipher, (HammingWeight(cipher.input("left"), 1, 1),))
    assert all(item["left_0"] for item in _satisfying_assignments(lower_boolean_problem(weight)))


def test_objectives_are_portable_but_plain_minisat_lowering_rejects_optimization():
    cipher = _xor_cipher()
    problem = AnalysisProblem(cipher, objective=MinimizeWeight(cipher.input("key")))
    with pytest.raises(NotImplementedError, match="optimization-capable"):
        lower_boolean_problem(problem)


def test_recovery_api_validates_user_facing_input_names():
    cipher = _xor_cipher()
    with pytest.raises(ValueError, match="unknown cipher input"):
        cipher.analyze().recover_input("missing", known_inputs={"left": 0}, output=0)
    with pytest.raises(ValueError, match="must not also be fixed"):
        cipher.analyze().recover_input(
            "key", known_inputs={"left": 0, "key": 0}, output=0
        )


def test_fixed_value_rejects_wrong_sequence_length():
    cipher = _xor_cipher()
    problem = AnalysisProblem(cipher, (FixedValue(cipher.input("left"), (0, 1)),))
    with pytest.raises(ValueError, match="length"):
        lower_boolean_problem(problem)


def test_solution_enumeration_blocks_projected_values_and_honors_limit():
    cipher = _xor_cipher()
    problem = AnalysisProblem(
        cipher,
        (FixedValue(cipher.output, 0),),
        {"key": cipher.input("key")},
    )
    results = cipher.analyze().enumerate_solutions(
        problem, limit=5, solver=_ExhaustiveSolver()
    )
    assert {result.value("key") for result in results} == {0, 1}
    assert len(results) == 2


def test_solution_enumeration_requires_a_positive_limit_and_projection():
    cipher = _xor_cipher()
    with pytest.raises(ValueError, match="positive"):
        cipher.analyze().enumerate_solutions(
            AnalysisProblem(cipher, projections={"key": cipher.input("key")}),
            limit=0,
            solver=_ExhaustiveSolver(),
        )
    with pytest.raises(ValueError, match="projection"):
        cipher.analyze().enumerate_solutions(
            AnalysisProblem(cipher), limit=1, solver=_ExhaustiveSolver()
        )
