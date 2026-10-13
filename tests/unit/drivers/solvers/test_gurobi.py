"""Optional Gurobi driver boundary."""

import importlib
from types import SimpleNamespace

import pytest

from claasp.drivers.solvers import GurobiSolver
from claasp.representations.constraints.milp import (
    ConstraintSense,
    LinearConstraint,
    LinearExpression,
    LinearVariable,
    MILPModel,
    VariableKind,
)


def test_gurobi_driver_is_lazy_and_never_a_default_dependency(monkeypatch):
    solver = GurobiSolver(timeout_seconds=3)
    model = MILPModel((LinearVariable("x", VariableKind.BINARY),), ())

    def unavailable(name):
        assert name == "gurobipy"
        raise ImportError("not installed")

    monkeypatch.setattr(importlib, "import_module", unavailable)
    assert not solver.is_available()
    with pytest.raises(ModuleNotFoundError, match="optional 'gurobipy'"):
        solver.solve(model)


def test_gurobi_driver_validates_configuration_and_model_type():
    with pytest.raises(ValueError, match="positive"):
        GurobiSolver(timeout_seconds=0)
    with pytest.raises(TypeError, match="MILPModel"):
        GurobiSolver().solve(object())
    with pytest.raises(TypeError, match="MILPModel"):
        GurobiSolver().solve_optimal_pool(object())
    with pytest.raises(ValueError, match="positive integer"):
        GurobiSolver().solve_optimal_pool(
            MILPModel((LinearVariable("x", VariableKind.BINARY),), ()), maximum_solutions=0
        )


def test_gurobi_driver_translates_and_rechecks_with_a_test_double(monkeypatch):
    class Expression:
        def __init__(self, constant):
            self.constant = constant
            self.terms = []

        def addTerms(self, coefficient, variable):
            self.terms.append((coefficient, variable))

        def __eq__(self, rhs):
            return ("=", self, rhs)

        def __le__(self, rhs):
            return ("<=", self, rhs)

        def __ge__(self, rhs):
            return (">=", self, rhs)

    class Variable:
        X = 1.0
        Xn = 1.0

    class NativeModel:
        def __init__(self, _name):
            self.Status = 2
            self.SolCount = 1
            self.ObjVal = 1.0
            self.constraints = []

        def setParam(self, *_args):
            pass

        def addVar(self, **_options):
            return Variable()

        def addConstr(self, relation, name):
            self.constraints.append((relation, name))

        def setObjective(self, expression, direction):
            self.objective = (expression, direction)

        def optimize(self):
            pass

    constants = SimpleNamespace(
        BINARY="B",
        INTEGER="I",
        CONTINUOUS="C",
        INFINITY=float("inf"),
        MINIMIZE=1,
        MAXIMIZE=-1,
        OPTIMAL=2,
        INFEASIBLE=3,
    )
    fake = SimpleNamespace(Model=NativeModel, LinExpr=Expression, GRB=constants)
    monkeypatch.setattr(importlib, "import_module", lambda _name: fake)
    model = MILPModel(
        (LinearVariable("x", VariableKind.BINARY),),
        (
            LinearConstraint(
                LinearExpression.from_terms({"x": 1}),
                ConstraintSense.GREATER_EQUAL,
                1,
                "active",
            ),
        ),
        LinearExpression.from_terms({"x": 1}),
    )
    solved = GurobiSolver(timeout_seconds=3).solve(model)
    assert solved.assignment == {"x": 1.0}
    assert solved.objective_value == 1.0
    pool = GurobiSolver(timeout_seconds=3).solve_optimal_pool(model, maximum_solutions=2)
    assert pool.assignments == ({"x": 1.0},)
    assert pool.objective_value == 1.0
    assert pool.is_exhaustive
