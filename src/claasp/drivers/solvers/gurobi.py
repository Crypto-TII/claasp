"""Optional in-process driver for the proprietary Gurobi optimizer."""

import importlib
from time import monotonic

from claasp.drivers.solvers.milp_results import MILPResult, MILPStatus
from claasp.representations.constraints.milp.model import (
    ConstraintSense,
    MILPModel,
    ObjectiveSense,
    VariableKind,
)


class GurobiSolver:
    """Solve a portable MILP model when ``gurobipy`` and a license are present.

    Gurobi is an explicit optional capability. CLAASP never selects it as the
    default solver, and importing this class does not import ``gurobipy``.

    EXAMPLES::

        >>> solver = GurobiSolver(timeout_seconds=30)
        >>> solver.timeout_seconds
        30
    """

    def __init__(self, timeout_seconds: float | None = None) -> None:
        if timeout_seconds is not None and timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.timeout_seconds = timeout_seconds

    @staticmethod
    def is_available() -> bool:
        """Return whether the optional Python package can be imported."""

        try:
            importlib.import_module("gurobipy")
        except (ImportError, OSError):
            return False
        return True

    def solve(self, model: MILPModel) -> MILPResult:
        """Optimize ``model`` and independently validate any returned witness."""

        if not isinstance(model, MILPModel):
            raise TypeError("model must be an MILPModel")
        try:
            gp = importlib.import_module("gurobipy")
        except (ImportError, OSError) as error:
            raise ModuleNotFoundError(
                "Gurobi support requires the optional 'gurobipy' package and a valid license"
            ) from error

        started = monotonic()
        native = gp.Model("claasp")
        native.setParam("OutputFlag", 0)
        if self.timeout_seconds is not None:
            native.setParam("TimeLimit", self.timeout_seconds)
        kinds = {
            VariableKind.BINARY: gp.GRB.BINARY,
            VariableKind.INTEGER: gp.GRB.INTEGER,
            VariableKind.CONTINUOUS: gp.GRB.CONTINUOUS,
        }
        variables = {
            variable.name: native.addVar(
                lb=-gp.GRB.INFINITY if variable.lower_bound is None else variable.lower_bound,
                ub=gp.GRB.INFINITY if variable.upper_bound is None else variable.upper_bound,
                vtype=kinds[variable.kind],
                name=variable.name,
            )
            for variable in model.variables
        }

        def lower(expression):
            result = gp.LinExpr(float(expression.constant))
            for name, coefficient in expression.terms:
                result.addTerms(float(coefficient), variables[name])
            return result

        for constraint in model.constraints:
            expression = lower(constraint.expression)
            if constraint.sense is ConstraintSense.EQUAL:
                relation = expression == constraint.rhs
            elif constraint.sense is ConstraintSense.LESS_EQUAL:
                relation = expression <= constraint.rhs
            else:
                relation = expression >= constraint.rhs
            native.addConstr(relation, name=constraint.name or "")
        direction = (
            gp.GRB.MINIMIZE
            if model.objective_sense is ObjectiveSense.MINIMIZE
            else gp.GRB.MAXIMIZE
        )
        native.setObjective(lower(model.objective), direction)
        native.optimize()
        elapsed = monotonic() - started

        if native.Status == gp.GRB.OPTIMAL:
            status = MILPStatus.OPTIMAL
        elif native.Status == gp.GRB.INFEASIBLE:
            status = MILPStatus.INFEASIBLE
        elif native.SolCount > 0:
            status = MILPStatus.FEASIBLE
        else:
            status = MILPStatus.UNKNOWN
        assignment = (
            {name: float(variable.X) for name, variable in variables.items()}
            if status in (MILPStatus.OPTIMAL, MILPStatus.FEASIBLE)
            else None
        )
        objective = float(native.ObjVal) if assignment is not None else None
        if assignment is not None:
            if not model.is_feasible(assignment, tolerance=1e-6):
                raise RuntimeError("Gurobi returned an assignment that is not feasible")
            if objective is None or abs(model.objective_value(assignment) - objective) > 1e-6:
                raise RuntimeError("Gurobi objective disagrees with the returned assignment")
        return MILPResult(status, assignment, objective, elapsed, "", "")
