"""Optional in-process driver for the proprietary Gurobi optimizer."""

import importlib
from collections.abc import Mapping
from dataclasses import dataclass
from time import monotonic

from claasp.drivers.solvers.milp_results import MILPResult, MILPStatus
from claasp.representations.constraints.milp.model import (
    ConstraintSense,
    MILPModel,
    ObjectiveSense,
    VariableKind,
)


@dataclass(frozen=True, slots=True)
class GurobiSolutionPoolResult:
    """Validated optimal assignments returned by Gurobi's solution pool.

    ``is_exhaustive`` is false when the requested pool capacity was reached,
    because more optimal assignments may exist.

    EXAMPLES::

        >>> result = GurobiSolutionPoolResult(
        ...     MILPStatus.OPTIMAL, ({"x": 1.0},), 1.0, 0.01, True
        ... )
        >>> (result.solution_count, result.is_exhaustive)
        (1, True)
    """

    status: MILPStatus
    assignments: tuple[Mapping[str, float], ...]
    objective_value: float | None
    runtime_seconds: float
    is_exhaustive: bool

    @property
    def solution_count(self) -> int:
        """Return the number of validated assignments in the pool."""

        return len(self.assignments)


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
        started = monotonic()
        gp, native, variables = self._build_native(model)
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

    def solve_optimal_pool(
        self, model: MILPModel, *, maximum_solutions: int = 1_000
    ) -> GurobiSolutionPoolResult:
        """Enumerate and validate up to ``maximum_solutions`` optimal assignments.

        This is an explicit Gurobi-only capability used by legacy monomial
        workflows. It is never selected by portable analyses or by default.
        """

        if not isinstance(model, MILPModel):
            raise TypeError("model must be an MILPModel")
        if (
            not isinstance(maximum_solutions, int)
            or isinstance(maximum_solutions, bool)
            or maximum_solutions <= 0
        ):
            raise ValueError("maximum_solutions must be a positive integer")
        started = monotonic()
        gp, native, variables = self._build_native(model)
        native.setParam("PoolSearchMode", 2)
        native.setParam("PoolSolutions", maximum_solutions)
        native.setParam("PoolGap", 0.0)
        native.optimize()
        elapsed = monotonic() - started
        if native.Status == gp.GRB.INFEASIBLE:
            return GurobiSolutionPoolResult(MILPStatus.INFEASIBLE, (), None, elapsed, True)
        if native.SolCount == 0:
            return GurobiSolutionPoolResult(MILPStatus.UNKNOWN, (), None, elapsed, False)
        status = MILPStatus.OPTIMAL if native.Status == gp.GRB.OPTIMAL else MILPStatus.FEASIBLE
        objective = float(native.ObjVal)
        assignments = []
        for solution_number in range(native.SolCount):
            native.setParam("SolutionNumber", solution_number)
            assignment = {name: float(variable.Xn) for name, variable in variables.items()}
            if not model.is_feasible(assignment, tolerance=1e-6):
                raise RuntimeError("Gurobi returned an infeasible solution-pool assignment")
            if abs(model.objective_value(assignment) - objective) > 1e-6:
                raise RuntimeError("Gurobi solution pool contains a non-optimal assignment")
            assignments.append(assignment)
        return GurobiSolutionPoolResult(
            status,
            tuple(assignments),
            objective,
            elapsed,
            status is MILPStatus.OPTIMAL and native.SolCount < maximum_solutions,
        )

    def _build_native(self, model: MILPModel):
        try:
            gp = importlib.import_module("gurobipy")
        except (ImportError, OSError) as error:
            raise ModuleNotFoundError(
                "Gurobi support requires the optional 'gurobipy' package and a valid license"
            ) from error

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
            gp.GRB.MINIMIZE if model.objective_sense is ObjectiveSense.MINIMIZE else gp.GRB.MAXIMIZE
        )
        native.setObjective(lower(model.objective), direction)
        return gp, native, variables


__all__ = ["GurobiSolutionPoolResult", "GurobiSolver"]
