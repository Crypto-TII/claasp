"""Optional HiGHS MILP execution through SciPy, without a solver license."""

from time import monotonic
from typing import overload

from claasp.drivers.solvers.base import SatResult, SatStatus
from claasp.drivers.solvers.milp_results import MILPResult, MILPStatus
from claasp.representations.constraints.milp.model import (
    ConstraintSense,
    MILPModel,
    ObjectiveSense,
    VariableKind,
)
from claasp.representations.constraints.sat import CNFFormula


class HighsSolver:
    """Solve portable MILP models with SciPy's bundled HiGHS implementation.

    SciPy is loaded only when solving. Interrupted runs retain feasible
    witnesses, but never become infeasibility or optimality proofs.

    EXAMPLES::

        >>> solver = HighsSolver(timeout_seconds=30)
        >>> solver.timeout_seconds
        30
    """

    def __init__(self, timeout_seconds: float | None = None):
        if timeout_seconds is not None and timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.timeout_seconds = timeout_seconds

    @overload
    def solve(self, model: MILPModel) -> MILPResult: ...

    @overload
    def solve(self, model: CNFFormula) -> SatResult: ...

    def solve(self, model: MILPModel | CNFFormula) -> MILPResult | SatResult:
        """Solve MILP or Boolean constraints and independently check witnesses.

        Trail search supplies a CNF relation. Each clause is translated to
        an exact binary linear inequality before invoking HiGHS. A checked
        feasible witness establishes SAT, even when optimization was interrupted;
        an interrupted run without a witness never establishes UNSAT.

        EXAMPLES::

            >>> from claasp.primitives import Speck
            >>> from claasp.drivers.solvers import HighsSolver
            >>> result = Speck(number_of_rounds=1).analysis.find_lowest_weight_xor_linear_trail(  # doctest: +SKIP
            ...     solver=HighsSolver(timeout_seconds=30))
            >>> result.is_optimal  # doctest: +SKIP
            True
        """
        if isinstance(model, CNFFormula):
            if not model.variables:
                return SatResult(SatStatus.SATISFIABLE, {}, 0.0, "empty conjunction", "")
            from claasp.representations.constraints.milp.boolean import cnf_to_milp

            solved = self.solve(cnf_to_milp(model))
            if solved.status is MILPStatus.UNKNOWN:
                raise RuntimeError("HiGHS returned unknown; Boolean infeasibility is not proved")
            assignment = (
                None
                if solved.assignment is None
                else {name: round(value) for name, value in solved.assignment.items()}
            )
            if assignment is not None and not model.is_satisfied(assignment):
                raise RuntimeError("HiGHS binary witness violates the original Boolean clauses")
            return SatResult(
                SatStatus.SATISFIABLE if solved.is_feasible else SatStatus.UNSATISFIABLE,
                assignment,
                solved.runtime_seconds,
                solved.stdout,
                solved.stderr,
            )
        if not isinstance(model, MILPModel):
            raise TypeError("model must be an MILPModel or CNFFormula")
        try:
            import numpy as np
            from scipy.optimize import Bounds, LinearConstraint, milp
            from scipy.sparse import coo_matrix
        except ImportError as error:
            raise ImportError(
                "HiGHS requires SciPy >= 1.9: pip install 'claasp[analysis]'"
            ) from error
        indices = {variable.name: index for index, variable in enumerate(model.variables)}
        rows, columns, coefficients = [], [], []
        lower, upper = [], []
        for row, constraint in enumerate(model.constraints):
            for name, coefficient in constraint.expression.terms:
                rows.append(row)
                columns.append(indices[name])
                coefficients.append(coefficient)
            rhs = constraint.rhs - constraint.expression.constant
            lower.append(-np.inf if constraint.sense is ConstraintSense.LESS_EQUAL else rhs)
            upper.append(np.inf if constraint.sense is ConstraintSense.GREATER_EQUAL else rhs)
        matrix = coo_matrix(
            (coefficients, (rows, columns)), shape=(len(lower), len(indices))
        ).tocsc()
        objective = np.zeros(len(indices))
        for name, coefficient in model.objective.terms:
            objective[indices[name]] = coefficient
        direction = -1 if model.objective_sense is ObjectiveSense.MAXIMIZE else 1
        options = {} if self.timeout_seconds is None else {"time_limit": self.timeout_seconds}
        started = monotonic()
        result = milp(
            direction * objective,
            integrality=np.array(
                [0 if v.kind is VariableKind.CONTINUOUS else 1 for v in model.variables]
            ),
            bounds=Bounds(
                [-np.inf if v.lower_bound is None else v.lower_bound for v in model.variables],
                [np.inf if v.upper_bound is None else v.upper_bound for v in model.variables],
            ),
            constraints=LinearConstraint(matrix, lower, upper),
            options=options,
        )
        elapsed = monotonic() - started
        if result.status == 2:
            return MILPResult(MILPStatus.INFEASIBLE, None, None, elapsed, result.message, "")
        if result.status not in (0, 1):
            raise RuntimeError(f"HiGHS failed: {result.message}")
        if result.x is None:
            return MILPResult(MILPStatus.UNKNOWN, None, None, elapsed, result.message, "")
        assignment = {
            variable.name: float(result.x[index]) for index, variable in enumerate(model.variables)
        }
        if not model.is_feasible(assignment, tolerance=1e-6):
            raise RuntimeError("HiGHS returned an infeasible assignment")
        recomputed = model.objective_value(assignment)
        expected = direction * float(result.fun) + model.objective.constant
        if abs(recomputed - expected) > 1e-6:
            raise RuntimeError("HiGHS objective disagrees with its assignment")
        status = MILPStatus.OPTIMAL if result.status == 0 else MILPStatus.FEASIBLE
        return MILPResult(status, assignment, recomputed, elapsed, result.message, "")


__all__ = ["HighsSolver"]
