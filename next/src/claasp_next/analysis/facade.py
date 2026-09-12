"""Simple user-facing analysis facade."""

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256

from claasp_next.analysis.boolean import lower_boolean_problem
from claasp_next.analysis.constraints import FixedValue
from claasp_next.analysis.problem import AnalysisProblem
from claasp_next.boolean.cnf import CNFFormula
from claasp_next.boolean.encoding import decode_unit, selection_variable_names
from claasp_next.boolean.solvers import MinisatSolver, SatResult, SatStatus
from claasp_next.core import Cipher, Selection


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    """Projected user values and reproducibility data from an analysis."""

    status: SatStatus
    values: Mapping[str, int | tuple[int, ...]]
    runtime_seconds: float
    backend: str
    statistics: Mapping[str, int]
    reproducibility: Mapping[str, str]
    solver_result: SatResult

    @property
    def is_satisfiable(self) -> bool:
        return self.status is SatStatus.SATISFIABLE

    def value(self, name: str) -> int | tuple[int, ...]:
        """Return one projected logical value by its user-facing name."""

        try:
            return self.values[name]
        except KeyError as error:
            raise KeyError(f"analysis projection {name!r} does not exist") from error


class Analysis:
    """Create and solve analyses for one cipher graph."""

    def __init__(self, cipher: Cipher) -> None:
        self.cipher = cipher

    def solve(self, problem: AnalysisProblem, solver: object | None = None) -> AnalysisResult:
        """Solve a backend-neutral problem through a SAT adapter."""

        if problem.cipher is not self.cipher:
            raise ValueError("analysis problem belongs to a different cipher")
        formula = lower_boolean_problem(problem)
        selected_solver = MinisatSolver() if solver is None else solver
        if not hasattr(selected_solver, "solve"):
            raise TypeError("solver must provide a solve(formula) method")
        solved = selected_solver.solve(formula)
        return self._result(problem, formula, selected_solver, solved)

    def enumerate_solutions(
        self,
        problem: AnalysisProblem,
        *,
        limit: int,
        solver: object | None = None,
    ) -> tuple[AnalysisResult, ...]:
        """Return up to ``limit`` distinct projected solutions.

        Each subsequent solve receives a blocking clause over the requested
        graph-level projections. At least one projection is therefore required.
        """

        if problem.cipher is not self.cipher:
            raise ValueError("analysis problem belongs to a different cipher")
        if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
            raise ValueError("solution limit must be a positive integer")
        if not problem.projections:
            raise ValueError("solution enumeration requires at least one projection")
        formula = lower_boolean_problem(problem)
        selected_solver = MinisatSolver() if solver is None else solver
        if not hasattr(selected_solver, "solve"):
            raise TypeError("solver must provide a solve(formula) method")
        results = []
        projected_names = tuple(
            name
            for selection in problem.projections.values()
            for group in selection_variable_names(selection)
            for name in group
        )
        while len(results) < limit:
            solved = selected_solver.solve(formula)
            result = self._result(problem, formula, selected_solver, solved)
            if not result.is_satisfiable:
                break
            results.append(result)
            indices = {name: index for index, name in enumerate(formula.variables, 1)}
            blocking = tuple(
                -indices[name] if solved.assignment[name] else indices[name]
                for name in projected_names
            )
            formula = CNFFormula(
                formula.variables,
                formula.clauses + (blocking,),
                formula.provenance + ("solution_block",),
            )
        return tuple(results)

    def _result(self, problem, formula, selected_solver, solved):
        projected = {}
        if solved.is_satisfiable:
            for name, selection in problem.projections.items():
                units = self._project(selection, solved.assignment)
                projected[name] = self.cipher._encode_boundary(units, selection.value_type)
        return AnalysisResult(
            solved.status,
            projected,
            solved.runtime_seconds,
            type(selected_solver).__name__,
            {"variables": formula.variable_count, "clauses": formula.clause_count},
            {
                "cipher": self.cipher.family_name,
                "backend": type(selected_solver).__name__,
                "executable": str(getattr(selected_solver, "executable", "embedded")),
                "formula_sha256": sha256(repr((formula.variables, formula.clauses)).encode()).hexdigest(),
            },
            solved,
        )

    def recover_input(
        self,
        input_name: str,
        *,
        known_inputs: Mapping[str, object],
        output: object,
        solver: object | None = None,
    ) -> AnalysisResult:
        """Recover one unknown input from known inputs and cipher output."""

        if input_name not in self.cipher.inputs:
            raise ValueError(f"unknown cipher input {input_name!r}")
        if input_name in known_inputs:
            raise ValueError("the recovered input must not also be fixed")
        expected_known = set(self.cipher.inputs) - {input_name}
        if set(known_inputs) != expected_known:
            raise ValueError(
                f"known_inputs must contain exactly {sorted(expected_known)!r}"
            )
        if self.cipher.output is None:
            raise ValueError("cipher has no declared output")
        constraints = [
            FixedValue(self.cipher.input(name), value) for name, value in known_inputs.items()
        ]
        constraints.append(FixedValue(self.cipher.output, output))
        problem = AnalysisProblem(
            self.cipher,
            constraints,
            {input_name: self.cipher.input(input_name)},
        )
        return self.solve(problem, solver)

    def find_lowest_weight_xor_differential_trail(self):
        """Find the lowest-weight trail supported by the reviewed graph slice."""

        if self.cipher.family_name == "speck":
            from claasp_next.analysis.arx import find_two_round_speck_xor_differential

            return find_two_round_speck_xor_differential(self.cipher)
        from claasp_next.analysis.spn import find_two_round_spn_xor_differential

        return find_two_round_spn_xor_differential(self.cipher)

    def is_xor_differential_transition_possible(
        self, component_id: str, input_difference: int, output_difference: int
    ) -> bool:
        """Check an S-box transition directly from the typed graph."""

        from claasp_next.analysis.trails import SBoxTransitionSemantics
        from claasp_next.components import BitVectorSBox

        component = next(
            (item for item in self.cipher.components if item.component_id == component_id),
            None,
        )
        if not isinstance(component, BitVectorSBox):
            raise NotImplementedError("transition feasibility currently supports bit-vector S-boxes")
        return SBoxTransitionSemantics(component.table).xor_differential(
            input_difference, output_difference
        ).is_possible

    @staticmethod
    def _project(selection: Selection, assignment: Mapping[str, int]) -> tuple[int, ...]:
        return tuple(
            decode_unit(names, assignment)
            for names in selection_variable_names(selection)
        )
