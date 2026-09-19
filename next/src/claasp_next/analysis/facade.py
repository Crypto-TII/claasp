"""Simple user-facing analysis facade."""

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256

from claasp_next.analysis.boolean import lower_boolean_problem
from claasp_next.analysis.constraints import FixedValue
from claasp_next.analysis.problem import AnalysisProblem
from claasp_next.drivers.solvers import MinisatSolver, SatStatus
from claasp_next.graph import Primitive, Selection
from claasp_next.provenance import DriverIdentity, DriverKind, ResultProvenance
from claasp_next.representations.constraints.sat.cnf import CNFFormula
from claasp_next.representations.constraints.sat.encoding import (
    decode_unit,
    resolved_selection_variable_names,
)


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    """Projected user values and reproducibility data from an analysis.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (AnalysisResult.__dataclass_params__.frozen, tuple(field.name for field in fields(AnalysisResult)))
        (True, ('status', 'values', 'runtime_seconds', 'backend', 'statistics', 'reproducibility', 'solver_result', 'provenance'))
    """

    status: SatStatus
    values: Mapping[str, int | tuple[int, ...]]
    runtime_seconds: float
    backend: str
    statistics: Mapping[str, int]
    reproducibility: Mapping[str, str]
    solver_result: object
    provenance: ResultProvenance

    @property
    def is_satisfiable(self) -> bool:
        """Return the is satisfiable for this public typed contract."""

        return self.status is SatStatus.SATISFIABLE

    def value(self, name: str) -> int | tuple[int, ...]:
        """Return one projected logical value by its user-facing name."""

        try:
            return self.values[name]
        except KeyError as error:
            raise KeyError(f"analysis projection {name!r} does not exist") from error


class Analysis:
    """Create and solve analyses for one primitive graph.

    EXAMPLES::

        >>> try:
        ...     Analysis()
        ... except TypeError:
        ...     print("required configuration rejected")
        required configuration rejected
    """

    def __init__(self, primitive: Primitive) -> None:
        self.primitive = primitive

    def solve(self, problem: AnalysisProblem, solver: object | None = None) -> AnalysisResult:
        """Solve a backend-neutral problem through a SAT adapter."""

        if problem.primitive is not self.primitive:
            raise ValueError("analysis problem belongs to a different primitive")
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

        if problem.primitive is not self.primitive:
            raise ValueError("analysis problem belongs to a different primitive")
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
            for group in resolved_selection_variable_names(self.primitive, selection)
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
                projected[name] = self.primitive._encode_boundary(units, selection.value_type)
        if getattr(solved.status, "value", None) == "unknown":
            raise RuntimeError("solver returned unknown; no analysis result can be projected")
        status = SatStatus.SATISFIABLE if solved.is_satisfiable else SatStatus.UNSATISFIABLE
        return AnalysisResult(
            status,
            projected,
            solved.runtime_seconds,
            type(selected_solver).__name__,
            {"variables": formula.variable_count, "clauses": formula.clause_count},
            {
                "primitive": self.primitive.family_name,
                "realization": self.primitive.realization.name,
                "backend": type(selected_solver).__name__,
                "executable": str(getattr(selected_solver, "executable", "embedded")),
                "formula_sha256": sha256(
                    repr((formula.variables, formula.clauses)).encode()
                ).hexdigest(),
            },
            solved,
            ResultProvenance.for_primitive(
                self.primitive,
                DriverIdentity(type(selected_solver).__name__, DriverKind.SOLVER),
            ),
        )

    def recover_input(
        self,
        input_name: str,
        *,
        known_inputs: Mapping[str, object],
        output: object,
        solver: object | None = None,
    ) -> AnalysisResult:
        """Recover one unknown input from known inputs and primitive output."""

        if input_name not in self.primitive.input_ports:
            raise ValueError(f"unknown primitive input {input_name!r}")
        if input_name in known_inputs:
            raise ValueError("the recovered input must not also be fixed")
        expected_known = set(self.primitive.input_ports) - {input_name}
        if set(known_inputs) != expected_known:
            raise ValueError(f"known_inputs must contain exactly {sorted(expected_known)!r}")
        if self.primitive.output is None:
            raise ValueError("primitive has no declared output")
        constraints = [
            FixedValue(self.primitive.input(name), value) for name, value in known_inputs.items()
        ]
        constraints.append(FixedValue(self.primitive.output, output))
        problem = AnalysisProblem(
            self.primitive,
            constraints,
            {input_name: self.primitive.input(input_name)},
        )
        return self.solve(problem, solver)

    def find_lowest_weight_xor_differential_trail(self):
        """Find the lowest-weight trail supported by the reviewed graph slice."""

        if self.primitive.family_name == "speck":
            from claasp_next.analysis.arx import find_two_round_speck_xor_differential

            return find_two_round_speck_xor_differential(self.primitive)
        from claasp_next.analysis.spn import find_two_round_spn_xor_differential

        return find_two_round_spn_xor_differential(self.primitive)

    def avalanche(
        self,
        input_name: str,
        number_of_samples: int,
        *,
        seed: int = 0,
        fixed_inputs=None,
    ):
        """Estimate the strict-avalanche matrix through the public evaluator."""

        from claasp_next.analysis.avalanche import avalanche_probabilities

        return avalanche_probabilities(
            self.primitive,
            input_name,
            number_of_samples,
            seed=seed,
            fixed_inputs=fixed_inputs,
        )

    def component_groups(self, domain):
        """Return immutable semantic groups, never structural bindings.

        EXAMPLES::

            >>> from claasp_next.analysis import PropertyDomain
            >>> from claasp_next.primitives import Present
            >>> groups = Present(number_of_rounds=1).analyze().component_groups(PropertyDomain.LOOKUP_TABLE)
            >>> max(group.count for group in groups)
            17
        """

        from claasp_next.analysis.component_properties import semantic_component_groups

        return semantic_component_groups(self.primitive, domain)

    def component_property(self, component, property_, domain, *, options=(), driver=None):
        """Return one typed, evidence-qualified semantic component property.

        ``component`` may be a component object or a graph id used only to
        locate it. The returned semantic identity never depends on that id.

        EXAMPLES::

            >>> from claasp_next.analysis import ComponentProperty, PropertyDomain
            >>> from claasp_next.components import BitVectorSBox
            >>> from claasp_next.primitives import Present
            >>> primitive = Present(number_of_rounds=1)
            >>> sbox = next(item for item in primitive.components if isinstance(item, BitVectorSBox))
            >>> result = primitive.analyze().component_property(
            ...     sbox, ComponentProperty.DIFFERENTIAL_UNIFORMITY,
            ...     PropertyDomain.LOOKUP_TABLE)
            >>> result.value, result.claim.value
            (4, 'exact')
        """

        from claasp_next.analysis.component_properties import (
            PropertyRequest,
            analyze_component_property,
        )

        selected = self._component(component)
        request = PropertyRequest(property_, domain, tuple(options))
        locations = tuple(
            occurrence.graph_location
            for group in self.component_groups(request.domain)
            for occurrence in group.occurrences
            if occurrence.component is selected and occurrence.graph_location is not None
        )
        if driver is not None:
            from dataclasses import replace

            if not hasattr(driver, "analyze"):
                raise TypeError(
                    "component-property driver must provide analyze(component, request)"
                )
            result = driver.analyze(selected, request)
            if result.request != request:
                raise TypeError(
                    "component-property driver returned a result for a different request"
                )
            return replace(
                result,
                provenance=replace(
                    result.provenance,
                    primitive=self.primitive.family_name,
                    realization=self.primitive.realization.name,
                    graph_locations=locations,
                ),
            )
        return analyze_component_property(
            selected,
            request,
            graph_locations=locations,
            primitive=self.primitive.family_name,
            realization=self.primitive.realization.name,
        )

    def component_properties(self, component, requests, *, driver=None):
        """Return typed results for an explicit sequence of property requests."""

        selected = self._component(component)
        return tuple(
            self.component_property(
                selected,
                request.property,
                request.domain,
                options=request.options,
                driver=driver,
            )
            for request in tuple(requests)
        )

    def _component(self, component):
        from claasp_next.graph import Component

        if isinstance(component, Component):
            if not any(item is component for item in self.primitive.components):
                raise ValueError("component does not belong to this primitive graph")
            return component
        if isinstance(component, str):
            matches = tuple(
                item for item in self.primitive.components if item.component_id == component
            )
            if len(matches) != 1:
                raise KeyError(f"primitive component {component!r} does not exist")
            return matches[0]
        raise TypeError("component must be a graph Component or component id")

    def is_xor_differential_transition_possible(
        self, component_id: str, input_difference: int, output_difference: int
    ) -> bool:
        """Check an S-box transition directly from the typed graph."""

        from claasp_next.components import BitVectorSBox
        from claasp_next.semantics.cryptanalysis import SBoxTransitionSemantics

        component = next(
            (item for item in self.primitive.components if item.component_id == component_id),
            None,
        )
        if not isinstance(component, BitVectorSBox):
            raise NotImplementedError(
                "transition feasibility currently supports bit-vector S-boxes"
            )
        return (
            SBoxTransitionSemantics(component.table)
            .xor_differential(input_difference, output_difference)
            .is_possible
        )

    def enumerate_xor_differential_trails(
        self,
        maximum_weight=None,
        *,
        fixed_weight=None,
        solver=None,
        nonzero_input="plaintext",
        fixed_input_differences=None,
        output_difference=None,
        limit=1000,
    ):
        """Enumerate component-product characteristics with checked differences.

        The default is single-key (key difference zero). Select a nonzero
        key input to include related-key propagation instead.
        """
        from claasp_next.drivers.solvers import Z3Solver
        from claasp_next.representations.constraints.smt import WordDifferentialSMTModel

        if fixed_input_differences is None:
            fixed_input_differences = (
                {"key": 0} if "key" in self.primitive.input_ports and nonzero_input != "key" else {}
            )
        model = WordDifferentialSMTModel(
            self.primitive,
            maximum_weight=maximum_weight,
            fixed_weight=fixed_weight,
            nonzero_input=nonzero_input,
            fixed_input_differences=fixed_input_differences,
            output_difference=output_difference,
        )
        return model.enumerate_trails(Z3Solver() if solver is None else solver, limit=limit)

    def enumerate_xor_linear_trails(
        self,
        maximum_weight,
        *,
        solver=None,
        nonzero_input="plaintext",
        fixed_input_masks=None,
        fixed_inputs=None,
        limit=1000,
    ):
        """Enumerate checked Word-graph characteristics, not whole-primitive hulls.

        By default, a keyed graph fixes key value zero (single-key analysis).
        Requesting ``nonzero_input="key"`` instead includes key-schedule masks.
        Solver execution is optional and separate from graph realization.
        """
        from claasp_next.drivers.solvers import Z3Solver
        from claasp_next.representations.constraints.smt import WordLinearSMTModel

        if fixed_inputs is None and fixed_input_masks is None:
            fixed_inputs = (
                {"key": 0} if "key" in self.primitive.input_ports and nonzero_input != "key" else {}
            )
        model = WordLinearSMTModel(
            self.primitive,
            maximum_weight=maximum_weight,
            nonzero_input=nonzero_input,
            fixed_input_masks=fixed_input_masks,
            fixed_inputs=fixed_inputs,
        )
        return model.enumerate_trails(Z3Solver() if solver is None else solver, limit=limit)

    def find_lowest_weight_xor_linear_trail(self):
        """Find the lowest-weight linear trail supported by the reviewed slice."""

        if self.primitive.family_name == "speck":
            from claasp_next.analysis.arx import find_four_round_speck_xor_linear

            return find_four_round_speck_xor_linear(self.primitive)
        from claasp_next.analysis.spn import find_three_round_spn_xor_linear

        return find_three_round_spn_xor_linear(self.primitive)

    def _project(self, selection: Selection, assignment: Mapping[str, int]) -> tuple[int, ...]:
        return tuple(
            decode_unit(names, assignment)
            for names in resolved_selection_variable_names(self.primitive, selection)
        )
