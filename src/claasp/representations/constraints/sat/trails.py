"""Complete SAT assembly for weighted word-graph trail searches."""

from contextlib import nullcontext
from hashlib import sha256
from typing import Any

from claasp.components import ModularAdd
from claasp.drivers.solvers import SatStatus
from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    ConstraintModelProvenance,
    _direct_model,
)
from claasp.representations.constraints.sat.components import (
    ModularAddDifferentialSATModel,
    ModularAddLinearSATModel,
)
from claasp.representations.constraints.sat.model import CNFFormula
from claasp.representations.constraints.smt.trails import (
    WordDifferentialEnumeration,
    WordDifferentialSMTModel,
    WordLinearEnumeration,
    WordLinearSMTModel,
)


def _component_applications(primitive, default, specialized):
    grouped: dict[ConstraintModelProvenance, list[str]] = {model: [] for _, model in specialized}
    grouped[default] = []
    for component in primitive.components:
        model = next(
            (
                model
                for component_type, model in specialized
                if isinstance(component, component_type)
            ),
            default,
        )
        grouped[model].append(component.component_id)
    return tuple(
        ConstraintModelApplication(model, tuple(component_ids))
        for model, component_ids in grouped.items()
        if component_ids
    )


def _cnf(formula, constraint_models) -> CNFFormula:
    return CNFFormula(
        formula.variables,
        formula.assertions,
        formula.provenance,
        constraint_models,
    )


def _enumeration_metadata(model, formula, solver, extra=()):
    return (
        ("primitive", model.primitive.family_name),
        (
            "realization",
            getattr(getattr(model.primitive, "realization", None), "name", "default"),
        ),
        ("backend", "sat"),
        ("solver", type(solver).__name__),
        ("executable", str(getattr(solver, "executable", "embedded"))),
        (
            "version",
            solver.version() if callable(getattr(solver, "version", None)) else "unreported",
        ),
        *extra,
        (
            "graph_sha256",
            sha256(
                repr(
                    (
                        model.primitive.input_ports,
                        model.primitive.bindings,
                        tuple(model.primitive.components),
                        model.primitive.output,
                    )
                ).encode()
            ).hexdigest(),
        ),
        ("formula_sha256", sha256(repr(formula).encode()).hexdigest()),
    )


def _enumerate(model, formula, solver, enumeration_type, metadata, limit):
    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        raise ValueError("limit must be a positive integer")
    indices = {name: index for index, name in enumerate(formula.variables, 1)}
    trails: list[Any] = []
    blocks: list[tuple[int, ...]] = []
    runtime = 0.0
    context = (
        solver.incremental(formula)
        if callable(getattr(solver, "incremental", None))
        else nullcontext(solver)
    )
    with context as execution:
        while True:
            current = CNFFormula(
                formula.variables,
                formula.clauses + tuple(blocks),
                formula.provenance + ("characteristic_block",) * len(blocks),
                formula.constraint_models,
            )
            result = execution.solve(current)
            runtime += result.runtime_seconds
            if result.status is SatStatus.UNSATISFIABLE:
                return enumeration_type(tuple(trails), True, runtime, metadata)
            if result.status is not SatStatus.SATISFIABLE or len(trails) == limit:
                return enumeration_type(tuple(trails), False, runtime, metadata)
            trail = model.decode_characteristic(result.assignment)
            trails.append(trail)
            blocks.append(
                tuple(
                    -indices[name] if value else indices[name]
                    for name, value in trail.semantic_assignment
                )
            )


class WordDifferentialSATModel:
    """Assemble exact XOR-differential component relations as ordinary CNF.

    The model supports the same typed Word graph as the backend-neutral Boolean
    assembly, including modular addition and bitwise AND. Deterministic wiring,
    boundary restrictions, nonzero inputs, and total-weight restrictions are
    included in one solver-ready formula.

    EXAMPLES::

        >>> from claasp.primitives import ToySpeck
        >>> model = WordDifferentialSATModel(
        ...     ToySpeck(2), fixed_weight=1, nonzero_input="plaintext",
        ...     fixed_input_differences={"key": 0},
        ... )
        >>> formula = model.cnf_formula()
        >>> (formula.variable_count > 0, "nonzero_external_difference" in formula.provenance)
        (True, True)
    """

    model_provenance = _direct_model(
        ConstraintBackend.SAT,
        "WordDifferentialSATModel",
        "xor_differential",
        "direct word-graph difference composition",
        "Component relations and graph wiring are composed directly as Boolean clauses.",
    )

    def __init__(
        self,
        primitive,
        *,
        maximum_weight=None,
        fixed_weight=None,
        nonzero_input=None,
        fixed_input_differences=None,
        output_difference=None,
    ) -> None:
        self._shared = WordDifferentialSMTModel(
            primitive,
            maximum_weight=maximum_weight,
            fixed_weight=fixed_weight,
            nonzero_input=nonzero_input,
            fixed_input_differences=fixed_input_differences,
            output_difference=output_difference,
        )
        self.primitive = self._shared.primitive
        self.maximum_weight = self._shared.maximum_weight
        self.fixed_weight = self._shared.fixed_weight
        self.nonzero_input = self._shared.nonzero_input
        self.fixed_input_differences = self._shared.fixed_input_differences
        self.output_difference = self._shared.output_difference

    def cnf_formula(self) -> CNFFormula:
        """Return the complete weighted differential trail formula."""

        formula = self._shared.smt_formula()
        return _cnf(
            formula,
            _component_applications(
                self.primitive,
                self.model_provenance,
                ((ModularAdd, ModularAddDifferentialSATModel.model_provenance),),
            ),
        )

    def decode_characteristic(self, assignment):
        """Decode and independently validate a complete SAT assignment."""

        return self._shared.decode_characteristic(assignment)

    def check_characteristic(self, trail) -> bool:
        """Recheck component transitions, graph wiring, and requested bounds."""

        return self._shared.check_characteristic(trail)

    def enumerate_trails(self, solver, *, limit=1000):
        """Enumerate distinct semantic characteristics until UNSAT or ``limit``."""

        formula = self.cnf_formula()
        metadata = _enumeration_metadata(
            self,
            formula,
            solver,
            (
                ("weight_range", repr((self.fixed_weight, self.maximum_weight))),
                (
                    "fixed_input_differences",
                    repr(tuple(sorted(self.fixed_input_differences.items()))),
                ),
                ("output_difference", repr(self.output_difference)),
            ),
        )
        return _enumerate(
            self,
            formula,
            solver,
            WordDifferentialEnumeration,
            metadata,
            limit,
        )


class WordLinearSATModel:
    """Assemble exact XOR-linear component masks and fanout as ordinary CNF.

    External input masks, constants, component mask relations, fanout, and the
    total-weight bound are represented explicitly. Decoding independently
    rechecks component transitions, correlation signs, and graph wiring.

    EXAMPLES::

        >>> from claasp.primitives import ToySpeck
        >>> model = WordLinearSATModel(
        ...     ToySpeck(3), maximum_weight=1, nonzero_input="plaintext",
        ...     fixed_inputs={"key": 0},
        ... )
        >>> formula = model.cnf_formula()
        >>> (formula.variable_count > 0, "nonzero_external_mask" in formula.provenance)
        (True, True)
    """

    model_provenance = _direct_model(
        ConstraintBackend.SAT,
        "WordLinearSATModel",
        "xor_linear",
        "direct word-graph mask composition",
        "Component mask relations and fanout are composed directly as Boolean clauses.",
    )

    def __init__(
        self,
        primitive,
        *,
        maximum_weight,
        nonzero_input=None,
        fixed_input_masks=None,
        fixed_inputs=None,
    ) -> None:
        self._shared = WordLinearSMTModel(
            primitive,
            maximum_weight=maximum_weight,
            nonzero_input=nonzero_input,
            fixed_input_masks=fixed_input_masks,
            fixed_inputs=fixed_inputs,
        )
        self.primitive = self._shared.primitive
        self.maximum_weight = self._shared.maximum_weight
        self.nonzero_input = self._shared.nonzero_input
        self.fixed_input_masks = self._shared.fixed_input_masks
        self.fixed_inputs = self._shared.fixed_inputs

    def cnf_formula(self) -> CNFFormula:
        """Return the complete weighted linear trail formula."""

        formula = self._shared.smt_formula()
        return _cnf(
            formula,
            _component_applications(
                self.primitive,
                self.model_provenance,
                ((ModularAdd, ModularAddLinearSATModel.model_provenance),),
            ),
        )

    def decode_characteristic(self, assignment):
        """Decode and independently validate a complete SAT assignment."""

        return self._shared.decode_characteristic(assignment)

    def check_characteristic(self, trail) -> bool:
        """Recheck component masks, fanout, signs, and the weight bound."""

        return self._shared.check_characteristic(trail)

    def enumerate_trails(self, solver, *, limit=1000):
        """Enumerate distinct semantic characteristics until UNSAT or ``limit``."""

        formula = self.cnf_formula()
        metadata = _enumeration_metadata(
            self,
            formula,
            solver,
            (("fixed_inputs", repr(tuple(sorted(self.fixed_inputs.items())))),),
        )
        return _enumerate(self, formula, solver, WordLinearEnumeration, metadata, limit)


__all__ = [
    "WordDifferentialSATModel",
    "WordLinearSATModel",
]
