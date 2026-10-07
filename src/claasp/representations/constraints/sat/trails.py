"""Complete SAT assembly for weighted word-graph trail searches."""

from contextlib import nullcontext
from dataclasses import dataclass, replace
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
    ModularAddNWindowSATModel,
)
from claasp.representations.constraints.sat.lowering import _native_xor_formula
from claasp.representations.constraints.sat.model import CNFFormula, NativeXorCNFFormula
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


@dataclass(frozen=True, slots=True, init=False)
class NWindowSATStrategy:
    """Select optional modular-add carry-difference run bounds.

    Choose one uniform window, one value per authored round, or one value per
    modular-add component.  ``None`` and the legacy value ``-1`` disable a
    location.  Full-window counting is optional and counts overlapping runs.

    EXAMPLES::

        >>> NWindowSATStrategy(2).window_size
        2
        >>> strategy = NWindowSATStrategy(
        ...     by_component={"modular_add_0_1": 2},
        ...     number_of_full_windows=1,
        ...     full_window_operator="at_most",
        ... )
        >>> strategy.full_window_operator
        'at_most'
    """

    window_size: int | None
    by_round: tuple[int | None, ...] | None
    by_component: tuple[tuple[str, int | None], ...] | None
    number_of_full_windows: int | None
    full_window_operator: str

    def __init__(
        self,
        window_size=None,
        *,
        by_round=None,
        by_component=None,
        number_of_full_windows=None,
        full_window_operator="at_least",
    ) -> None:
        choices = sum(value is not None for value in (window_size, by_round, by_component))
        if choices != 1:
            raise ValueError("choose exactly one uniform, per-round, or per-component window")
        if number_of_full_windows is not None and (
            not isinstance(number_of_full_windows, int)
            or isinstance(number_of_full_windows, bool)
            or number_of_full_windows < 0
        ):
            raise ValueError("number_of_full_windows must be a nonnegative integer")
        if full_window_operator not in {"at_least", "at_most", "exactly"}:
            raise ValueError("full_window_operator must be at_least, at_most, or exactly")
        object.__setattr__(
            self,
            "window_size",
            self._window(window_size) if window_size is not None else None,
        )
        normalized_rounds = (
            tuple(self._window(value) for value in by_round) if by_round is not None else None
        )
        normalized_components = (
            tuple(sorted((name, self._window(value)) for name, value in by_component.items()))
            if by_component is not None
            else None
        )
        object.__setattr__(self, "by_round", normalized_rounds)
        object.__setattr__(self, "by_component", normalized_components)
        object.__setattr__(self, "number_of_full_windows", number_of_full_windows)
        object.__setattr__(self, "full_window_operator", full_window_operator)

    @staticmethod
    def _window(value):
        if value is None or value == -1:
            return None
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError("window sizes must be nonnegative integers, None, or -1")
        return value

    def selections(self, primitive):
        """Return validated ``(component, window_size)`` selections."""

        additions = tuple(
            component for component in primitive.components if isinstance(component, ModularAdd)
        )
        if self.window_size is not None:
            selected = tuple((component, self.window_size) for component in additions)
        elif self.by_round is not None:
            if len(self.by_round) != len(primitive.rounds):
                raise ValueError("per-round windows must match the primitive round count")
            round_numbers = {
                component.component_id: primitive_round.number
                for primitive_round in primitive.rounds
                for component in primitive_round.components
            }
            selected = tuple(
                (component, self.by_round[round_numbers[component.component_id]])
                for component in additions
                if self.by_round[round_numbers[component.component_id]] is not None
            )
        else:
            configured = dict(self.by_component or ())
            if any(component.component_id is None for component in additions):
                raise ValueError("modular-add components must have graph identifiers")
            addition_ids = {str(component.component_id) for component in additions}
            if set(configured) != addition_ids:
                raise ValueError(
                    "per-component windows must name every modular-add component exactly once"
                )
            selected_items = []
            for component in additions:
                window = configured[str(component.component_id)]
                if window is not None:
                    selected_items.append((component, window))
            selected = tuple(selected_items)
        for component, window in selected:
            width = getattr(component.output_type.domain, "width", None)
            if width is None:
                raise NotImplementedError("n-window constraints require Word domains")
            if window > width - 1:
                raise ValueError(
                    f"window for {component.component_id} must not exceed word width - 1"
                )
        if self.number_of_full_windows is not None and any(window == 0 for _, window in selected):
            raise ValueError("full-window counting requires positive window sizes")
        return selected

    def __repr__(self) -> str:
        if self.window_size is not None:
            selection = f"window_size={self.window_size!r}"
        elif self.by_round is not None:
            selection = f"by_round={self.by_round!r}"
        else:
            selection = f"by_component={dict(self.by_component or ())!r}"
        return (
            f"NWindowSATStrategy({selection}, "
            f"number_of_full_windows={self.number_of_full_windows!r}, "
            f"full_window_operator={self.full_window_operator!r})"
        )


def _at_most(variables, bound, allocate, indices, add, prefix):
    if bound < 0:
        impossible = indices[allocate(f"{prefix}_impossible")]
        add((impossible,), "n_window_full_count")
        add((-impossible,), "n_window_full_count")
        return
    if bound >= len(variables):
        return
    if bound == 0:
        for name in variables:
            add((-indices[name],), "n_window_full_count")
        return
    previous = ()
    for position, name in enumerate(variables):
        current = tuple(allocate(f"{prefix}_{position}_{count}") for count in range(1, bound + 1))
        add((-indices[name], indices[current[0]]), "n_window_full_count")
        if previous:
            for count in range(bound):
                add((-indices[previous[count]], indices[current[count]]), "n_window_full_count")
            for count in range(1, bound):
                add(
                    (-indices[name], -indices[previous[count - 1]], indices[current[count]]),
                    "n_window_full_count",
                )
            add((-indices[name], -indices[previous[-1]]), "n_window_full_count")
        previous = current


def _apply_n_window(model, formula, strategy):
    variables = list(formula.variables)
    indices = {name: index for index, name in enumerate(variables, 1)}
    clauses = list(formula.clauses)
    provenance = list(formula.provenance)

    def allocate(name):
        if name not in indices:
            variables.append(name)
            indices[name] = len(variables)
        return name

    def add(literals, label):
        clauses.append(tuple(literals))
        provenance.append(label)

    selections = strategy.selections(model.primitive)
    full_windows: list[str] = []
    for component, window in selections:
        width = component.output_type.domain.width
        operands = model._shared._operands[component.component_id]
        output = model._shared._ports[component.component_id]
        for unit in range(component.output_type.unit_count):
            local_model = ModularAddNWindowSATModel(width, window)
            local = local_model.cnf_formula()
            groups = [operand[unit * width : (unit + 1) * width] for operand in operands]
            groups.append(output[unit * width : (unit + 1) * width])
            mapped = {
                f"{label}_{bit}": name
                for label, names in zip(("left", "right", "output"), groups)
                for bit, name in enumerate(names)
            }
            prefix = f"__n_window_{component.component_id}_{unit}"
            for name in local.variables:
                if name not in mapped:
                    mapped[name] = allocate(f"{prefix}_{name}")
            local_indices = {
                position: indices[mapped[name]] for position, name in enumerate(local.variables, 1)
            }
            for clause, label in zip(local.clauses, local.provenance):
                add(
                    (
                        local_indices[abs(literal)] * (1 if literal > 0 else -1)
                        for literal in clause
                    ),
                    label,
                )
            full_windows.extend(mapped[name] for name in local_model.full_window_names)

    count = strategy.number_of_full_windows
    if count is not None:
        operator = strategy.full_window_operator
        if operator in {"at_most", "exactly"}:
            _at_most(full_windows, count, allocate, indices, add, "__n_window_at_most")
        if operator in {"at_least", "exactly"}:
            complements = []
            for position, name in enumerate(full_windows):
                complement = allocate(f"__n_window_complement_{position}")
                add((indices[name], indices[complement]), "n_window_full_count")
                add((-indices[name], -indices[complement]), "n_window_full_count")
                complements.append(complement)
            _at_most(
                complements,
                len(full_windows) - count,
                allocate,
                indices,
                add,
                "__n_window_at_least",
            )
    applications = formula.constraint_models
    if selections:
        applications += (
            ConstraintModelApplication(
                ModularAddNWindowSATModel.model_provenance,
                tuple(component.component_id for component, _ in selections),
            ),
        )
    model._n_window_selections = selections
    return CNFFormula(tuple(variables), tuple(clauses), tuple(provenance), applications)


def _check_n_window(model, trail):
    if model.n_window is None:
        return True
    values = dict(trail.semantic_assignment)
    full_window_count = 0
    for component, window in model._n_window_selections:
        width = component.output_type.domain.width
        operands = model._shared._operands[component.component_id]
        output = model._shared._ports[component.component_id]
        for unit in range(component.output_type.unit_count):
            carry_differences = tuple(
                values[operands[0][unit * width + bit]]
                ^ values[operands[1][unit * width + bit]]
                ^ values[output[unit * width + bit]]
                for bit in range(width - 1)
            )
            run_length = window + 1
            if any(
                all(carry_differences[start : start + run_length])
                for start in range(len(carry_differences) - run_length + 1)
            ):
                return False
            if window:
                full_window_count += sum(
                    all(carry_differences[start : start + window])
                    for start in range(len(carry_differences) - window + 1)
                )
    expected = model.n_window.number_of_full_windows
    if expected is None:
        return True
    if model.n_window.full_window_operator == "at_least":
        return full_window_count >= expected
    if model.n_window.full_window_operator == "at_most":
        return full_window_count <= expected
    return full_window_count == expected


def _enumeration_metadata(model, formula, solver, extra=()):
    return (
        ("primitive", model.primitive.family_name),
        (
            "realization",
            getattr(getattr(model.primitive, "realization", None), "name", "default"),
        ),
        ("backend", "sat"),
        (
            "formulation",
            "native_xor" if isinstance(formula, NativeXorCNFFormula) else "ordinary_cnf",
        ),
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
    if isinstance(formula, NativeXorCNFFormula):
        from claasp.drivers.solvers.cryptominisat import CryptoMiniSatSolver

        if not isinstance(solver, CryptoMiniSatSolver):
            raise TypeError("native-XOR trail formulas require CryptoMiniSatSolver")
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
            current = replace(
                formula,
                clauses=formula.clauses + tuple(blocks),
                provenance=formula.provenance + ("characteristic_block",) * len(blocks),
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
        n_window=None,
    ) -> None:
        if n_window is not None and not isinstance(n_window, NWindowSATStrategy):
            raise TypeError("n_window must be an NWindowSATStrategy")
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
        self.n_window = n_window
        self._formula: CNFFormula | None = None
        self._n_window_selections = ()

    def cnf_formula(self) -> CNFFormula:
        """Return the complete weighted differential trail formula."""

        formula = self._shared.smt_formula()
        result = _cnf(
            formula,
            _component_applications(
                self.primitive,
                self.model_provenance,
                ((ModularAdd, ModularAddDifferentialSATModel.model_provenance),),
            ),
        )
        if self.n_window is not None:
            result = _apply_n_window(self, result, self.n_window)
        self._formula = result
        return result

    def decode_characteristic(self, assignment):
        """Decode and independently validate a complete SAT assignment."""

        if self._formula is None:
            raise ValueError("build the formula before decoding")
        if not self._formula.is_satisfied(assignment):
            raise ValueError("invalid word differential SAT witness")
        trail = self._shared.decode_characteristic(assignment)
        if not self.check_characteristic(trail):
            raise ValueError("word differential witness violates the n-window strategy")
        return trail

    def check_characteristic(self, trail) -> bool:
        """Recheck component transitions, graph wiring, and requested bounds."""

        return self._shared.check_characteristic(trail) and _check_n_window(self, trail)

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
                ("n_window", repr(self.n_window)),
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


class WordDifferentialNativeXorSATModel(WordDifferentialSATModel):
    """Lower complete differential trails with verified native XOR records.

    Only clause groups that exactly equal a canonical parity relation are
    replaced. Expanding the native records therefore reconstructs the ordinary
    CNF formula exactly, while CryptoMiniSat can consume the compact form.

    EXAMPLES::

        >>> from claasp.primitives import ToySpeck
        >>> model = WordDifferentialNativeXorSATModel(ToySpeck(2), fixed_weight=1)
        >>> formula = model.cnf_formula()
        >>> (formula.native_xor_count > 0, formula.expanded_cnf().clause_count)
        (True, 484)
    """

    model_provenance = _direct_model(
        ConstraintBackend.SAT,
        "WordDifferentialNativeXorSATModel",
        "xor_differential",
        "canonical parity groups as CryptoMiniSat native XOR records",
        "Each replaced parity group is verified against its complete ordinary-CNF expansion.",
    )

    def cnf_formula(self) -> NativeXorCNFFormula:
        """Return the complete trail formula with exact native parity records."""

        formula = _native_xor_formula(super().cnf_formula())
        result = replace(
            formula,
            constraint_models=tuple(
                item for item in formula.constraint_models if item.model != self.model_provenance
            )
            + (
                ConstraintModelApplication(
                    self.model_provenance,
                    tuple(str(component.component_id) for component in self.primitive.components),
                ),
            ),
        )
        self._formula = result
        return result


class WordLinearNativeXorSATModel(WordLinearSATModel):
    """Lower complete linear trails with verified native XOR records.

    EXAMPLES::

        >>> from claasp.primitives import ToySpeck
        >>> model = WordLinearNativeXorSATModel(ToySpeck(3), maximum_weight=1)
        >>> formula = model.cnf_formula()
        >>> (formula.native_xor_count > 0, formula.clause_count < 706)
        (True, True)
    """

    model_provenance = _direct_model(
        ConstraintBackend.SAT,
        "WordLinearNativeXorSATModel",
        "xor_linear",
        "canonical parity groups as CryptoMiniSat native XOR records",
        "Each replaced parity group is verified against its complete ordinary-CNF expansion.",
    )

    def cnf_formula(self) -> NativeXorCNFFormula:
        """Return the complete trail formula with exact native parity records."""

        formula = _native_xor_formula(super().cnf_formula())
        return replace(
            formula,
            constraint_models=tuple(
                item for item in formula.constraint_models if item.model != self.model_provenance
            )
            + (
                ConstraintModelApplication(
                    self.model_provenance,
                    tuple(str(component.component_id) for component in self.primitive.components),
                ),
            ),
        )


__all__ = [
    "NWindowSATStrategy",
    "WordDifferentialNativeXorSATModel",
    "WordDifferentialSATModel",
    "WordLinearNativeXorSATModel",
    "WordLinearSATModel",
]
