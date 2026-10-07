"""Complete SAT assembly for weighted word-graph trail searches."""

from __future__ import annotations

from contextlib import nullcontext
from dataclasses import dataclass, replace
from hashlib import sha256
from itertools import product
from typing import Any

from claasp.components import (
    Add,
    Constant,
    Identity,
    ModularAdd,
    ModularSubtract,
    Permutation,
    Rotate,
    Xor,
)
from claasp.domains import Word
from claasp.drivers.solvers import SatStatus
from claasp.primitives import Speck
from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    ConstraintModelProvenance,
    _direct_model,
    _unaudited_model,
)
from claasp.representations.constraints.sat.components import (
    DifferentialToTruncatedSATModel,
    ImpossibleBoundarySATModel,
    ModularAddDeterministicTruncatedSATModel,
    ModularAddDifferentialSATModel,
    ModularAddLinearSATModel,
    ModularAddNWindowSATModel,
    ModularAddSemiDeterministicTruncatedSATModel,
    ModularSubtractDeterministicTruncatedSATModel,
    ProbabilisticTruncatedModularAddSATModel,
    TruncatedToLinearSATModel,
)
from claasp.representations.constraints.sat.lowering import _native_xor_formula
from claasp.representations.constraints.sat.model import CNFFormula, NativeXorCNFFormula
from claasp.representations.constraints.smt.trails import (
    WordDifferentialEnumeration,
    WordDifferentialSMTModel,
    WordLinearEnumeration,
    WordLinearSMTModel,
)
from claasp.semantics.cryptanalysis import (
    ImpossiblePropagationBoundary,
    ProbabilisticTruncatedTrail,
    TruncatedBit,
    TruncatedXorDifference,
    truncated_modular_add,
    truncated_modular_subtract,
)
from claasp.transformations import invert_primitive, slice_rounds


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


@dataclass(frozen=True, slots=True)
class WordDeterministicTruncatedCharacteristic:
    """One independently checked deterministic-truncated Word-graph witness.

    EXAMPLES::

        >>> zero = TruncatedXorDifference.parse("0")
        >>> characteristic = WordDeterministicTruncatedCharacteristic(
        ...     (("plaintext", zero),), zero, (), ()
        ... )
        >>> str(characteristic.output_pattern)
        '0'
    """

    input_patterns: tuple[tuple[str, TruncatedXorDifference], ...]
    output_pattern: TruncatedXorDifference
    component_patterns: tuple[tuple[str, TruncatedXorDifference], ...]
    semantic_assignment: tuple[tuple[str, int], ...]


@dataclass(frozen=True, slots=True)
class WordDeterministicTruncatedEnumeration:
    """Results and reproducibility metadata from a truncated SAT search.

    EXAMPLES::

        >>> result = WordDeterministicTruncatedEnumeration(
        ...     (), True, 0.01, (("solver", "MinisatSolver"),)
        ... )
        >>> (result.complete, dict(result.metadata)["solver"])
        (True, 'MinisatSolver')
    """

    trails: tuple[WordDeterministicTruncatedCharacteristic, ...]
    complete: bool
    runtime_seconds: float
    metadata: tuple[tuple[str, str], ...]


def _truncated_pattern(bits, assignment):
    return TruncatedXorDifference(
        tuple(
            TruncatedBit.UNKNOWN
            if assignment[unknown]
            else TruncatedBit.ONE
            if assignment[value]
            else TruncatedBit.ZERO
            for unknown, value in bits
        )
    )


class WordDeterministicTruncatedSATModel:
    """Assemble deterministic-truncated ARX Word graphs as ordinary CNF.

    Port trits use a canonical ``(unknown, value)`` representation. Structural
    wiring and XOR are composed directly, while every two-input modular-add
    step reuses :class:`ModularAddDeterministicTruncatedSATModel`. Decoding
    independently propagates the typed three-valued semantics over the graph.

    EXAMPLES::

        >>> from claasp.primitives import ToySpeck
        >>> model = WordDeterministicTruncatedSATModel(
        ...     ToySpeck(2), fixed_input_patterns={"key": "0" * 16},
        ...     nonzero_input="plaintext",
        ... )
        >>> formula = model.cnf_formula()
        >>> (formula.variable_count > 0, "truncated_nonzero_input" in formula.provenance)
        (True, True)
    """

    model_provenance = _direct_model(
        ConstraintBackend.SAT,
        "WordDeterministicTruncatedSATModel",
        "deterministic_truncated_xor",
        "direct ARX word-graph composition with paired-carry modular addition",
        "Graph wiring is direct; modular addition reuses the recovered legacy clauses.",
    )

    def __init__(
        self,
        primitive,
        *,
        fixed_input_patterns=None,
        output_pattern=None,
        nonzero_input=None,
    ) -> None:
        self.primitive = primitive
        if nonzero_input is not None and nonzero_input not in primitive.input_ports:
            raise ValueError("unknown nonzero input")
        self.nonzero_input = nonzero_input
        fixed = dict(fixed_input_patterns or {})
        unknown = set(fixed) - set(primitive.input_ports)
        if unknown:
            raise ValueError(f"unknown fixed input pattern: {sorted(unknown)!r}")
        self.fixed_input_patterns = {
            name: self._coerce(pattern, primitive.input_ports[name].value_type)
            for name, pattern in fixed.items()
        }
        self.output_pattern = (
            None
            if output_pattern is None
            else self._coerce(output_pattern, primitive.output.value_type)
        )
        self._formula: CNFFormula | None = None
        self._ports: dict[str, tuple[tuple[str, str], ...]] = {}
        self._operands: dict[str, tuple[tuple[tuple[str, str], ...], ...]] = {}
        self._output: tuple[tuple[str, str], ...] = ()
        self._semantic_names: tuple[str, ...] = ()

    @staticmethod
    def _coerce(pattern, value_type):
        if not isinstance(value_type.domain, Word):
            raise NotImplementedError("truncated SAT lowering requires Word domains")
        if isinstance(pattern, str):
            pattern = TruncatedXorDifference.parse(pattern)
        if not isinstance(pattern, TruncatedXorDifference):
            raise TypeError("truncated patterns must be strings or TruncatedXorDifference values")
        expected = value_type.unit_count * value_type.domain.width
        if len(pattern.bits) != expected:
            raise ValueError(f"truncated pattern must contain {expected} bits")
        return pattern

    def cnf_formula(self) -> CNFFormula:
        """Return the complete deterministic-truncated graph formula."""

        variables, indices, clauses, provenance = [], {}, [], []

        def allocate(name):
            if name not in indices:
                variables.append(name)
                indices[name] = len(variables)
            return name

        def add(literals, label):
            clauses.append(tuple(literals))
            provenance.append(label)

        def pair(name):
            result = (allocate(name + "_unknown"), allocate(name + "_value"))
            add((-indices[result[0]], -indices[result[1]]), "truncated_canonical_unknown")
            return result

        def equal(left, right, label):
            for source, target in zip(left, right):
                add((-indices[source], indices[target]), label)
                add((indices[source], -indices[target]), label)

        def xor_relation(operands, output, label):
            symbols = ((0, 0), (0, 1), (1, 0))
            for inputs in product(symbols, repeat=len(operands)):
                expected = (1, 0) if (1, 0) in inputs else (0, sum(v for _, v in inputs) % 2)
                for candidate in symbols:
                    if candidate == expected:
                        continue
                    add(
                        (
                            -indices[name] if bit else indices[name]
                            for names_pair, bits_pair in zip(
                                (*operands, output), (*inputs, candidate)
                            )
                            for name, bit in zip(names_pair, bits_pair)
                        ),
                        label,
                    )

        sources = [(name, port.value_type) for name, port in self.primitive.input_ports.items()]
        sources += [(item.component_id, item.output_type) for item in self.primitive.components]
        ports = {}
        for name, value_type in sources:
            if not isinstance(value_type.domain, Word):
                raise NotImplementedError("truncated SAT lowering requires Word domains")
            ports[name] = tuple(
                pair(f"truncated_{name}_{bit}")
                for bit in range(value_type.unit_count * value_type.domain.width)
            )

        def selected(selection):
            return tuple(
                ports[owner_id][bit]
                for owner_id, bit in self.primitive.selection_bit_sources(selection)
            )

        operands_by_id = {}
        for component in self.primitive.components:
            component_id = component.component_id
            operands = tuple(selected(selection) for selection in component.inputs)
            operands_by_id[component_id] = operands
            output = ports[component_id]
            width = component.output_type.domain.width
            if isinstance(component, (ModularAdd, ModularSubtract)):
                for unit in range(component.output_type.unit_count):
                    accumulator = operands[0][unit * width : (unit + 1) * width]
                    for operand_number, operand_group in enumerate(operands[1:], 1):
                        operand = operand_group[unit * width : (unit + 1) * width]
                        last = operand_number == len(operands) - 1
                        target = (
                            output[unit * width : (unit + 1) * width]
                            if last
                            else tuple(
                                pair(f"__truncated_{component_id}_{unit}_{operand_number}_{bit}")
                                for bit in range(width)
                            )
                        )
                        local_type = (
                            ModularAddDeterministicTruncatedSATModel
                            if isinstance(component, ModularAdd)
                            else ModularSubtractDeterministicTruncatedSATModel
                        )
                        local = local_type(width).cnf_formula()
                        mapping = {}
                        for prefix, names in (
                            ("left", accumulator),
                            ("right", operand),
                            ("output", target),
                        ):
                            for bit, names_pair in enumerate(names):
                                for field, name in zip(("unknown", "value"), names_pair):
                                    mapping[f"{prefix}_{bit}_{field}"] = name
                        for name in local.variables:
                            if name not in mapping:
                                mapping[name] = allocate(
                                    f"__truncated_{component_id}_{unit}_{operand_number}_{name}"
                                )
                        remap = {
                            position: indices[mapping[name]]
                            for position, name in enumerate(local.variables, 1)
                        }
                        for clause, label in zip(local.clauses, local.provenance):
                            add(
                                (
                                    remap[abs(literal)] * (1 if literal > 0 else -1)
                                    for literal in clause
                                ),
                                label,
                            )
                        accumulator = target
            elif isinstance(component, (Xor, Add)):
                for bit, target in enumerate(output):
                    xor_relation(
                        tuple(operand[bit] for operand in operands), target, "truncated_xor"
                    )
            elif isinstance(component, Identity):
                for source, target in zip(operands[0], output):
                    equal(source, target, "truncated_identity")
            elif isinstance(component, Permutation):
                units = tuple(
                    operands[0][start : start + width]
                    for start in range(0, len(operands[0]), width)
                )
                for target_unit, source_unit in enumerate(component.mapping):
                    for source, target in zip(
                        units[source_unit], output[target_unit * width : (target_unit + 1) * width]
                    ):
                        equal(source, target, "truncated_permutation")
            elif isinstance(component, Rotate):
                offset = component.amount if component.direction == "right" else -component.amount
                for unit in range(component.output_type.unit_count):
                    source = operands[0][unit * width : (unit + 1) * width]
                    target = output[unit * width : (unit + 1) * width]
                    for bit in range(width):
                        equal(source[bit], target[(bit + offset) % width], "truncated_rotate")
            elif isinstance(component, Constant):
                for unknown_name, value_name in output:
                    add((-indices[unknown_name],), "truncated_zero_constant")
                    add((-indices[value_name],), "truncated_zero_constant")
            else:
                raise NotImplementedError(
                    f"no deterministic-truncated SAT semantics for {type(component).__name__}"
                )

        output = selected(self.primitive.output)
        if self.nonzero_input is not None:
            add(
                (indices[name] for names_pair in ports[self.nonzero_input] for name in names_pair),
                "truncated_nonzero_input",
            )

        def fix(names, pattern, label):
            for names_pair, bit in zip(names, pattern.bits):
                encoded = (1, 0) if bit is TruncatedBit.UNKNOWN else (0, int(bit.value))
                for name, value in zip(names_pair, encoded):
                    add(((indices[name] if value else -indices[name]),), label)

        for name, pattern in self.fixed_input_patterns.items():
            fix(ports[name], pattern, "truncated_fixed_input")
        if self.output_pattern is not None:
            fix(output, self.output_pattern, "truncated_fixed_output")

        self._ports, self._operands, self._output = ports, operands_by_id, output
        self._semantic_names = tuple(
            name for names in ports.values() for names_pair in names for name in names_pair
        )
        self._formula = CNFFormula(
            tuple(variables),
            tuple(clauses),
            tuple(provenance),
            _component_applications(
                self.primitive,
                self.model_provenance,
                (
                    (ModularAdd, ModularAddDeterministicTruncatedSATModel.model_provenance),
                    (
                        ModularSubtract,
                        ModularSubtractDeterministicTruncatedSATModel.model_provenance,
                    ),
                ),
            ),
        )
        return self._formula

    @staticmethod
    def _units(pattern, width):
        return tuple(
            TruncatedXorDifference(pattern.bits[start : start + width])
            for start in range(0, len(pattern.bits), width)
        )

    def _evaluate(self, assignment):
        patterns = {
            name: _truncated_pattern(bits, assignment) for name, bits in self._ports.items()
        }
        for component in self.primitive.components:
            width = component.output_type.domain.width
            operands = tuple(
                _truncated_pattern(names, assignment)
                for names in self._operands[component.component_id]
            )
            operand_units = tuple(self._units(pattern, width) for pattern in operands)
            if isinstance(component, (ModularAdd, ModularSubtract)):
                expected_units = []
                for items in zip(*operand_units):
                    value = items[0]
                    for operand in items[1:]:
                        value = (
                            truncated_modular_add(value, operand)
                            if isinstance(component, ModularAdd)
                            else truncated_modular_subtract(value, operand)
                        )
                    expected_units.append(value)
            elif isinstance(component, (Xor, Add)):
                expected_units = []
                for items in zip(*operand_units):
                    value = items[0]
                    for operand in items[1:]:
                        value = value.xor(operand)
                    expected_units.append(value)
            elif isinstance(component, (Identity, Permutation)):
                items = operand_units[0]
                expected_units = (
                    [items[position] for position in component.mapping]
                    if isinstance(component, Permutation)
                    else list(items)
                )
            elif isinstance(component, Rotate):
                method = "rotate_right" if component.direction == "right" else "rotate_left"
                expected_units = [
                    getattr(item, method)(component.amount) for item in operand_units[0]
                ]
            elif isinstance(component, Constant):
                expected_units = [
                    TruncatedXorDifference.parse("0" * width)
                ] * component.output_type.unit_count
            else:
                return None
            expected = TruncatedXorDifference(
                tuple(bit for unit in expected_units for bit in unit.bits)
            )
            if patterns[component.component_id] != expected:
                return None
        return patterns

    def decode_characteristic(self, assignment):
        """Decode and independently validate a complete SAT assignment."""

        if self._formula is None:
            raise ValueError("build the formula before decoding")
        if not self._formula.is_satisfied(assignment):
            raise ValueError("invalid deterministic-truncated SAT witness")
        patterns = self._evaluate(assignment)
        if patterns is None:
            raise ValueError("truncated witness violates independent graph propagation")
        result = WordDeterministicTruncatedCharacteristic(
            tuple((name, patterns[name]) for name in self.primitive.input_ports),
            _truncated_pattern(self._output, assignment),
            tuple(
                (item.component_id, patterns[item.component_id])
                for item in self.primitive.components
            ),
            tuple((name, int(bool(assignment[name]))) for name in self._semantic_names),
        )
        if not self.check_characteristic(result):
            raise ValueError("truncated witness violates requested boundaries")
        return result

    def check_characteristic(self, trail) -> bool:
        """Recheck graph propagation and requested boundary restrictions."""

        if self._formula is None:
            raise ValueError("build the formula before checking")
        values = dict(trail.semantic_assignment)
        if (
            len(values) != len(trail.semantic_assignment)
            or set(values) != set(self._semantic_names)
            or any(value not in (0, 1) for value in values.values())
        ):
            return False
        patterns = self._evaluate(values)
        if patterns is None:
            return False
        inputs = tuple((name, patterns[name]) for name in self.primitive.input_ports)
        output = _truncated_pattern(self._output, values)
        components = tuple(
            (item.component_id, patterns[item.component_id]) for item in self.primitive.components
        )
        selected_input = None if self.nonzero_input is None else dict(inputs)[self.nonzero_input]
        return (
            trail.input_patterns == inputs
            and trail.output_pattern == output
            and trail.component_patterns == components
            and (self.output_pattern is None or output == self.output_pattern)
            and (
                selected_input is None
                or selected_input != TruncatedXorDifference.parse("0" * len(selected_input.bits))
            )
            and all(
                dict(inputs)[name] == pattern for name, pattern in self.fixed_input_patterns.items()
            )
        )

    def enumerate_trails(self, solver, *, limit=1000):
        """Enumerate distinct port-pattern characteristics."""

        formula = self.cnf_formula()
        metadata = _enumeration_metadata(
            self,
            formula,
            solver,
            (
                (
                    "fixed_input_patterns",
                    repr(
                        tuple(
                            sorted(
                                (name, str(value))
                                for name, value in self.fixed_input_patterns.items()
                            )
                        )
                    ),
                ),
                (
                    "output_pattern",
                    repr(None if self.output_pattern is None else str(self.output_pattern)),
                ),
            ),
        )
        return _enumerate(
            self,
            formula,
            solver,
            WordDeterministicTruncatedEnumeration,
            metadata,
            limit,
        )


class WordDeterministicTruncatedNativeXorSATModel(WordDeterministicTruncatedSATModel):
    """Use native XOR records for exact parity groups in truncated trails.

    The historical CryptoMiniSat wrapper emitted the same clauses as its
    ordinary-SAT parent and warned that no advantage was known. This explicit
    v5 alternative re-encodes only complete canonical parity groups; expanding
    every native record reconstructs the ordinary formula exactly.

    EXAMPLES::

        >>> from claasp.primitives import ToySpeck
        >>> model = WordDeterministicTruncatedNativeXorSATModel(
        ...     ToySpeck(2), fixed_input_patterns={"key": "0" * 16}
        ... )
        >>> formula = model.cnf_formula()
        >>> (formula.native_xor_count, formula.expanded_cnf().clause_count)
        (48, 797)
    """

    model_provenance = _direct_model(
        ConstraintBackend.SAT,
        "WordDeterministicTruncatedNativeXorSATModel",
        "deterministic_truncated_xor",
        "canonical parity groups as CryptoMiniSat native XOR records",
        "Each replaced parity group is verified against its complete ordinary-CNF expansion.",
    )

    def cnf_formula(self) -> NativeXorCNFFormula:
        """Return the complete truncated formula with native parity records."""

        formula = _native_xor_formula(super().cnf_formula())
        self._formula = formula
        return formula


@dataclass(frozen=True, slots=True)
class SpeckImpossibleSATTrail:
    """One independently checked impossible-differential SAT witness.

    EXAMPLES::

        >>> zero = TruncatedXorDifference.parse("00")
        >>> characteristic = WordDeterministicTruncatedCharacteristic((), zero, (), ())
        >>> trail = SpeckImpossibleSATTrail(
        ...     characteristic, characteristic,
        ...     ImpossiblePropagationBoundary(
        ...         TruncatedXorDifference.parse("01"),
        ...         TruncatedXorDifference.parse("00"),
        ...     ),
        ...     (),
        ... )
        >>> trail.boundary.contradictory_positions
        (1,)
    """

    forward: WordDeterministicTruncatedCharacteristic
    backward: WordDeterministicTruncatedCharacteristic
    boundary: ImpossiblePropagationBoundary
    semantic_assignment: tuple[tuple[str, int], ...]


class SpeckImpossibleSATModel:
    """Search a zero-key Speck impossible differential across a round split.

    The prefix propagates a plaintext difference forward. The suffix is sliced
    from the same primitive, inverted, and propagates an output difference
    backward. Their middle-state trits are joined by exact incompatibility
    indicators, at least one of which must identify opposite known bits.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> model = SpeckImpossibleSATModel(Speck(number_of_rounds=3), middle_round=1)
        >>> formula = model.cnf_formula()
        >>> (formula.variable_count > 0, "truncated_incompatibility_exists" in formula.provenance)
        (True, True)
    """

    model_provenance = _direct_model(
        ConstraintBackend.SAT,
        "SpeckImpossibleSATModel",
        "impossible_xor_differential",
        "forward/backward deterministic-truncated graph composition",
        "The whole-graph assembly composes reviewed encodings without a literature claim.",
    )

    def __init__(
        self,
        primitive,
        middle_round: int,
        *,
        input_pattern=None,
        output_pattern=None,
    ) -> None:
        plaintext = primitive.input_ports.get("plaintext")
        if (
            primitive.family_name != "speck"
            or plaintext is None
            or not isinstance(plaintext.value_type.domain, Word)
            or plaintext.value_type.domain.width != 16
        ):
            raise NotImplementedError("the reviewed impossible slice supports Speck32/64")
        if not isinstance(middle_round, int) or isinstance(middle_round, bool):
            raise TypeError("middle_round must be an integer")
        if not 1 <= middle_round < len(primitive.rounds):
            raise ValueError("middle_round must be inside the primitive")
        self.primitive = primitive
        self.middle_round = middle_round
        prefix = slice_rounds(primitive, 0, middle_round - 1).primitive
        suffix = slice_rounds(primitive, middle_round, len(primitive.rounds) - 1).primitive
        inverse = invert_primitive(
            suffix, recover_input="state", retained_inputs=("key",)
        ).primitive
        zero_key = "0" * (
            primitive.input_ports["key"].value_type.unit_count
            * primitive.input_ports["key"].value_type.domain.width
        )
        forward_patterns = {"key": zero_key}
        if input_pattern is not None:
            forward_patterns["plaintext"] = input_pattern
        self.forward_model = WordDeterministicTruncatedSATModel(
            prefix,
            fixed_input_patterns=forward_patterns,
            nonzero_input="plaintext",
        )
        self.backward_model = WordDeterministicTruncatedSATModel(
            inverse,
            fixed_input_patterns={
                "key": zero_key,
                **({"output": output_pattern} if output_pattern is not None else {}),
            },
            nonzero_input="output",
        )
        self._formula: CNFFormula | None = None
        self._forward_map: dict[str, str] = {}
        self._backward_map: dict[str, str] = {}
        self._boundary_map: dict[str, str] = {}

    def cnf_formula(self) -> CNFFormula:
        """Return the composed forward, backward, and contradiction formula."""

        forward = self.forward_model.cnf_formula()
        backward = self.backward_model.cnf_formula()
        variables: list[str] = []
        clauses: list[tuple[int, ...]] = []
        provenance: list[str] = []
        indices: dict[str, int] = {}

        def allocate(name):
            if name not in indices:
                variables.append(name)
                indices[name] = len(variables)
            return name

        def append_formula(formula, prefix):
            mapping = {name: allocate(prefix + name) for name in formula.variables}
            local = {
                position: indices[mapping[name]]
                for position, name in enumerate(formula.variables, 1)
            }
            clauses.extend(
                tuple(local[abs(literal)] * (1 if literal > 0 else -1) for literal in clause)
                for clause in formula.clauses
            )
            provenance.extend(formula.provenance)
            return mapping

        self._forward_map = append_formula(forward, "forward__")
        self._backward_map = append_formula(backward, "backward__")
        boundary_model = ImpossibleBoundarySATModel(len(self.forward_model._output))
        boundary = boundary_model.cnf_formula()
        mapped = {}
        for bit in range(boundary_model.width):
            for field_number, field in enumerate(("unknown", "value")):
                mapped[f"forward_{bit}_{field}"] = self._forward_map[
                    self.forward_model._output[bit][field_number]
                ]
                mapped[f"backward_{bit}_{field}"] = self._backward_map[
                    self.backward_model._output[bit][field_number]
                ]
        for name in boundary.variables:
            mapped.setdefault(name, allocate("boundary__" + name))
        local = {
            position: indices[mapped[name]] for position, name in enumerate(boundary.variables, 1)
        }
        clauses.extend(
            tuple(local[abs(literal)] * (1 if literal > 0 else -1) for literal in clause)
            for clause in boundary.clauses
        )
        provenance.extend(boundary.provenance)
        self._boundary_map = mapped
        self._formula = CNFFormula(
            tuple(variables),
            tuple(clauses),
            tuple(provenance),
            forward.constraint_models
            + backward.constraint_models
            + boundary.constraint_models
            + (ConstraintModelApplication(self.model_provenance),),
        )
        return self._formula

    def decode_trail(self, assignment) -> SpeckImpossibleSATTrail:
        """Decode and independently validate a complete SAT assignment."""

        if self._formula is None:
            raise ValueError("build the formula before decoding")
        if not self._formula.is_satisfied(assignment):
            raise ValueError("invalid impossible-differential SAT witness")
        forward_assignment = {
            name: assignment[mapped] for name, mapped in self._forward_map.items()
        }
        backward_assignment = {
            name: assignment[mapped] for name, mapped in self._backward_map.items()
        }
        boundary_assignment = {
            name: assignment[mapped] for name, mapped in self._boundary_map.items()
        }
        forward = self.forward_model.decode_characteristic(forward_assignment)
        backward = self.backward_model.decode_characteristic(backward_assignment)
        boundary = ImpossibleBoundarySATModel(len(forward.output_pattern.bits)).decode_boundary(
            boundary_assignment
        )
        expected = ImpossiblePropagationBoundary(forward.output_pattern, backward.output_pattern)
        if boundary != expected or not boundary.is_impossible:
            raise ValueError("decoded directional trails do not form an impossible boundary")
        return SpeckImpossibleSATTrail(
            forward,
            backward,
            boundary,
            tuple((name, int(bool(assignment[name]))) for name in self._formula.variables),
        )


@dataclass(frozen=True, slots=True)
class SemiDeterministicModularAddTransition:
    """Decoded transition produced by the recovered window formulation.

    EXAMPLES::

        >>> transition = SemiDeterministicModularAddTransition(
        ...     TruncatedXorDifference.parse("01"),
        ...     TruncatedXorDifference.parse("00"),
        ...     TruncatedXorDifference.parse("01"),
        ...     100,
        ... )
        >>> transition.weight
        1.0
    """

    left: TruncatedXorDifference
    right: TruncatedXorDifference
    output: TruncatedXorDifference
    scaled_weight: int

    @property
    def weight(self) -> float:
        """Return the base-two probability weight."""

        return self.scaled_weight / 100


@dataclass(frozen=True, slots=True)
class SpeckSemiDeterministicTruncatedTrail:
    """A decoded Speck trail using recovered look-ahead-window additions.

    EXAMPLES::

        >>> empty = SpeckSemiDeterministicTruncatedTrail(
        ...     TruncatedXorDifference.parse("00"),
        ...     TruncatedXorDifference.parse("00"),
        ...     (),
        ... )
        >>> (empty.scaled_weight, empty.weight)
        (0, 0.0)
    """

    input_pattern: TruncatedXorDifference
    output_pattern: TruncatedXorDifference
    transitions: tuple[SemiDeterministicModularAddTransition, ...]

    @property
    def scaled_weight(self) -> int:
        """Return the sum of the historical fixed-point transition costs."""

        return sum(transition.scaled_weight for transition in self.transitions)

    @property
    def weight(self) -> float:
        """Return the base-two probability weight."""

        return self.scaled_weight / 100


class SpeckProbabilisticTruncatedSATModel:
    """Compose counter-based probabilistic truncated SAT over Speck32/64.

    Each round reuses :class:`ProbabilisticTruncatedModularAddSATModel`; the
    remaining rotations and XOR are wired directly in canonical ternary form.
    Solver assignments decode to typed transitions whose costs and state
    propagation are independently rechecked.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> model = SpeckProbabilisticTruncatedSATModel(
        ...     Speck(number_of_rounds=2),
        ...     "00000000011111001110000000000000",
        ...     "???????????????1???????????????1",
        ... )
        >>> formula = model.cnf_formula()
        >>> (formula.variable_count > 900, formula.clause_count > 200000)
        (True, True)
    """

    model_provenance = _unaudited_model(
        ConstraintBackend.SAT,
        "SpeckProbabilisticTruncatedSATModel",
        "probabilistic_truncated_xor",
        "counter-based Speck round composition in ordinary CNF",
        "The exact correspondence with a primary-source construction has not been audited.",
    )
    _addition_model_type: type[Any] = ProbabilisticTruncatedModularAddSATModel

    def __init__(
        self, primitive, input_pattern, output_pattern, *, maximum_scaled_weight=None
    ) -> None:
        plaintext = primitive.input_ports.get("plaintext")
        if (
            primitive.family_name != "speck"
            or plaintext is None
            or not isinstance(plaintext.value_type.domain, Word)
            or plaintext.value_type.domain.width != 16
        ):
            raise NotImplementedError("the reviewed probabilistic slice supports Speck32/64")
        self.primitive = primitive
        self.width = 16
        self.input_pattern = None if input_pattern is None else self._coerce(input_pattern)
        self.output_pattern = None if output_pattern is None else self._coerce(output_pattern)
        if maximum_scaled_weight is not None and (
            not isinstance(maximum_scaled_weight, int)
            or isinstance(maximum_scaled_weight, bool)
            or maximum_scaled_weight < 0
        ):
            raise ValueError("maximum_scaled_weight must be a nonnegative integer")
        self.maximum_scaled_weight = maximum_scaled_weight
        self._formula: CNFFormula | None = None
        self._round_models: list[Any] = []
        self._round_maps: list[dict[str, str]] = []
        self._states: tuple[tuple[tuple[tuple[str, str], ...], ...], ...] = ()

    def _coerce(self, pattern):
        if isinstance(pattern, str):
            pattern = TruncatedXorDifference.parse(pattern)
        if not isinstance(pattern, TruncatedXorDifference):
            raise TypeError("boundaries must be strings or TruncatedXorDifference values")
        if len(pattern.bits) != 2 * self.width:
            raise ValueError("Speck32 boundaries must contain 32 bits")
        return pattern

    def cnf_formula(self) -> CNFFormula:
        """Return fixed boundaries and every probabilistic Speck round in CNF."""

        variables: list[str] = []
        indices: dict[str, int] = {}
        clauses: list[tuple[int, ...]] = []
        provenance: list[str] = []

        def allocate(name):
            if name not in indices:
                variables.append(name)
                indices[name] = len(variables)
            return name

        def add(literals, label):
            clauses.append(tuple(literals))
            provenance.append(label)

        states = tuple(
            tuple(
                tuple(
                    (
                        allocate(f"state_{boundary}_{word}_{bit}_unknown"),
                        allocate(f"state_{boundary}_{word}_{bit}_value"),
                    )
                    for bit in range(self.width)
                )
                for word in range(2)
            )
            for boundary in range(len(self.primitive.rounds) + 1)
        )
        for boundary in states:
            for word in boundary:
                for unknown, value in word:
                    add((-indices[unknown], -indices[value]), "truncated_canonical_unknown")

        symbols = ((0, 0), (0, 1), (1, 0))

        def xor_relation(left, right, output):
            for left_value in symbols:
                for right_value in symbols:
                    expected = (
                        (1, 0)
                        if (1, 0) in (left_value, right_value)
                        else (0, left_value[1] ^ right_value[1])
                    )
                    for candidate in symbols:
                        if candidate == expected:
                            continue
                        add(
                            tuple(
                                -indices[name] if bit else indices[name]
                                for pair, encoded in (
                                    (left, left_value),
                                    (right, right_value),
                                    (output, candidate),
                                )
                                for name, bit in zip(pair, encoded)
                            ),
                            "probabilistic_truncated_xor",
                        )

        round_models = []
        round_maps = []
        applications: list[ConstraintModelApplication] = []
        weighted_costs: list[str] = []
        for round_number in range(len(self.primitive.rounds)):
            operations = self.primitive.round_operations[round_number]
            alpha = operations["rotate_right"].amount
            beta = operations["rotate_left"].amount
            local_model = self._addition_model_type(self.width)
            local = local_model.cnf_formula()
            mapping = {}
            for bit in range(self.width):
                for field_number, field in enumerate(("unknown", "value")):
                    mapping[f"left_{bit}_{field}"] = states[round_number][0][
                        (bit - alpha) % self.width
                    ][field_number]
                    mapping[f"right_{bit}_{field}"] = states[round_number][1][bit][field_number]
                    mapping[f"output_{bit}_{field}"] = states[round_number + 1][0][bit][
                        field_number
                    ]
            for name in local.variables:
                mapping.setdefault(name, allocate(f"round_{round_number}__{name}"))
            local_indices = {
                position: indices[mapping[name]] for position, name in enumerate(local.variables, 1)
            }
            for clause, label in zip(local.clauses, local.provenance):
                add(
                    tuple(
                        local_indices[abs(literal)] * (1 if literal > 0 else -1)
                        for literal in clause
                    ),
                    label,
                )
            for bit in range(self.width):
                xor_relation(
                    states[round_number][1][(bit + beta) % self.width],
                    states[round_number + 1][0][bit],
                    states[round_number + 1][1][bit],
                )
            round_models.append(local_model)
            round_maps.append(mapping)
            applications.extend(local.constraint_models)
            weighted_costs.extend(
                self._weighted_cost_names(mapping, round_number, allocate, indices, add)
            )

        def fix(boundary, pattern, label):
            pairs = states[boundary][0] + states[boundary][1]
            for pair, bit in zip(pairs, pattern.bits):
                encoded = (1, 0) if bit is TruncatedBit.UNKNOWN else (0, int(bit.value))
                for name, value in zip(pair, encoded):
                    add(((indices[name] if value else -indices[name]),), label)

        if self.input_pattern is not None:
            fix(0, self.input_pattern, "fixed_probabilistic_input")
        if self.output_pattern is not None:
            fix(-1, self.output_pattern, "fixed_probabilistic_output")
        add(
            (indices[name] for pair in states[0][0] + states[0][1] for name in pair),
            "probabilistic_nonzero_input",
        )
        if self.maximum_scaled_weight is not None:
            _at_most(
                weighted_costs,
                self.maximum_scaled_weight,
                allocate,
                indices,
                add,
                "__probabilistic_weight",
            )
        self._round_models = round_models
        self._round_maps = round_maps
        self._states = states
        self._formula = CNFFormula(
            tuple(variables),
            tuple(clauses),
            tuple(provenance),
            tuple(applications) + (ConstraintModelApplication(self.model_provenance),),
        )
        return self._formula

    def _weighted_cost_names(self, mapping, _round_number, _allocate, _indices, _add):
        return (
            mapping[f"cost_{bit}_{cost}"]
            for bit in range(self.width)
            for cost in (4, 9, 19, 41, 100)
            for _ in range(cost)
        )

    def decode_trail(
        self, assignment
    ) -> ProbabilisticTruncatedTrail | SpeckSemiDeterministicTruncatedTrail:
        """Decode and independently validate every round and state boundary."""

        if self._formula is None:
            raise ValueError("build the formula before decoding")
        if not self._formula.is_satisfied(assignment):
            raise ValueError("invalid probabilistic truncated SAT witness")
        input_pattern = TruncatedXorDifference(
            _truncated_pattern(self._states[0][0], assignment).bits
            + _truncated_pattern(self._states[0][1], assignment).bits
        )
        transitions = []
        for local_model, mapping in zip(self._round_models, self._round_maps):
            local_assignment = {name: assignment[mapped] for name, mapped in mapping.items()}
            transitions.append(local_model.decode_transition(local_assignment))
        for round_number, transition in enumerate(transitions):
            operations = self.primitive.round_operations[round_number]
            expected_left = (
                input_pattern.bits[: self.width]
                if round_number == 0
                else transitions[round_number - 1].output.bits
            )
            if transition.left != TruncatedXorDifference(expected_left).rotate_right(
                operations["rotate_right"].amount
            ):
                raise ValueError("probabilistic trail violates the Speck left rotation")
            right = _truncated_pattern(self._states[round_number][1], assignment)
            next_right = right.rotate_left(operations["rotate_left"].amount).xor(transition.output)
            if next_right != _truncated_pattern(self._states[round_number + 1][1], assignment):
                raise ValueError("probabilistic trail violates the Speck XOR wiring")
        output = TruncatedXorDifference(
            _truncated_pattern(self._states[-1][0], assignment).bits
            + _truncated_pattern(self._states[-1][1], assignment).bits
        )
        trail = ProbabilisticTruncatedTrail(input_pattern, output, tuple(transitions))
        if self.input_pattern is not None and trail.input_pattern != self.input_pattern:
            raise ValueError("decoded probabilistic trail changed its input boundary")
        if self.output_pattern is not None and trail.output_pattern != self.output_pattern:
            raise ValueError("decoded probabilistic trail changed its output boundary")
        return trail


class SpeckSemiDeterministicTruncatedSATModel(SpeckProbabilisticTruncatedSATModel):
    """Compose recovered look-ahead-window additions over Speck32/64.

    This formulation keeps the same graph wiring, boundaries, and scaled-weight
    interface as :class:`SpeckProbabilisticTruncatedSATModel`, making the two
    encodings directly comparable without changing the selected SAT solver.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> model = SpeckSemiDeterministicTruncatedSATModel(
        ...     Speck(number_of_rounds=2),
        ...     "00000000011111001110000000000000",
        ...     "???????????????1???????????????1",
        ...     maximum_scaled_weight=100,
        ... )
        >>> formula = model.cnf_formula()
        >>> formula.clause_count < 1200000
        True
    """

    model_provenance = _unaudited_model(
        ConstraintBackend.SAT,
        "SpeckSemiDeterministicTruncatedSATModel",
        "semi_deterministic_truncated_xor",
        "recovered look-ahead-window Speck round composition in ordinary CNF",
        "The exact correspondence with a primary-source construction has not been audited.",
    )
    _addition_model_type = ModularAddSemiDeterministicTruncatedSATModel

    def _weighted_cost_names(self, mapping, round_number, allocate, indices, add):
        weighted: list[str] = []
        weights = (0, 4, 9, 19, 41, 100)
        for bit in range(self.width):
            selectors = []
            for code, weight in enumerate(weights):
                selector = allocate(f"round_{round_number}__weight_{bit}_{weight}")
                selectors.append(selector)
                desired = tuple(
                    indices[mapping[f"weight_{field}_{bit}"]] * (1 if code & mask else -1)
                    for field, mask in (("p", 4), ("q", 2), ("r", 1))
                )
                for literal in desired:
                    add((-indices[selector], literal), "semi_deterministic_weight_selector")
                add(
                    (indices[selector], *(-literal for literal in desired)),
                    "semi_deterministic_weight_selector",
                )
                weighted.extend(selector for _ in range(weight))
            add(
                (indices[selector] for selector in selectors),
                "semi_deterministic_weight_code",
            )
        return weighted

    def decode_trail(self, assignment) -> SpeckSemiDeterministicTruncatedTrail:
        """Decode and independently validate recovered round transitions."""

        if self._formula is None:
            raise ValueError("build the formula before decoding")
        if not self._formula.is_satisfied(assignment):
            raise ValueError("invalid semi-deterministic truncated SAT witness")
        input_pattern = TruncatedXorDifference(
            _truncated_pattern(self._states[0][0], assignment).bits
            + _truncated_pattern(self._states[0][1], assignment).bits
        )
        transitions = []
        for local_model, mapping in zip(self._round_models, self._round_maps):
            local_assignment = {name: assignment[mapped] for name, mapped in mapping.items()}
            left, right, output, scaled_weight = local_model.decode_transition(local_assignment)
            transitions.append(
                SemiDeterministicModularAddTransition(left, right, output, scaled_weight)
            )
        for round_number, transition in enumerate(transitions):
            operations = self.primitive.round_operations[round_number]
            expected_left = (
                input_pattern.bits[: self.width]
                if round_number == 0
                else transitions[round_number - 1].output.bits
            )
            if transition.left != TruncatedXorDifference(expected_left).rotate_right(
                operations["rotate_right"].amount
            ):
                raise ValueError("semi-deterministic trail violates the Speck left rotation")
            right = _truncated_pattern(self._states[round_number][1], assignment)
            next_right = right.rotate_left(operations["rotate_left"].amount).xor(transition.output)
            if next_right != _truncated_pattern(self._states[round_number + 1][1], assignment):
                raise ValueError("semi-deterministic trail violates the Speck XOR wiring")
        output = TruncatedXorDifference(
            _truncated_pattern(self._states[-1][0], assignment).bits
            + _truncated_pattern(self._states[-1][1], assignment).bits
        )
        trail = SpeckSemiDeterministicTruncatedTrail(input_pattern, output, tuple(transitions))
        if self.input_pattern is not None and trail.input_pattern != self.input_pattern:
            raise ValueError("decoded semi-deterministic trail changed its input boundary")
        if self.output_pattern is not None and trail.output_pattern != self.output_pattern:
            raise ValueError("decoded semi-deterministic trail changed its output boundary")
        return trail


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


@dataclass(frozen=True, slots=True)
class SharedDifferencePairedSATTrail:
    """Two characteristics sharing one input difference.

    Corresponding modular-add output differences are mutually exclusive, as
    in the recovered legacy high-order characteristic search.

    EXAMPLES::

        >>> from types import SimpleNamespace
        >>> trail = SharedDifferencePairedSATTrail(
        ...     SimpleNamespace(total_weight=2), SimpleNamespace(total_weight=3)
        ... )
        >>> trail.total_weight
        5
    """

    left: Any
    right: Any

    @property
    def total_weight(self):
        """Return the sum of both component-characteristic weights."""

        return self.left.total_weight + self.right.total_weight


class SharedDifferencePairedWordDifferentialSATModel:
    """Recover the legacy shared-difference paired characteristic search.

    This is deliberately not the exact four-evaluation paired graph. It
    composes two XOR-differential characteristics with identical external
    input differences and forbids corresponding modular-add output bits from
    being active in both copies.

    EXAMPLES::

        >>> from claasp.primitives import ToySpeck
        >>> model = SharedDifferencePairedWordDifferentialSATModel(
        ...     ToySpeck(2), maximum_total_weight=2,
        ...     fixed_input_differences={"key": 0}, nonzero_input="plaintext",
        ... )
        >>> formula = model.cnf_formula()
        >>> (formula.variable_count > 0, "paired_modadd_output_exclusion" in formula.provenance)
        (True, True)
    """

    model_provenance = _unaudited_model(
        ConstraintBackend.SAT,
        "SharedDifferencePairedWordDifferentialSATModel",
        "shared_difference_paired_input_differential",
        "two shared-input-difference characteristics with modular-add output exclusion",
        "Recovered from legacy CLAASP; its precise high-order interpretation remains unaudited.",
    )

    def __init__(
        self,
        primitive,
        *,
        maximum_total_weight=None,
        fixed_total_weight=None,
        nonzero_input=None,
        fixed_input_differences=None,
        left_output_difference=None,
        right_output_difference=None,
    ) -> None:
        if maximum_total_weight is not None and fixed_total_weight is not None:
            raise ValueError("choose maximum_total_weight or fixed_total_weight, not both")
        for weight in (maximum_total_weight, fixed_total_weight):
            if weight is not None and (
                not isinstance(weight, int) or isinstance(weight, bool) or weight < 0
            ):
                raise ValueError("total weights must be nonnegative integers")
        options = {
            "nonzero_input": nonzero_input,
            "fixed_input_differences": fixed_input_differences,
        }
        self.left_model = WordDifferentialSATModel(
            primitive, output_difference=left_output_difference, **options
        )
        self.right_model = WordDifferentialSATModel(
            primitive, output_difference=right_output_difference, **options
        )
        self.primitive = primitive
        self.maximum_total_weight = maximum_total_weight
        self.fixed_total_weight = fixed_total_weight
        self._formula: CNFFormula | None = None
        self._maps: dict[str, dict[str, str]] = {}

    def cnf_formula(self) -> CNFFormula:
        """Return the paired characteristic formula."""

        subformulas = (
            ("left", self.left_model.cnf_formula()),
            ("right", self.right_model.cnf_formula()),
        )
        variables: list[str] = []
        indices: dict[str, int] = {}
        clauses: list[tuple[int, ...]] = []
        provenance: list[str] = []
        applications: list[ConstraintModelApplication] = []
        maps: dict[str, dict[str, str]] = {}

        def allocate(name):
            if name not in indices:
                variables.append(name)
                indices[name] = len(variables)
            return name

        def add(literals, label):
            clauses.append(tuple(literals))
            provenance.append(label)

        for namespace, formula in subformulas:
            mapping = {name: allocate(f"{namespace}_{name}") for name in formula.variables}
            remap = {
                position: indices[mapping[name]]
                for position, name in enumerate(formula.variables, 1)
            }
            for clause, label in zip(formula.clauses, formula.provenance):
                add(
                    (remap[abs(literal)] * (1 if literal > 0 else -1) for literal in clause),
                    label,
                )
            applications.extend(formula.constraint_models)
            maps[namespace] = mapping

        for input_name in self.primitive.input_ports:
            left = self.left_model._shared._ports[input_name]
            right = self.right_model._shared._ports[input_name]
            for left_name, right_name in zip(left, right):
                left_index = indices[maps["left"][left_name]]
                right_index = indices[maps["right"][right_name]]
                add((-left_index, right_index), "paired_shared_input_difference")
                add((left_index, -right_index), "paired_shared_input_difference")

        additions = tuple(
            component
            for component in self.primitive.components
            if isinstance(component, ModularAdd)
        )
        for component in additions:
            left = self.left_model._shared._ports[component.component_id]
            right = self.right_model._shared._ports[component.component_id]
            for left_name, right_name in zip(left, right):
                add(
                    (
                        -indices[maps["left"][left_name]],
                        -indices[maps["right"][right_name]],
                    ),
                    "paired_modadd_output_exclusion",
                )

        weights = [
            maps[namespace][name]
            for namespace, formula in subformulas
            for name in formula.variables
            if name.startswith("weight_")
        ]
        bound = (
            self.fixed_total_weight
            if self.fixed_total_weight is not None
            else self.maximum_total_weight
        )
        if bound is not None:
            _at_most(weights, bound, allocate, indices, add, "__paired_weight")
        if self.fixed_total_weight is not None:
            if self.fixed_total_weight > len(weights):
                impossible = allocate("__paired_impossible_weight")
                add((indices[impossible],), "paired_fixed_weight")
                add((-indices[impossible],), "paired_fixed_weight")
            else:
                complements = []
                for position, name in enumerate(weights):
                    complement = allocate(f"__paired_weight_complement_{position}")
                    add((indices[name], indices[complement]), "paired_fixed_weight")
                    add((-indices[name], -indices[complement]), "paired_fixed_weight")
                    complements.append(complement)
                _at_most(
                    complements,
                    len(weights) - self.fixed_total_weight,
                    allocate,
                    indices,
                    add,
                    "__paired_lower_weight",
                )

        applications.append(
            ConstraintModelApplication(
                self.model_provenance,
                tuple(str(component.component_id) for component in additions),
            )
        )
        self._maps = maps
        self._formula = CNFFormula(
            tuple(variables), tuple(clauses), tuple(provenance), tuple(applications)
        )
        return self._formula

    def decode_trail(self, assignment) -> SharedDifferencePairedSATTrail:
        """Decode both characteristics and recheck the paired restrictions."""

        if self._formula is None:
            raise ValueError("build the formula before decoding")
        if not self._formula.is_satisfied(assignment):
            raise ValueError("invalid shared-difference paired SAT witness")

        def project(namespace):
            return {
                local: assignment[global_name]
                for local, global_name in self._maps[namespace].items()
            }

        left_assignment, right_assignment = project("left"), project("right")
        left = self.left_model.decode_characteristic(left_assignment)
        right = self.right_model.decode_characteristic(right_assignment)
        if left.input_differences != right.input_differences:
            raise ValueError("paired characteristics do not share their input difference")
        for component in self.primitive.components:
            if not isinstance(component, ModularAdd):
                continue
            left_names = self.left_model._shared._ports[component.component_id]
            right_names = self.right_model._shared._ports[component.component_id]
            if any(
                left_assignment[a] and right_assignment[b] for a, b in zip(left_names, right_names)
            ):
                raise ValueError("paired modular-add output differences overlap")
        trail = SharedDifferencePairedSATTrail(left, right)
        bound = self.fixed_total_weight
        if bound is not None and trail.total_weight != bound:
            raise ValueError("paired trail changed its fixed total weight")
        if self.maximum_total_weight is not None and trail.total_weight > self.maximum_total_weight:
            raise ValueError("paired trail exceeds its total-weight bound")
        return trail


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


@dataclass(frozen=True, slots=True)
class SharedDifferencePairedDifferentialLinearSATTrail:
    """Two shared-input differential prefixes joined to one linear suffix.

    The objective is both differential weights plus twice the linear weight.

    EXAMPLES::

        >>> from types import SimpleNamespace
        >>> trail = SharedDifferencePairedDifferentialLinearSATTrail(
        ...     SimpleNamespace(total_weight=5), SimpleNamespace(total_weight=3)
        ... )
        >>> trail.total_weight
        11
    """

    paired_differential: SharedDifferencePairedSATTrail
    linear: Any

    @property
    def total_weight(self):
        """Return both differential weights plus twice the linear weight."""

        return self.paired_differential.total_weight + 2 * self.linear.total_weight


class SharedDifferencePairedWordDifferentialLinearSATModel:
    """Recover the legacy paired-input differential-linear SAT composition.

    Two exact differential characteristics share an external input difference
    and obey the recovered modular-add output exclusions. A mask entering the
    suffix may be active only where both prefix output differences are zero.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> model = SharedDifferencePairedWordDifferentialLinearSATModel(
        ...     Speck(number_of_rounds=3), prefix_rounds=2,
        ...     paired_differential_maximum_weight=16,
        ...     linear_maximum_weight=16,
        ... )
        >>> formula = model.cnf_formula()
        >>> (formula.variable_count > 0, formula.provenance.count("paired_differential_linear_boundary"))
        (True, 64)
    """

    model_provenance = _unaudited_model(
        ConstraintBackend.SAT,
        "SharedDifferencePairedWordDifferentialLinearSATModel",
        "shared_difference_paired_input_differential_linear",
        "two shared-input differential prefixes joined to one linear suffix",
        "Recovered from legacy CLAASP; its high-order interpretation and boundary provenance remain unaudited.",
    )

    def __init__(
        self,
        primitive,
        *,
        prefix_rounds: int,
        paired_differential_maximum_weight: int,
        linear_maximum_weight: int,
        maximum_total_weight: int | None = None,
        fixed_total_weight: int | None = None,
        input_difference: int | None = None,
        output_mask: int | None = None,
    ) -> None:
        if not isinstance(prefix_rounds, int) or isinstance(prefix_rounds, bool):
            raise ValueError("prefix_rounds must be an integer")
        if not 0 < prefix_rounds < len(primitive.rounds):
            raise ValueError("the differential prefix and linear suffix must both be nonempty")
        if maximum_total_weight is not None and fixed_total_weight is not None:
            raise ValueError("choose maximum_total_weight or fixed_total_weight, not both")
        for weight in (
            paired_differential_maximum_weight,
            linear_maximum_weight,
            maximum_total_weight,
            fixed_total_weight,
        ):
            if weight is not None and (
                not isinstance(weight, int) or isinstance(weight, bool) or weight < 0
            ):
                raise ValueError("weight bounds must be nonnegative integers")
        block_width = sum(
            port.value_type.unit_count * port.value_type.domain.width
            for name, port in primitive.input_ports.items()
            if name == "plaintext"
        )
        if not block_width:
            raise NotImplementedError("paired differential-linear SAT assembly requires plaintext")
        for value, label in ((input_difference, "input difference"), (output_mask, "output mask")):
            if value is not None and (
                not isinstance(value, int)
                or isinstance(value, bool)
                or not 0 <= value < 1 << block_width
            ):
                raise ValueError(f"{label} must fit the primitive block width")
        self.primitive = primitive
        self.prefix_rounds = prefix_rounds
        self.paired_differential_maximum_weight = paired_differential_maximum_weight
        self.linear_maximum_weight = linear_maximum_weight
        self.maximum_total_weight = maximum_total_weight
        self.fixed_total_weight = fixed_total_weight
        self.input_difference = input_difference
        self.output_mask = output_mask
        self._formula: CNFFormula | None = None
        self._maps: dict[str, dict[str, str]] = {}

    def cnf_formula(self) -> CNFFormula:
        """Return the complete paired differential-linear formula."""

        prefix = slice_rounds(self.primitive, 0, self.prefix_rounds - 1).primitive
        suffix = slice_rounds(
            self.primitive, self.prefix_rounds, len(self.primitive.rounds) - 1
        ).primitive
        fixed_differences = {"key": 0} if "key" in prefix.input_ports else {}
        if self.input_difference is not None:
            fixed_differences["plaintext"] = self.input_difference
        self._paired = SharedDifferencePairedWordDifferentialSATModel(
            prefix,
            maximum_total_weight=self.paired_differential_maximum_weight,
            nonzero_input="plaintext" if self.input_difference is None else None,
            fixed_input_differences=fixed_differences,
        )
        fixed_masks = {name: 0 for name in suffix.input_ports if name != "state"}
        self._linear = WordLinearSATModel(
            suffix,
            maximum_weight=self.linear_maximum_weight,
            fixed_input_masks=fixed_masks,
        )
        paired_formula = self._paired.cnf_formula()
        linear_formula = self._linear.cnf_formula()
        subformulas = (("paired", paired_formula), ("linear", linear_formula))
        variables: list[str] = []
        indices: dict[str, int] = {}
        clauses: list[tuple[int, ...]] = []
        provenance: list[str] = []
        applications: list[ConstraintModelApplication] = []
        maps: dict[str, dict[str, str]] = {}

        def allocate(name):
            if name not in indices:
                variables.append(name)
                indices[name] = len(variables)
            return name

        def add(literals, label):
            clauses.append(tuple(literals))
            provenance.append(label)

        for namespace, formula in subformulas:
            mapping = {name: allocate(f"{namespace}_{name}") for name in formula.variables}
            remap = {
                position: indices[mapping[name]]
                for position, name in enumerate(formula.variables, 1)
            }
            for clause, label in zip(formula.clauses, formula.provenance):
                add(
                    (remap[abs(literal)] * (1 if literal > 0 else -1) for literal in clause),
                    label,
                )
            applications.extend(formula.constraint_models)
            maps[namespace] = mapping

        linear_input = self._linear._shared._ports["state"]
        for side, model in (("left", self._paired.left_model), ("right", self._paired.right_model)):
            paired_output = model._shared._output
            if len(paired_output) != len(linear_input):
                raise ValueError("paired differential-linear boundary widths disagree")
            for difference, mask in zip(paired_output, linear_input):
                add(
                    (
                        -indices[maps["paired"][self._paired._maps[side][difference]]],
                        -indices[maps["linear"][mask]],
                    ),
                    "paired_differential_linear_boundary",
                )

        linear_output = tuple(maps["linear"][name] for name in self._linear._shared._output)
        if self.output_mask is None:
            add(
                (indices[name] for name in linear_output),
                "nonzero_paired_differential_linear_output_mask",
            )
        else:
            for bit, name in enumerate(linear_output):
                value = self.output_mask & (1 << (len(linear_output) - 1 - bit))
                add(
                    ((indices[name] if value else -indices[name]),),
                    "fixed_paired_differential_linear_output_mask",
                )

        differential_weights = [
            maps["paired"][name]
            for name in paired_formula.variables
            if name.startswith(("left_weight_", "right_weight_"))
        ]
        linear_weights = [
            maps["linear"][name] for name in linear_formula.variables if name.startswith("weight_")
        ]
        objective_weights = differential_weights + linear_weights + linear_weights
        bound = (
            self.fixed_total_weight
            if self.fixed_total_weight is not None
            else self.maximum_total_weight
        )
        if bound is not None:
            _at_most(objective_weights, bound, allocate, indices, add, "__paired_dl_weight")
        if self.fixed_total_weight is not None:
            if self.fixed_total_weight > len(objective_weights):
                impossible = allocate("__paired_dl_impossible_weight")
                add((indices[impossible],), "paired_dl_fixed_weight")
                add((-indices[impossible],), "paired_dl_fixed_weight")
            else:
                complements = []
                for position, name in enumerate(objective_weights):
                    complement = allocate(f"__paired_dl_weight_complement_{position}")
                    add((indices[name], indices[complement]), "paired_dl_fixed_weight")
                    add((-indices[name], -indices[complement]), "paired_dl_fixed_weight")
                    complements.append(complement)
                _at_most(
                    complements,
                    len(objective_weights) - self.fixed_total_weight,
                    allocate,
                    indices,
                    add,
                    "__paired_dl_lower_weight",
                )

        applications.append(ConstraintModelApplication(self.model_provenance))
        self._maps = maps
        self._formula = CNFFormula(
            tuple(variables), tuple(clauses), tuple(provenance), tuple(applications)
        )
        return self._formula

    def decode_trail(self, assignment) -> SharedDifferencePairedDifferentialLinearSATTrail:
        """Decode and independently check the paired prefix and shared boundary."""

        if self._formula is None:
            raise ValueError("build the formula before decoding")
        if not self._formula.is_satisfied(assignment):
            raise ValueError("invalid paired differential-linear SAT witness")
        paired_assignment = {
            local: assignment[global_name] for local, global_name in self._maps["paired"].items()
        }
        linear_assignment = {
            local: assignment[global_name] for local, global_name in self._maps["linear"].items()
        }
        paired = self._paired.decode_trail(paired_assignment)
        linear = self._linear.decode_characteristic(linear_assignment)
        state_mask = dict(linear.input_masks)["state"]
        width = len(self._linear._shared._ports["state"])
        mask_bits = tuple((state_mask >> (width - bit - 1)) & 1 for bit in range(width))
        for difference in (paired.left.output_difference, paired.right.output_difference):
            difference_bits = tuple((difference >> (width - bit - 1)) & 1 for bit in range(width))
            if any(mask and active for mask, active in zip(mask_bits, difference_bits)):
                raise ValueError("paired differential-linear boundary is incompatible")
        trail = SharedDifferencePairedDifferentialLinearSATTrail(paired, linear)
        if self.fixed_total_weight is not None and trail.total_weight != self.fixed_total_weight:
            raise ValueError("paired differential-linear trail changed its fixed weight")
        if self.maximum_total_weight is not None and trail.total_weight > self.maximum_total_weight:
            raise ValueError("paired differential-linear trail exceeds its total-weight bound")
        return trail


@dataclass(frozen=True, slots=True)
class WordSemiDeterministicDifferentialLinearSATTrail:
    """An exact differential, semi-deterministic middle, and linear suffix.

    EXAMPLES::

        >>> from types import SimpleNamespace
        >>> trail = WordSemiDeterministicDifferentialLinearSATTrail(
        ...     SimpleNamespace(total_weight=2),
        ...     SimpleNamespace(weight=0.41),
        ...     SimpleNamespace(total_weight=3),
        ... )
        >>> (trail.legacy_objective_weight, trail.middle_weight)
        (8, 0.41)
    """

    differential: Any
    middle: SpeckSemiDeterministicTruncatedTrail
    linear: Any

    @property
    def legacy_objective_weight(self):
        """Return the historical differential-plus-twice-linear objective."""

        return self.differential.total_weight + 2 * self.linear.total_weight

    @property
    def middle_weight(self):
        """Return the recovered semi-deterministic middle estimate separately."""

        return self.middle.weight


class WordSemiDeterministicDifferentialLinearSATModel:
    """Compose exact, semi-deterministic, and linear Speck SAT searches.

    The middle uses the recovered look-ahead-window modular-add encoding. Its
    estimated weight is reported separately because the legacy objective did
    not consistently account for that fixed-point quantity.

    EXAMPLES::

        >>> model = WordSemiDeterministicDifferentialLinearSATModel(
        ...     Speck(number_of_rounds=3), prefix_rounds=1, middle_rounds=1,
        ...     differential_maximum_weight=16,
        ...     middle_maximum_scaled_weight=100,
        ...     linear_maximum_weight=16,
        ... )
        >>> formula = model.cnf_formula()
        >>> (formula.variable_count > 0, "differential_to_truncated_exact" in formula.provenance)
        (True, True)
    """

    model_provenance = _unaudited_model(
        ConstraintBackend.SAT,
        "WordSemiDeterministicDifferentialLinearSATModel",
        "differential_linear",
        "round-sliced differential, semi-deterministic-truncated, and linear composition",
        "Recovered from legacy CLAASP; the middle probability and exact literature correspondence remain unaudited.",
    )

    def __init__(
        self,
        primitive,
        *,
        prefix_rounds: int,
        middle_rounds: int,
        differential_maximum_weight: int,
        middle_maximum_scaled_weight: int | None,
        linear_maximum_weight: int,
        input_difference: int | None = None,
        output_mask: int | None = None,
    ) -> None:
        if primitive.family_name != "speck":
            raise NotImplementedError("the reviewed semi-deterministic composition supports Speck")
        counts = (prefix_rounds, middle_rounds)
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value <= 0 for value in counts
        ):
            raise ValueError("prefix_rounds and middle_rounds must be positive integers")
        if prefix_rounds + middle_rounds >= len(primitive.rounds):
            raise ValueError("the differential, middle, and linear slices must all be nonempty")
        for weight in (
            differential_maximum_weight,
            middle_maximum_scaled_weight,
            linear_maximum_weight,
        ):
            if weight is not None and (
                not isinstance(weight, int) or isinstance(weight, bool) or weight < 0
            ):
                raise ValueError("weight bounds must be nonnegative integers")
        block_width = (
            primitive.input_ports["plaintext"].value_type.unit_count
            * primitive.input_ports["plaintext"].value_type.domain.width
        )
        for value, label in ((input_difference, "input difference"), (output_mask, "output mask")):
            if value is not None and (
                not isinstance(value, int)
                or isinstance(value, bool)
                or not 0 <= value < 1 << block_width
            ):
                raise ValueError(f"{label} must fit the primitive block width")
        self.primitive = primitive
        self.prefix_rounds = prefix_rounds
        self.middle_rounds = middle_rounds
        self.differential_maximum_weight = differential_maximum_weight
        self.middle_maximum_scaled_weight = middle_maximum_scaled_weight
        self.linear_maximum_weight = linear_maximum_weight
        self.input_difference = input_difference
        self.output_mask = output_mask
        self._formula: CNFFormula | None = None
        self._maps: dict[str, dict[str, str]] = {}

    def cnf_formula(self) -> CNFFormula:
        """Return the complete semi-deterministic differential-linear formula."""

        prefix_end = self.prefix_rounds - 1
        middle_end = prefix_end + self.middle_rounds
        prefix = slice_rounds(self.primitive, 0, prefix_end).primitive
        suffix = slice_rounds(
            self.primitive, middle_end + 1, len(self.primitive.rounds) - 1
        ).primitive
        fixed_differences = {"key": 0} if "key" in prefix.input_ports else {}
        if self.input_difference is not None:
            fixed_differences["plaintext"] = self.input_difference
        self._prefix = WordDifferentialSATModel(
            prefix,
            maximum_weight=self.differential_maximum_weight,
            nonzero_input="plaintext" if self.input_difference is None else None,
            fixed_input_differences=fixed_differences,
        )
        self._middle = SpeckSemiDeterministicTruncatedSATModel(
            Speck(number_of_rounds=self.middle_rounds),
            None,
            None,
            maximum_scaled_weight=self.middle_maximum_scaled_weight,
        )
        fixed_masks = {name: 0 for name in suffix.input_ports if name != "state"}
        self._linear = WordLinearSATModel(
            suffix,
            maximum_weight=self.linear_maximum_weight,
            fixed_input_masks=fixed_masks,
        )
        subformulas = (
            ("differential", self._prefix.cnf_formula()),
            ("middle", self._middle.cnf_formula()),
            ("linear", self._linear.cnf_formula()),
        )
        variables: list[str] = []
        indices: dict[str, int] = {}
        clauses: list[tuple[int, ...]] = []
        provenance: list[str] = []
        applications: list[ConstraintModelApplication] = []
        maps: dict[str, dict[str, str]] = {}

        def allocate(name):
            if name not in indices:
                variables.append(name)
                indices[name] = len(variables)
            return name

        def add(literals, label):
            clauses.append(tuple(literals))
            provenance.append(label)

        for namespace, formula in subformulas:
            mapping = {name: allocate(f"{namespace}_{name}") for name in formula.variables}
            remap = {
                position: indices[mapping[name]]
                for position, name in enumerate(formula.variables, 1)
            }
            for clause, label in zip(formula.clauses, formula.provenance):
                add(
                    (remap[abs(literal)] * (1 if literal > 0 else -1) for literal in clause),
                    label,
                )
            applications.extend(formula.constraint_models)
            maps[namespace] = mapping

        middle_input = self._middle._states[0][0] + self._middle._states[0][1]
        prefix_output = self._prefix._shared._output
        if len(prefix_output) != len(middle_input):
            raise ValueError("upper semi-deterministic boundary widths disagree")
        upper = DifferentialToTruncatedSATModel(len(prefix_output)).cnf_formula()
        upper_mapping = {
            **{
                f"difference_{bit}": maps["differential"][name]
                for bit, name in enumerate(prefix_output)
            },
            **{
                f"truncated_{bit}_{field}": maps["middle"][pair[position]]
                for bit, pair in enumerate(middle_input)
                for position, field in enumerate(("unknown", "value"))
            },
        }
        self._append_connector(upper, upper_mapping, indices, add, applications)

        middle_output = self._middle._states[-1][0] + self._middle._states[-1][1]
        linear_input = self._linear._shared._ports["state"]
        if len(middle_output) != len(linear_input):
            raise ValueError("lower semi-deterministic boundary widths disagree")
        lower = TruncatedToLinearSATModel(len(linear_input)).cnf_formula()
        lower_mapping = {
            **{
                f"truncated_{bit}_{field}": maps["middle"][pair[position]]
                for bit, pair in enumerate(middle_output)
                for position, field in enumerate(("unknown", "value"))
            },
            **{f"mask_{bit}": maps["linear"][name] for bit, name in enumerate(linear_input)},
        }
        self._append_connector(lower, lower_mapping, indices, add, applications)

        linear_output = tuple(maps["linear"][name] for name in self._linear._shared._output)
        if self.output_mask is None:
            add(
                (indices[name] for name in linear_output),
                "nonzero_semi_differential_linear_output_mask",
            )
        else:
            for bit, name in enumerate(linear_output):
                value = self.output_mask & (1 << (len(linear_output) - 1 - bit))
                add(
                    ((indices[name] if value else -indices[name]),),
                    "fixed_semi_differential_linear_output_mask",
                )

        applications.append(ConstraintModelApplication(self.model_provenance))
        self._maps = maps
        self._formula = CNFFormula(
            tuple(variables), tuple(clauses), tuple(provenance), tuple(applications)
        )
        return self._formula

    @staticmethod
    def _append_connector(formula, mapping, indices, add, applications):
        remap = {
            position: indices[mapping[name]] for position, name in enumerate(formula.variables, 1)
        }
        for clause, label in zip(formula.clauses, formula.provenance):
            add(
                (remap[abs(literal)] * (1 if literal > 0 else -1) for literal in clause),
                label,
            )
        applications.extend(formula.constraint_models)

    def decode_trail(self, assignment) -> WordSemiDeterministicDifferentialLinearSATTrail:
        """Decode all sections and independently check both connectors."""

        if self._formula is None:
            raise ValueError("build the formula before decoding")
        if not self._formula.is_satisfied(assignment):
            raise ValueError("invalid semi-deterministic differential-linear SAT witness")

        def project(namespace):
            return {
                local: assignment[global_name]
                for local, global_name in self._maps[namespace].items()
            }

        differential = self._prefix.decode_characteristic(project("differential"))
        middle = self._middle.decode_trail(project("middle"))
        linear = self._linear.decode_characteristic(project("linear"))
        if any(bit is TruncatedBit.UNKNOWN for bit in middle.input_pattern.bits):
            raise ValueError("upper semi-deterministic boundary is not exact")
        if differential.output_difference != int(str(middle.input_pattern), 2):
            raise ValueError("upper semi-deterministic boundary values disagree")
        state_mask = dict(linear.input_masks)["state"]
        mask_bits = tuple(
            (state_mask >> (len(middle.output_pattern.bits) - bit - 1)) & 1
            for bit in range(len(middle.output_pattern.bits))
        )
        if any(
            bit is TruncatedBit.UNKNOWN and mask
            for bit, mask in zip(middle.output_pattern.bits, mask_bits)
        ):
            raise ValueError("lower semi-deterministic boundary is incompatible")
        return WordSemiDeterministicDifferentialLinearSATTrail(differential, middle, linear)


@dataclass(frozen=True, slots=True)
class WordDeterministicDifferentialLinearSATTrail:
    """One decoded differential, deterministic-truncated, and linear witness.

    The objective is the characteristic convention used by the legacy SAT
    search: differential weight plus twice the linear-correlation weight. The
    deterministic middle contributes no probability estimate.

    EXAMPLES::

        >>> from types import SimpleNamespace
        >>> trail = WordDeterministicDifferentialLinearSATTrail(
        ...     SimpleNamespace(total_weight=2),
        ...     SimpleNamespace(),
        ...     SimpleNamespace(total_weight=3),
        ... )
        >>> trail.total_weight
        8
    """

    differential: Any
    middle: WordDeterministicTruncatedCharacteristic
    linear: Any

    @property
    def total_weight(self):
        """Return differential weight plus twice the linear weight."""

        return self.differential.total_weight + 2 * self.linear.total_weight


class WordDeterministicDifferentialLinearSATModel:
    """Compose exact, truncated, and linear SAT searches over round slices.

    This recovered strategy keeps all three submodels independently decodable.
    The upper connector converts the prefix output difference to an exact
    truncated state; the lower connector forces masks to zero only at unknown
    middle bits.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> model = WordDeterministicDifferentialLinearSATModel(
        ...     Speck(number_of_rounds=3), prefix_rounds=1, middle_rounds=1,
        ...     differential_maximum_weight=16, linear_maximum_weight=16,
        ... )
        >>> formula = model.cnf_formula()
        >>> (formula.variable_count > 0, "differential_to_truncated_exact" in formula.provenance)
        (True, True)
    """

    model_provenance = _unaudited_model(
        ConstraintBackend.SAT,
        "WordDeterministicDifferentialLinearSATModel",
        "differential_linear",
        "round-sliced differential, deterministic-truncated, and linear composition",
        "Recovered from CLAASP's SAT composition; exact primary-source correspondence remains unaudited.",
    )

    def __init__(
        self,
        primitive,
        *,
        prefix_rounds: int,
        middle_rounds: int,
        differential_maximum_weight: int,
        linear_maximum_weight: int,
        input_difference: int | None = None,
        output_mask: int | None = None,
    ) -> None:
        counts = (prefix_rounds, middle_rounds)
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value <= 0 for value in counts
        ):
            raise ValueError("prefix_rounds and middle_rounds must be positive integers")
        if prefix_rounds + middle_rounds >= len(primitive.rounds):
            raise ValueError("the differential, middle, and linear slices must all be nonempty")
        for weight in (differential_maximum_weight, linear_maximum_weight):
            if not isinstance(weight, int) or isinstance(weight, bool) or weight < 0:
                raise ValueError("weight bounds must be nonnegative integers")
        block_width = sum(
            port.value_type.unit_count * port.value_type.domain.width
            for name, port in primitive.input_ports.items()
            if name == "plaintext"
        )
        if not block_width:
            raise NotImplementedError("differential-linear SAT assembly requires plaintext")
        for value, label in ((input_difference, "input difference"), (output_mask, "output mask")):
            if value is not None and (
                not isinstance(value, int)
                or isinstance(value, bool)
                or not 0 <= value < 1 << block_width
            ):
                raise ValueError(f"{label} must fit the primitive block width")
        self.primitive = primitive
        self.prefix_rounds = prefix_rounds
        self.middle_rounds = middle_rounds
        self.suffix_rounds = len(primitive.rounds) - prefix_rounds - middle_rounds
        self.differential_maximum_weight = differential_maximum_weight
        self.linear_maximum_weight = linear_maximum_weight
        self.input_difference = input_difference
        self.output_mask = output_mask
        self._formula: CNFFormula | None = None
        self._maps: dict[str, dict[str, str]] = {}

    @staticmethod
    def _zero_pattern(port):
        return "0" * (port.value_type.unit_count * port.value_type.domain.width)

    def cnf_formula(self) -> CNFFormula:
        """Return the complete round-sliced differential-linear formula."""

        prefix_end = self.prefix_rounds - 1
        middle_end = prefix_end + self.middle_rounds
        prefix_primitive = slice_rounds(self.primitive, 0, prefix_end).primitive
        middle_primitive = slice_rounds(self.primitive, self.prefix_rounds, middle_end).primitive
        suffix_primitive = slice_rounds(
            self.primitive, middle_end + 1, len(self.primitive.rounds) - 1
        ).primitive

        prefix_fixed = {"key": 0} if "key" in prefix_primitive.input_ports else {}
        if self.input_difference is not None:
            prefix_fixed["plaintext"] = self.input_difference
        self._prefix = WordDifferentialSATModel(
            prefix_primitive,
            maximum_weight=self.differential_maximum_weight,
            nonzero_input="plaintext" if self.input_difference is None else None,
            fixed_input_differences=prefix_fixed,
        )
        middle_fixed = {
            name: self._zero_pattern(port)
            for name, port in middle_primitive.input_ports.items()
            if name != "state"
        }
        self._middle = WordDeterministicTruncatedSATModel(
            middle_primitive, fixed_input_patterns=middle_fixed
        )
        suffix_fixed = {name: 0 for name in suffix_primitive.input_ports if name != "state"}
        self._linear = WordLinearSATModel(
            suffix_primitive,
            maximum_weight=self.linear_maximum_weight,
            fixed_input_masks=suffix_fixed,
        )
        subformulas = (
            ("differential", self._prefix.cnf_formula()),
            ("middle", self._middle.cnf_formula()),
            ("linear", self._linear.cnf_formula()),
        )

        variables: list[str] = []
        indices: dict[str, int] = {}
        clauses: list[tuple[int, ...]] = []
        provenance: list[str] = []
        applications = []
        maps = {}

        def allocate(name):
            if name not in indices:
                variables.append(name)
                indices[name] = len(variables)
            return name

        def append_formula(namespace, formula):
            mapping = {name: allocate(f"{namespace}_{name}") for name in formula.variables}
            remap = {
                position: indices[mapping[name]]
                for position, name in enumerate(formula.variables, 1)
            }
            for clause, label in zip(formula.clauses, formula.provenance):
                clauses.append(
                    tuple(remap[abs(literal)] * (1 if literal > 0 else -1) for literal in clause)
                )
                provenance.append(label)
            applications.extend(formula.constraint_models)
            maps[namespace] = mapping

        for namespace, formula in subformulas:
            append_formula(namespace, formula)

        def append_connector(formula, mapping):
            remap = {
                position: indices[mapping[name]]
                for position, name in enumerate(formula.variables, 1)
            }
            for clause, label in zip(formula.clauses, formula.provenance):
                clauses.append(
                    tuple(remap[abs(literal)] * (1 if literal > 0 else -1) for literal in clause)
                )
                provenance.append(label)
            applications.extend(formula.constraint_models)

        prefix_output = self._prefix._shared._output
        middle_input = self._middle._ports["state"]
        if len(prefix_output) != len(middle_input):
            raise ValueError("upper differential-linear boundary widths disagree")
        upper = DifferentialToTruncatedSATModel(len(prefix_output)).cnf_formula()
        append_connector(
            upper,
            {
                **{
                    f"difference_{bit}": maps["differential"][name]
                    for bit, name in enumerate(prefix_output)
                },
                **{
                    f"truncated_{bit}_{field}": maps["middle"][pair[position]]
                    for bit, pair in enumerate(middle_input)
                    for position, field in enumerate(("unknown", "value"))
                },
            },
        )

        middle_output = self._middle._output
        linear_input = self._linear._shared._ports["state"]
        if len(middle_output) != len(linear_input):
            raise ValueError("lower differential-linear boundary widths disagree")
        lower = TruncatedToLinearSATModel(len(linear_input)).cnf_formula()
        append_connector(
            lower,
            {
                **{
                    f"truncated_{bit}_{field}": maps["middle"][pair[position]]
                    for bit, pair in enumerate(middle_output)
                    for position, field in enumerate(("unknown", "value"))
                },
                **{f"mask_{bit}": maps["linear"][name] for bit, name in enumerate(linear_input)},
            },
        )

        linear_output = tuple(maps["linear"][name] for name in self._linear._shared._output)
        if self.output_mask is None:
            clauses.append(tuple(indices[name] for name in linear_output))
            provenance.append("nonzero_differential_linear_output_mask")
        else:
            for bit, name in enumerate(linear_output):
                value = self.output_mask & (1 << (len(linear_output) - 1 - bit))
                clauses.append(((indices[name] if value else -indices[name]),))
                provenance.append("fixed_differential_linear_output_mask")

        applications.append(ConstraintModelApplication(self.model_provenance))
        self._maps = maps
        self._formula = CNFFormula(
            tuple(variables), tuple(clauses), tuple(provenance), tuple(applications)
        )
        return self._formula

    def decode_trail(self, assignment) -> WordDeterministicDifferentialLinearSATTrail:
        """Decode all three sections and independently check both connectors."""

        if self._formula is None:
            raise ValueError("build the formula before decoding")
        if not self._formula.is_satisfied(assignment):
            raise ValueError("invalid differential-linear SAT witness")

        def project(namespace):
            return {
                local: assignment[global_name]
                for local, global_name in self._maps[namespace].items()
            }

        differential = self._prefix.decode_characteristic(project("differential"))
        middle = self._middle.decode_characteristic(project("middle"))
        linear = self._linear.decode_characteristic(project("linear"))
        middle_input = dict(middle.input_patterns)["state"]
        if any(bit is TruncatedBit.UNKNOWN for bit in middle_input.bits):
            raise ValueError("upper differential-linear boundary is not exact")
        if differential.output_difference != int(str(middle_input), 2):
            raise ValueError("upper differential-linear boundary values disagree")
        state_mask = dict(linear.input_masks)["state"]
        mask_bits = tuple(
            (state_mask >> (len(middle.output_pattern.bits) - bit - 1)) & 1
            for bit in range(len(middle.output_pattern.bits))
        )
        if any(
            bit is TruncatedBit.UNKNOWN and mask
            for bit, mask in zip(middle.output_pattern.bits, mask_bits)
        ):
            raise ValueError("lower differential-linear boundary is incompatible")
        return WordDeterministicDifferentialLinearSATTrail(differential, middle, linear)


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
    "SpeckImpossibleSATModel",
    "SpeckImpossibleSATTrail",
    "SpeckProbabilisticTruncatedSATModel",
    "SemiDeterministicModularAddTransition",
    "SharedDifferencePairedSATTrail",
    "SharedDifferencePairedDifferentialLinearSATTrail",
    "SharedDifferencePairedWordDifferentialLinearSATModel",
    "SharedDifferencePairedWordDifferentialSATModel",
    "SpeckSemiDeterministicTruncatedSATModel",
    "SpeckSemiDeterministicTruncatedTrail",
    "WordDeterministicTruncatedCharacteristic",
    "WordDeterministicTruncatedEnumeration",
    "WordDeterministicTruncatedNativeXorSATModel",
    "WordDeterministicTruncatedSATModel",
    "WordDifferentialNativeXorSATModel",
    "WordDifferentialSATModel",
    "WordLinearNativeXorSATModel",
    "WordLinearSATModel",
    "WordSemiDeterministicDifferentialLinearSATModel",
    "WordSemiDeterministicDifferentialLinearSATTrail",
]
