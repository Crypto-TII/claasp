"""Capability-based exact optimization of weighted Word characteristics."""

from dataclasses import dataclass
from fractions import Fraction
from time import perf_counter

from claasp.components import (
    BitwiseAnd,
    BitwiseNot,
    BitwiseOr,
    Constant,
    Identity,
    ModularAdd,
    ModularSubtract,
    Permutation,
    Rotate,
    Shift,
    Xor,
)
from claasp.domains import Word
from claasp.drivers.solvers import MinisatSolver, SatStatus
from claasp.representations.constraints.sat import (
    WordDifferentialSATModel,
    WordLinearSATModel,
)
from claasp.semantics.cryptanalysis import (
    Trail,
    TrailComponentTransition,
    TrailKind,
    TrailRoundTransition,
    TrailSearchMetadata,
    TrailSearchResult,
    XorDifference,
    XorMask,
)


class TrailSearchCapabilityError(NotImplementedError):
    """An exact trail backend cannot model the first reported graph feature.

    EXAMPLES::

        >>> isinstance(TrailSearchCapabilityError("gap"), NotImplementedError)
        True
    """


@dataclass(frozen=True, slots=True)
class InputPolicy:
    """Resolved active and fixed external inputs for one search."""

    nonzero_input: str
    fixed_patterns: dict[str, int]


_WORD_COMPONENTS = (
    ModularAdd,
    ModularSubtract,
    BitwiseAnd,
    BitwiseOr,
    BitwiseNot,
    Xor,
    Identity,
    Rotate,
    Shift,
    Permutation,
    Constant,
)


def require_word_sat_capability(primitive, kind: TrailKind) -> None:
    """Reject the first unsupported domain/component with actionable context.

    EXAMPLES::

        >>> from claasp.primitives import Simon
        >>> require_word_sat_capability(Simon(number_of_rounds=1), TrailKind.XOR_DIFFERENTIAL)
    """

    for name, port in primitive.input_ports.items():
        if not isinstance(port.value_type.domain, Word):
            raise _capability_error(
                primitive, kind, f"input {name!r} domain {type(port.value_type.domain).__name__}"
            )
    if primitive.output is None:
        raise _capability_error(primitive, kind, "missing primitive output")
    if not isinstance(primitive.output.value_type.domain, Word):
        raise _capability_error(
            primitive, kind, f"output domain {type(primitive.output.value_type.domain).__name__}"
        )
    for component in primitive.components:
        if not isinstance(component.output_type.domain, Word):
            reason = f"component {component.component_id!r} domain {type(component.output_type.domain).__name__}"
            raise _capability_error(primitive, kind, reason)
        if not isinstance(component, _WORD_COMPONENTS):
            reason = f"component {component.component_id!r} ({type(component).__name__})"
            raise _capability_error(primitive, kind, reason)
        if (
            isinstance(component, (ModularAdd, ModularSubtract, BitwiseAnd, BitwiseOr))
            and len(component.inputs) != 2
        ):
            reason = f"component {component.component_id!r} ({type(component).__name__}) arity {len(component.inputs)}"
            raise _capability_error(primitive, kind, reason)


def _capability_error(primitive, kind, reason):
    return TrailSearchCapabilityError(
        f"primitive {primitive.family_name!r}, analysis {kind.value!r}, backend 'sat': "
        f"first unsupported feature is {reason}"
    )


def resolve_input_policy(
    primitive, nonzero_input, fixed_patterns, *, add_key_tweak_defaults=True
) -> InputPolicy:
    """Choose one active data input and zero default key/tweak patterns."""

    names = tuple(primitive.input_ports)
    if nonzero_input is None:
        if "plaintext" in names:
            nonzero_input = "plaintext"
        elif len(names) == 1:
            nonzero_input = names[0]
        else:
            candidates = tuple(
                name for name in names if "key" not in name.lower() and "tweak" not in name.lower()
            )
            if len(candidates) != 1:
                raise ValueError(
                    f"cannot choose a unique active input for {primitive.family_name!r}; "
                    f"set nonzero_input explicitly from {names!r}"
                )
            nonzero_input = candidates[0]
    if nonzero_input not in primitive.input_ports:
        raise ValueError(f"unknown nonzero input {nonzero_input!r}; choose from {names!r}")
    resolved = dict(fixed_patterns or {})
    for name in names:
        if (
            add_key_tweak_defaults
            and name != nonzero_input
            and ("key" in name.lower() or "tweak" in name.lower())
        ):
            resolved.setdefault(name, 0)
    if nonzero_input in resolved:
        raise ValueError(f"nonzero input {nonzero_input!r} cannot also be fixed")
    return InputPolicy(nonzero_input, resolved)


def optimize_word_characteristic(
    primitive,
    kind: TrailKind,
    *,
    solver=None,
    nonzero_input=None,
    fixed_input_differences=None,
    fixed_input_masks=None,
    fixed_inputs=None,
) -> TrailSearchResult:
    """Minimize an integer characteristic weight and prove the preceding bound UNSAT.

    EXAMPLES::

        >>> try:
        ...     optimize_word_characteristic()
        ... except TypeError:
        ...     print("configuration required")
        configuration required
    """

    require_word_sat_capability(primitive, kind)
    fixed = fixed_input_differences if kind is TrailKind.XOR_DIFFERENTIAL else fixed_input_masks
    policy = resolve_input_policy(
        primitive,
        nonzero_input,
        fixed,
        add_key_tweak_defaults=kind is TrailKind.XOR_DIFFERENTIAL,
    )
    resolved_fixed_inputs = dict(fixed_inputs or {})
    if kind is TrailKind.XOR_LINEAR and fixed_input_masks is None:
        for name in primitive.input_ports:
            if name != policy.nonzero_input and ("key" in name.lower() or "tweak" in name.lower()):
                resolved_fixed_inputs.setdefault(name, 0)
    selected_solver = MinisatSolver() if solver is None else solver
    if not callable(getattr(selected_solver, "solve", None)):
        raise TypeError("solver must provide a solve(formula) method")
    started = perf_counter()
    runtime = 0.0

    def build(bound):
        if kind is TrailKind.XOR_DIFFERENTIAL:
            return WordDifferentialSATModel(
                primitive,
                maximum_weight=bound,
                nonzero_input=policy.nonzero_input,
                fixed_input_differences=policy.fixed_patterns,
            )
        options = {
            "maximum_weight": bound,
            "nonzero_input": policy.nonzero_input,
            "fixed_input_masks": policy.fixed_patterns,
        }
        if resolved_fixed_inputs:
            options["fixed_inputs"] = resolved_fixed_inputs
        return WordLinearSATModel(primitive, **options)

    def solve(bound):
        nonlocal runtime
        model = build(bound)
        formula = model.cnf_formula()
        result = selected_solver.solve(formula)
        runtime += result.runtime_seconds
        return model, formula, result

    best_model, best_formula, feasible = solve(None)
    if feasible.status is not SatStatus.SATISFIABLE:
        raise RuntimeError(
            f"no nonzero {kind.value} characteristic exists for {primitive.family_name!r}"
        )
    best = best_model.decode_characteristic(feasible.assignment)
    if not best_model.check_characteristic(best):
        raise RuntimeError("decoded SAT characteristic failed independent validation")
    upper, lower = int(best.total_weight), 0
    while lower < upper:
        candidate = (lower + upper) // 2
        model, formula, solved = solve(candidate)
        if solved.status is SatStatus.UNSATISFIABLE:
            lower = candidate + 1
        elif solved.status is SatStatus.SATISFIABLE:
            characteristic = model.decode_characteristic(solved.assignment)
            if not model.check_characteristic(characteristic):
                raise RuntimeError("decoded SAT characteristic failed independent validation")
            best_model, best_formula, best = model, formula, characteristic
            upper = min(candidate, int(characteristic.total_weight))
        else:
            raise RuntimeError("SAT solver did not complete exact trail optimization")
    if int(best.total_weight) != upper:
        best_model, best_formula, solved = solve(upper)
        if solved.status is not SatStatus.SATISFIABLE:
            raise RuntimeError("SAT optimum could not be reconstructed")
        best = best_model.decode_characteristic(solved.assignment)
    if upper > 0:
        _, _, proof = solve(upper - 1)
        if proof.status is not SatStatus.UNSATISFIABLE:
            raise RuntimeError(f"bound {upper - 1} was not proved UNSAT")
    if not best_model.check_characteristic(best):
        raise RuntimeError("optimal SAT characteristic failed independent validation")
    trail = _trail(primitive, kind, policy.nonzero_input, best)
    components, rounds = _evidence(primitive, kind, best_model._shared, best)
    version = getattr(selected_solver, "version", None)
    metadata = TrailSearchMetadata(
        "exact SAT optimization by binary search; immediate lower bound proved UNSAT",
        type(selected_solver).__name__,
        version() if callable(version) else None,
        max(runtime, perf_counter() - started),
    )
    return TrailSearchResult(
        trail,
        float(upper),
        metadata,
        components,
        best_model.constraint_models,
        rounds,
    )


def _trail(primitive, kind, active_input, characteristic):
    pattern = XorDifference if kind is TrailKind.XOR_DIFFERENTIAL else XorMask
    inputs = dict(
        characteristic.input_differences
        if kind is TrailKind.XOR_DIFFERENTIAL
        else characteristic.input_masks
    )
    output = (
        characteristic.output_difference
        if kind is TrailKind.XOR_DIFFERENTIAL
        else characteristic.output_mask
    )
    return Trail(
        kind,
        pattern(
            inputs[active_input], primitive.input_ports[active_input].value_type.encoded_bit_size
        ),
        pattern(output, primitive.output.value_type.encoded_bit_size),
        characteristic.steps,
    )


def _packed(names, assignment):
    value = 0
    for name in names:
        value = (value << 1) | assignment[name]
    return value


def _evidence(primitive, kind, model, characteristic):
    pattern = XorDifference if kind is TrailKind.XOR_DIFFERENTIAL else XorMask
    assignment = dict(characteristic.semantic_assignment)
    steps = {step.component_id: step.transition for step in characteristic.steps}
    round_by_id = {
        component.component_id: primitive_round.number
        for primitive_round in primitive.rounds
        for component in primitive_round.components
    }
    components = []
    for component in primitive.components:
        output_names = model._ports[component.component_id]
        operand_groups = (
            model._operands[component.component_id]
            if kind is TrailKind.XOR_DIFFERENTIAL
            else model._edges[component.component_id]
        )
        input_names = tuple(name for group in operand_groups for name in group)
        local = steps.get(f"{component.component_id}[0]")
        components.append(
            TrailComponentTransition(
                round_by_id[component.component_id],
                component.component_id,
                type(component).__name__,
                pattern(_packed(input_names, assignment), len(input_names))
                if input_names
                else None,
                pattern(_packed(output_names, assignment), len(output_names)),
                local if local is not None and component.output_type.unit_count == 1 else None,
            )
        )
    rounds = []
    for primitive_round in primitive.rounds:
        component = primitive_round.components[-1]
        names = model._ports[component.component_id]
        ratio, sign = Fraction(1), 1
        for step in characteristic.steps:
            if round_by_id[step.component_id.split("[")[0]] == primitive_round.number:
                ratio *= Fraction(step.transition.numerator, step.transition.denominator)
                sign *= step.transition.sign
        rounds.append(
            TrailRoundTransition(
                primitive_round.number,
                pattern(_packed(names, assignment), len(names)),
                ratio.numerator,
                ratio.denominator,
                sign,
            )
        )
    return tuple(components), tuple(rounds)


__all__ = [
    "TrailSearchCapabilityError",
    "optimize_word_characteristic",
    "require_word_sat_capability",
]
