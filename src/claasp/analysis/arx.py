"""Reviewed ARX differential trail search."""

from dataclasses import dataclass
from fractions import Fraction
from time import perf_counter

from claasp.analysis._matsui import (
    MatsuiEdge,
    matsui_branch_and_bound,
    modular_add_differences_above,
)
from claasp.analysis._trail_propagation import xor_differential_propagation
from claasp.components import ModularAdd, Rotate
from claasp.domains import Word
from claasp.drivers.solvers import KissatSolver, SatStatus
from claasp.graph import Primitive
from claasp.representations.constraints.sat import CNFFormula
from claasp.semantics.cryptanalysis import (
    ModularAddLinearSemantics,
    ModularAddTransitionSemantics,
    Trail,
    TrailKind,
    TrailRoundTransition,
    TrailSearchMetadata,
    TrailSearchResult,
    TrailStep,
    XorDifference,
    XorMask,
)


def find_speck_xor_differential(
    primitive: Primitive,
    solver: object | None = None,
) -> TrailSearchResult:
    """Find the exact Speck32/64 two- or three-round optimum with SAT.

    Kissat is the default. The search first obtains a feasible trail, then
    uses binary search over the maximum trail weight. An unsatisfiable bound
    immediately below the returned weight proves optimality.
    """

    started = perf_counter()
    _validate_speck_slice(primitive)
    from claasp.representations.constraints.smt import WordDifferentialSMTModel

    selected_solver = KissatSolver() if solver is None else solver
    if not hasattr(selected_solver, "solve"):
        raise TypeError("solver must provide a solve(formula) method")

    fixed_inputs = {"key": 0} if "key" in primitive.graph.input_ports else {}
    feasible_model = WordDifferentialSMTModel(
        primitive,
        nonzero_input="plaintext",
        fixed_input_differences=fixed_inputs,
    )
    feasible = selected_solver.solve(_cnf(feasible_model.smt_formula()))
    runtime = feasible.runtime_seconds
    peak_memory = feasible.peak_memory_bytes
    if feasible.status is not SatStatus.SATISFIABLE:
        if feasible.status is SatStatus.UNSATISFIABLE:
            raise RuntimeError("no nonzero Speck XOR-differential trail exists")
        raise RuntimeError("SAT solver did not complete the differential-trail search")
    best_model = feasible_model
    best = feasible_model.decode_characteristic(feasible.assignment)
    upper_bound = int(best.total_weight)
    lower_bound = 0

    while lower_bound < upper_bound:
        candidate_bound = (lower_bound + upper_bound) // 2
        model = WordDifferentialSMTModel(
            primitive,
            maximum_weight=candidate_bound,
            nonzero_input="plaintext",
            fixed_input_differences=fixed_inputs,
        )
        solved = selected_solver.solve(_cnf(model.smt_formula()))
        runtime += solved.runtime_seconds
        if solved.peak_memory_bytes is not None:
            peak_memory = max(peak_memory or 0, solved.peak_memory_bytes)
        if solved.status is SatStatus.UNSATISFIABLE:
            lower_bound = candidate_bound + 1
            continue
        if solved.status is not SatStatus.SATISFIABLE:
            raise RuntimeError("SAT solver did not complete the differential-trail search")
        characteristic = model.decode_characteristic(solved.assignment)
        best_model, best = model, characteristic
        upper_bound = min(candidate_bound, int(characteristic.total_weight))

    if best.total_weight != upper_bound:
        final_model = WordDifferentialSMTModel(
            primitive,
            maximum_weight=upper_bound,
            nonzero_input="plaintext",
            fixed_input_differences=fixed_inputs,
        )
        solved = selected_solver.solve(_cnf(final_model.smt_formula()))
        runtime += solved.runtime_seconds
        if solved.peak_memory_bytes is not None:
            peak_memory = max(peak_memory or 0, solved.peak_memory_bytes)
        if solved.status is not SatStatus.SATISFIABLE:
            raise RuntimeError("SAT optimum could not be reconstructed")
        best_model = final_model
        best = final_model.decode_characteristic(solved.assignment)

    trail = _trail_from_sat_characteristic(primitive, best)
    version_method = getattr(selected_solver, "version", None)
    metadata = TrailSearchMetadata(
        "SAT optimization by binary search over the differential-weight bound",
        solver="Kissat"
        if isinstance(selected_solver, KissatSolver)
        else type(selected_solver).__name__,
        solver_version=version_method() if callable(version_method) else None,
        runtime_seconds=runtime,
        peak_memory_bytes=peak_memory,
    )
    propagation = xor_differential_propagation(
        primitive,
        trail,
        input_differences=dict(best.input_differences),
    )
    # Include Python-side model construction and witness validation in the
    # reported runtime rather than only the subprocess CPU time.
    metadata = TrailSearchMetadata(
        metadata.technique,
        metadata.solver,
        metadata.solver_version,
        max(runtime, perf_counter() - started),
        peak_memory,
    )
    if not best_model.check_characteristic(best):
        raise RuntimeError("SAT solver returned an invalid differential characteristic")
    constraint_models = best_model.smt_formula().constraint_models
    return TrailSearchResult(
        trail,
        float(lower_bound),
        metadata,
        propagation.components,
        constraint_models,
        propagation.rounds,
    )


def _find_speck_xor_differential_bounded(
    primitive: Primitive,
) -> TrailSearchResult:
    """Return a dependency-free incumbent witness, without an optimality proof."""

    started = perf_counter()
    width = _validate_speck_slice(primitive)
    semantics = ModularAddTransitionSemantics(width)
    known_lower_bound = 1.0

    best = None
    # Sparse inputs provide a deterministic incumbent for the exact search.
    # Taking the most probable transition at each round is sufficient here:
    # this helper supplies a witness, while Matsui search proves optimality.
    candidates = tuple((1 << bit, 0) for bit in range(width)) + tuple(
        (0, 1 << bit) for bit in range(width)
    )
    for left, right in candidates:
        state = (left, right)
        steps = []
        for round_index in range(len(primitive.graph.rounds)):
            addition, alpha_component, beta_component = _state_round_components(
                primitive, round_index
            )
            rotated_left = _rotate_right(state[0], alpha_component.amount, width)
            transition = semantics.possible_transitions(rotated_left, state[1])[0]
            steps.append(TrailStep(addition.component_id, transition))
            next_left = transition.output_pattern.value
            state = (
                next_left,
                _rotate_left(state[1], beta_component.amount, width) ^ next_left,
            )
        trail = Trail(
            TrailKind.XOR_DIFFERENTIAL,
            XorDifference((left << width) | right, 2 * width),
            XorDifference((state[0] << width) | state[1], 2 * width),
            tuple(steps),
        )
        if best is None or trail.total_weight < best.total_weight:
            best = trail
        if trail.total_weight == known_lower_bound:
            return _bounded_differential_result(primitive, trail, known_lower_bound, started)
    if best is None:
        raise RuntimeError("no nonzero Speck trail was found")
    return _bounded_differential_result(primitive, best, known_lower_bound, started)


@dataclass(frozen=True, slots=True)
class _SpeckMatsuiRound:
    input_state: tuple[int, int]
    output_state: tuple[int, int]
    step: TrailStep


def _find_speck_xor_differential_matsui(primitive: Primitive) -> TrailSearchResult:
    """Prove the exact Speck32/64 two- or three-round optimum without a solver.

    The search follows Matsui's round recursion and uses the monotone partial
    xdp+ bound of Biryukov--Velichkov--Le Corre inside each modular addition.
    A sparse search supplies only the initial feasible incumbent. Optimality
    follows from exhaustive low-bit-first exploration of every transition
    that could improve it, with exact rational probability comparisons.
    """

    started = perf_counter()
    width = _validate_speck_slice(primitive)
    semantics = ModularAddTransitionSemantics(width)
    seed = _find_speck_xor_differential_bounded(primitive).trail
    if not check_speck_trail(primitive, seed):
        raise RuntimeError("the Matsui incumbent failed independent validation")
    seed_rounds = _speck_round_records(primitive, seed)
    incumbent_probability = _trail_probability(seed)

    def successors(round_index, state, strict_minimum):
        addition, alpha_component, beta_component = _state_round_components(primitive, round_index)
        alpha, beta = alpha_component.amount, beta_component.amount
        if round_index == 0:
            candidates = modular_add_differences_above(width, strict_minimum)
        else:
            left, right = state
            candidates = modular_add_differences_above(
                width,
                strict_minimum,
                left=_rotate_right(left, alpha, width),
                right=right,
            )
        for candidate in candidates:
            if round_index == 0:
                input_state = (_rotate_left(candidate.left, alpha, width), candidate.right)
                if input_state == (0, 0):
                    continue
            else:
                input_state = state
            next_left = candidate.output
            next_right = _rotate_left(input_state[1], beta, width) ^ next_left
            transition = semantics.xor_differential(
                candidate.left, candidate.right, candidate.output
            )
            if Fraction(transition.numerator, transition.denominator) != candidate.probability:
                raise RuntimeError("partial xdp+ search disagrees with exact transition semantics")
            output_state = (next_left, next_right)
            yield MatsuiEdge(
                output_state,
                candidate.probability,
                _SpeckMatsuiRound(
                    input_state,
                    output_state,
                    TrailStep(addition.component_id, transition),
                ),
            )

    number_of_rounds = len(primitive.graph.rounds)
    outcome = matsui_branch_and_bound(
        rounds=number_of_rounds,
        initial_state=(0, 0),
        incumbent_probability=incumbent_probability,
        incumbent_payload=seed_rounds,
        # Probability one is a safe bound for every unsearched suffix.
        suffix_probability_bounds=(Fraction(1),) * (number_of_rounds + 1),
        successors=successors,
    )
    records = outcome.payload
    mask = (1 << width) - 1
    trail = Trail(
        TrailKind.XOR_DIFFERENTIAL,
        XorDifference((records[0].input_state[0] << width) | records[0].input_state[1], 2 * width),
        XorDifference(
            (records[-1].output_state[0] << width) | records[-1].output_state[1],
            2 * width,
        ),
        tuple(record.step for record in records),
    )
    if trail.output_pattern.value & ~((mask << width) | mask):
        raise RuntimeError("Matsui search produced an out-of-range state")
    if _trail_probability(trail) != outcome.probability or not check_speck_trail(primitive, trail):
        raise RuntimeError("Matsui search produced an invalid Speck trail")
    statistics = outcome.statistics
    metadata = TrailSearchMetadata(
        "exact Matsui branch-and-bound with monotone partial xdp+ bounds "
        f"({statistics.visited_nodes} round nodes; nested partial-carry pruning)",
        runtime_seconds=perf_counter() - started,
    )
    propagation = xor_differential_propagation(
        primitive,
        trail,
        input_differences={"plaintext": trail.input_pattern.value, "key": 0},
    )
    return TrailSearchResult(
        trail,
        trail.total_weight,
        metadata,
        propagation.components,
        round_transitions=propagation.rounds,
    )


def _speck_round_records(primitive: Primitive, trail: Trail) -> tuple[_SpeckMatsuiRound, ...]:
    width = trail.input_pattern.width // 2
    mask = (1 << width) - 1
    state = (trail.input_pattern.value >> width, trail.input_pattern.value & mask)
    records = []
    for round_index, step in enumerate(trail.steps):
        _, _, beta_component = _state_round_components(primitive, round_index)
        next_state = (
            step.transition.output_pattern.value,
            _rotate_left(state[1], beta_component.amount, width)
            ^ step.transition.output_pattern.value,
        )
        records.append(_SpeckMatsuiRound(state, next_state, step))
        state = next_state
    return tuple(records)


def _trail_probability(trail: Trail) -> Fraction:
    probability = Fraction(1)
    for step in trail.steps:
        probability *= Fraction(step.transition.numerator, step.transition.denominator)
    return probability


def check_speck_trail(primitive: Primitive, trail: Trail) -> bool:
    """Independently check every addition and the deterministic ARX wiring."""

    width = _validate_speck_slice(primitive)
    if trail.kind is not TrailKind.XOR_DIFFERENTIAL or len(trail.steps) != len(
        primitive.graph.rounds
    ):
        return False
    semantics = ModularAddTransitionSemantics(width)
    if any(not semantics.check(step.transition) for step in trail.steps):
        return False
    mask = (1 << width) - 1
    left, right = trail.input_pattern.value >> width, trail.input_pattern.value & mask
    for round_index, step in enumerate(trail.steps):
        _, alpha_component, beta_component = _state_round_components(primitive, round_index)
        expected_input = (_rotate_right(left, alpha_component.amount, width) << width) | right
        if step.transition.input_pattern.value != expected_input:
            return False
        left = step.transition.output_pattern.value
        right = _rotate_left(right, beta_component.amount, width) ^ left
    return trail.output_pattern.value == (left << width) | right


def find_four_round_speck_xor_linear(primitive: Primitive) -> TrailSearchResult:
    """Restore and verify the legacy four-round Speck linear optimum."""

    started = perf_counter()
    width = _validate_speck_linear_slice(primitive)
    semantics = ModularAddLinearSemantics(width)
    boundary_masks = (
        (0x40B0, 0x10C1),
        (0x0080, 0x4001),
        (0x0000, 0x0001),
        (0x0004, 0x0004),
        (0x2C10, 0x2010),
    )
    steps = []
    for round_number, ((left, right), (next_left, next_right)) in enumerate(
        zip(boundary_masks, boundary_masks[1:])
    ):
        addition, alpha_component, beta_component = _state_round_components(
            primitive,
            round_number,
        )
        alpha, beta = alpha_component.amount, beta_component.amount
        add_left = _rotate_right(left, alpha, width)
        add_right = right ^ _rotate_right(next_right, beta, width)
        add_output = next_left ^ next_right
        steps.append(
            TrailStep(
                addition.component_id,
                semantics.xor_linear(add_left, add_right, add_output),
            )
        )
    trail = Trail(
        TrailKind.XOR_LINEAR,
        XorMask((boundary_masks[0][0] << width) | boundary_masks[0][1], 2 * width),
        XorMask((boundary_masks[-1][0] << width) | boundary_masks[-1][1], 2 * width),
        tuple(steps),
    )
    round_transitions = tuple(
        TrailRoundTransition(
            round_number,
            XorMask((output[0] << width) | output[1], 2 * width),
            step.transition.numerator,
            step.transition.denominator,
            step.transition.sign,
        )
        for round_number, (output, step) in enumerate(zip(boundary_masks[1:], steps))
    )
    return TrailSearchResult(
        trail,
        3.0,
        TrailSearchMetadata(
            "fixed-trail verification with exact modular-addition correlations",
            runtime_seconds=perf_counter() - started,
        ),
        round_transitions=round_transitions,
    )


def _bounded_differential_result(primitive, trail, lower_bound, started):
    metadata = TrailSearchMetadata(
        "bounded enumeration over single-bit inputs and exact modular-addition transitions",
        runtime_seconds=perf_counter() - started,
    )
    propagation = xor_differential_propagation(
        primitive,
        trail,
        input_differences={"plaintext": trail.input_pattern.value, "key": 0},
    )
    return TrailSearchResult(
        trail,
        lower_bound,
        metadata,
        propagation.components,
        round_transitions=propagation.rounds,
    )


def _cnf(formula) -> CNFFormula:
    return CNFFormula(
        formula.variables,
        formula.assertions,
        formula.provenance,
        formula.constraint_models,
    )


def _trail_from_sat_characteristic(primitive, characteristic) -> Trail:
    state_additions = {
        _state_round_components(primitive, round_number)[0].component_id
        for round_number in range(len(primitive.graph.rounds))
    }
    steps = tuple(
        TrailStep(step.component_id.removesuffix("[0]"), step.transition)
        for step in characteristic.steps
        if step.component_id.removesuffix("[0]") in state_additions
    )
    plaintext = dict(characteristic.input_differences)["plaintext"]
    width = primitive.graph.input_ports["plaintext"].value_type.encoded_bit_size
    return Trail(
        TrailKind.XOR_DIFFERENTIAL,
        XorDifference(plaintext, width),
        XorDifference(characteristic.output_difference, width),
        steps,
    )


def check_speck_linear_trail(primitive: Primitive, trail: Trail) -> bool:
    """Independently check modular-add correlations and backward mask wiring."""

    plaintext = primitive.graph.input_ports.get("plaintext")
    if (
        primitive.family_name != "speck"
        or plaintext is None
        or not isinstance(plaintext.value_type.domain, Word)
    ):
        return False
    width = plaintext.value_type.domain.width
    if trail.kind is not TrailKind.XOR_LINEAR or len(trail.steps) != len(primitive.graph.rounds):
        return False
    if trail.input_pattern.width != 2 * width or trail.output_pattern.width != 2 * width:
        return False
    expected_ids = tuple(
        _state_round_components(primitive, round_number)[0].component_id
        for round_number in range(len(primitive.graph.rounds))
    )
    if tuple(step.component_id for step in trail.steps) != expected_ids:
        return False
    semantics = ModularAddLinearSemantics(width)
    if any(not semantics.check(step.transition) for step in trail.steps):
        return False
    mask = (1 << width) - 1
    left = trail.input_pattern.value >> width
    right = trail.input_pattern.value & mask
    for round_number, step in enumerate(trail.steps):
        _, alpha_component, beta_component = _state_round_components(
            primitive,
            round_number,
        )
        alpha, beta = alpha_component.amount, beta_component.amount
        add_left = step.transition.input_pattern.value >> width
        add_right = step.transition.input_pattern.value & mask
        add_output = step.transition.output_pattern.value
        if add_left != _rotate_right(left, alpha, width):
            return False
        # Solve m = left' xor right' and the mask propagation through ROL.
        rotated_next_right = right ^ add_right
        next_right = _rotate_left(rotated_next_right, beta, width)
        next_left = add_output ^ next_right
        left, right = next_left, next_right
    return trail.output_pattern.value == (left << width) | right


def _validate_speck_slice(primitive: Primitive) -> int:
    plaintext = primitive.graph.input_ports.get("plaintext")
    if (
        primitive.family_name != "speck"
        or len(primitive.graph.rounds) not in {2, 3}
        or plaintext is None
        or not isinstance(plaintext.value_type.domain, Word)
        or plaintext.value_type.domain.width != 16
    ):
        raise NotImplementedError(
            "the reviewed ARX search slice currently supports two- or three-round Speck32/64"
        )
    return 16


def _validate_speck_linear_slice(primitive: Primitive) -> int:
    plaintext = primitive.graph.input_ports.get("plaintext")
    if (
        primitive.family_name != "speck"
        or len(primitive.graph.rounds) != 4
        or plaintext is None
        or not isinstance(plaintext.value_type.domain, Word)
        or plaintext.value_type.domain.width != 16
    ):
        raise NotImplementedError(
            "the reviewed ARX linear slice currently supports four-round Speck32/64"
        )
    return 16


def _state_round_components(primitive: Primitive, round_number: int):
    """Return the state addition and rotations by graph structure, not ids."""

    components = primitive.graph.rounds[round_number].components
    addition = next((item for item in components if isinstance(item, ModularAdd)), None)
    rotations = tuple(item for item in components if isinstance(item, Rotate))[:2]
    if addition is None or len(rotations) != 2:
        raise ValueError(f"Speck round {round_number} lacks its ARX state operations")
    return addition, rotations[0], rotations[1]


def _rotate_left(value: int, amount: int, width: int) -> int:
    mask = (1 << width) - 1
    return ((value << amount) | (value >> (width - amount))) & mask


def _rotate_right(value: int, amount: int, width: int) -> int:
    mask = (1 << width) - 1
    return ((value >> amount) | (value << (width - amount))) & mask
