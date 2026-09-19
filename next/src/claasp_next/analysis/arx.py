"""Reviewed ARX differential trail search."""

from claasp_next.components import ModularAdd, Rotate
from claasp_next.domains import Word
from claasp_next.graph import Primitive
from claasp_next.semantics.cryptanalysis import (
    ModularAddLinearSemantics,
    ModularAddTransitionSemantics,
    Trail,
    TrailKind,
    TrailSearchResult,
    TrailStep,
    XorDifference,
    XorMask,
)


def find_two_round_speck_xor_differential(primitive: Primitive) -> TrailSearchResult:
    """Reproduce the exact legacy Speck32/64 two-round optimum."""

    width = _validate_speck_slice(primitive)
    semantics = ModularAddTransitionSemantics(width)
    _, alpha_component, beta_component = _state_round_components(primitive, 0)
    alpha, beta = alpha_component.amount, beta_component.amount
    legacy_lower_bound = 1.0

    best = None
    # A weight-one optimum has a sparse representative. Search single-bit
    # state differences deterministically and stop once the preserved lower
    # bound is met.
    candidates = tuple((1 << bit, 0) for bit in range(width)) + tuple(
        (0, 1 << bit) for bit in range(width)
    )
    for left, right in candidates:
        rotated_left = _rotate_right(left, alpha, width)
        for first in semantics.possible_transitions(rotated_left, right):
            if first.weight > legacy_lower_bound:
                break
            new_left = first.output_pattern.value
            new_right = _rotate_left(right, beta, width) ^ new_left
            second_left = _rotate_right(new_left, alpha, width)
            second = semantics.possible_transitions(second_left, new_right)[0]
            final_left = second.output_pattern.value
            final_right = _rotate_left(new_right, beta, width) ^ final_left
            trail = Trail(
                TrailKind.XOR_DIFFERENTIAL,
                XorDifference((left << width) | right, 2 * width),
                XorDifference((final_left << width) | final_right, 2 * width),
                (
                    TrailStep(_state_round_components(primitive, 0)[0].component_id, first),
                    TrailStep(_state_round_components(primitive, 1)[0].component_id, second),
                ),
            )
            if best is None or trail.total_weight < best.total_weight:
                best = trail
            if trail.total_weight == legacy_lower_bound:
                return TrailSearchResult(
                    trail,
                    legacy_lower_bound,
                    "legacy CLAASP MilpXorDifferentialModel Speck32/64-2 optimum",
                )
    if best is None:
        raise RuntimeError("no nonzero Speck trail was found")
    return TrailSearchResult(best, legacy_lower_bound, "legacy CLAASP Speck32/64-2 bound")


def check_speck_trail(primitive: Primitive, trail: Trail) -> bool:
    """Independently check both additions and deterministic ARX wiring."""

    width = _validate_speck_slice(primitive)
    if trail.kind is not TrailKind.XOR_DIFFERENTIAL or len(trail.steps) != 2:
        return False
    semantics = ModularAddTransitionSemantics(width)
    if any(not semantics.check(step.transition) for step in trail.steps):
        return False
    _, alpha_component, beta_component = _state_round_components(primitive, 0)
    alpha, beta = alpha_component.amount, beta_component.amount
    mask = (1 << width) - 1
    left, right = trail.input_pattern.value >> width, trail.input_pattern.value & mask
    first, second = (step.transition for step in trail.steps)
    if first.input_pattern.value != (_rotate_right(left, alpha, width) << width) | right:
        return False
    new_left = first.output_pattern.value
    new_right = _rotate_left(right, beta, width) ^ new_left
    if second.input_pattern.value != (_rotate_right(new_left, alpha, width) << width) | new_right:
        return False
    final_left = second.output_pattern.value
    final_right = _rotate_left(new_right, beta, width) ^ final_left
    return trail.output_pattern.value == (final_left << width) | final_right


def find_four_round_speck_xor_linear(primitive: Primitive) -> TrailSearchResult:
    """Restore and verify the legacy four-round Speck linear optimum."""

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
    return TrailSearchResult(
        trail,
        3.0,
        "legacy CLAASP SatXorLinearModel/MilpXorLinearModel Speck32/64-4 optimum",
    )


def check_speck_linear_trail(primitive: Primitive, trail: Trail) -> bool:
    """Independently check modular-add correlations and backward mask wiring."""

    plaintext = primitive.input_ports.get("plaintext")
    if (
        primitive.family_name != "speck"
        or plaintext is None
        or not isinstance(plaintext.value_type.domain, Word)
    ):
        return False
    width = plaintext.value_type.domain.width
    if trail.kind is not TrailKind.XOR_LINEAR or len(trail.steps) != len(primitive.rounds):
        return False
    if trail.input_pattern.width != 2 * width or trail.output_pattern.width != 2 * width:
        return False
    expected_ids = tuple(
        _state_round_components(primitive, round_number)[0].component_id
        for round_number in range(len(primitive.rounds))
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
    plaintext = primitive.input_ports.get("plaintext")
    if (
        primitive.family_name != "speck"
        or len(primitive.rounds) != 2
        or plaintext is None
        or not isinstance(plaintext.value_type.domain, Word)
        or plaintext.value_type.domain.width != 16
    ):
        raise NotImplementedError(
            "the reviewed ARX search slice currently supports two-round Speck32/64"
        )
    return 16


def _validate_speck_linear_slice(primitive: Primitive) -> int:
    plaintext = primitive.input_ports.get("plaintext")
    if (
        primitive.family_name != "speck"
        or len(primitive.rounds) != 4
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

    components = primitive.rounds[round_number].components
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
