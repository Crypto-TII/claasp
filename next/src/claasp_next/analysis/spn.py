"""Exact small-round SPN trail search over typed cipher graphs."""

from math import inf

from claasp_next.analysis.trails import (
    SBoxTransitionSemantics,
    Trail,
    TrailKind,
    TrailSearchResult,
    TrailStep,
    XorDifference,
)
from claasp_next.components import BitVectorSBox, Permutation
from claasp_next.core import Cipher
from claasp_next.domains import Bit


def find_two_round_spn_xor_differential(cipher: Cipher) -> TrailSearchResult:
    """Find an exact nonzero two-round XOR-differential SPN trail.

    The current reviewed slice accepts the two-round PRESENT graph. It derives
    its S-box and permutation from graph components, fixes the key difference
    to zero, and proves optimality when the constructed trail meets the
    nonzero-transition lower bound for both substitution layers.
    """

    _validate_present_slice(cipher)
    first_sboxes = _round_sboxes(cipher, 1)
    second_sboxes = _round_sboxes(cipher, 2)
    first_permutation = _component(cipher, "p_layer_1", Permutation)
    second_permutation = _component(cipher, "p_layer_2", Permutation)
    semantics = SBoxTransitionSemantics(first_sboxes[0].table)
    width = cipher.input("plaintext").value_type.unit_count
    nibble_count = width // semantics.width
    transitions = {
        difference: tuple(
            transition
            for output in range(1 << semantics.width)
            if (
                transition := semantics.xor_differential(difference, output)
            ).is_possible
        )
        for difference in range(1 << semantics.width)
    }
    minimum_nonzero_weight = min(
        transition.weight
        for difference, choices in transitions.items()
        if difference
        for transition in choices
    )

    best = None
    for active_nibble in range(nibble_count):
        for input_difference in range(1, 1 << semantics.width):
            for first_transition in transitions[input_difference]:
                first_output = first_transition.output_pattern.value << (
                    semantics.width * (nibble_count - 1 - active_nibble)
                )
                second_input = _permute(first_output, width, first_permutation.mapping)
                second_steps = []
                second_output = 0
                for nibble in range(nibble_count):
                    shift = semantics.width * (nibble_count - 1 - nibble)
                    difference = (second_input >> shift) & ((1 << semantics.width) - 1)
                    transition = min(
                        transitions[difference],
                        key=lambda item: (item.weight, item.output_pattern.value),
                    )
                    second_steps.append(TrailStep(second_sboxes[nibble].component_id, transition))
                    second_output |= transition.output_pattern.value << shift
                final_output = _permute(second_output, width, second_permutation.mapping)
                input_pattern = input_difference << (
                    semantics.width * (nibble_count - 1 - active_nibble)
                )
                steps = (
                    TrailStep(first_sboxes[active_nibble].component_id, first_transition),
                    *second_steps,
                )
                candidate = Trail(
                    TrailKind.XOR_DIFFERENTIAL,
                    XorDifference(input_pattern, width),
                    XorDifference(final_output, width),
                    steps,
                )
                ordering = (
                    candidate.total_weight,
                    candidate.input_pattern.value,
                    candidate.output_pattern.value,
                )
                if best is None or ordering < best[0]:
                    best = (ordering, candidate)

    if best is None or best[1].total_weight == inf:
        raise RuntimeError("no nonzero SPN trail was found")
    active_second_layer = sum(
        step.transition.input_pattern.value != 0 for step in best[1].steps[1:]
    )
    lower_bound = minimum_nonzero_weight * (1 + active_second_layer)
    return TrailSearchResult(
        best[1],
        lower_bound,
        "legacy CLAASP MilpXorDifferentialModel PRESENT-2 regression",
    )


def check_spn_trail(cipher: Cipher, trail: Trail) -> bool:
    """Independently recompute transitions and SPN wiring in ``trail``."""

    components = {component.component_id: component for component in cipher.components}
    for step in trail.steps:
        component = components.get(step.component_id)
        if not isinstance(component, BitVectorSBox):
            return False
        if not SBoxTransitionSemantics(component.table).check(step.transition):
            return False
    if len(trail.steps) != 17:
        return False
    first, second = trail.steps[0], trail.steps[1:]
    nibble = int(first.component_id.rsplit("_", 1)[1])
    shift = 4 * (15 - nibble)
    if trail.input_pattern.value != first.transition.input_pattern.value << shift:
        return False
    first_output = first.transition.output_pattern.value << shift
    first_permutation = _component(cipher, "p_layer_1", Permutation)
    second_input = _permute(first_output, 64, first_permutation.mapping)
    second_output = 0
    for position, step in enumerate(second):
        shift = 4 * (15 - position)
        if step.transition.input_pattern.value != (second_input >> shift) & 0xF:
            return False
        second_output |= step.transition.output_pattern.value << shift
    final = _permute(
        second_output,
        64,
        _component(cipher, "p_layer_2", Permutation).mapping,
    )
    return final == trail.output_pattern.value


def _validate_present_slice(cipher: Cipher) -> None:
    plaintext = cipher.inputs.get("plaintext")
    key = cipher.inputs.get("key")
    if (
        cipher.family_name != "present"
        or len(cipher.rounds) != 2
        or plaintext is None
        or key is None
        or not isinstance(plaintext.value_type.domain, Bit)
        or plaintext.value_type.unit_count != 64
    ):
        raise NotImplementedError(
            "the reviewed SPN search slice currently supports two-round PRESENT"
        )


def _round_sboxes(cipher: Cipher, round_number: int) -> tuple[BitVectorSBox, ...]:
    prefix = f"sbox_{round_number}_"
    result = tuple(
        component
        for component in cipher.components
        if isinstance(component, BitVectorSBox) and component.component_id.startswith(prefix)
    )
    if len(result) != 16:
        raise ValueError(f"PRESENT round {round_number} must contain 16 state S-boxes")
    return result


def _component(cipher: Cipher, component_id: str, expected_type):
    component = next(
        (item for item in cipher.components if item.component_id == component_id), None
    )
    if not isinstance(component, expected_type):
        raise ValueError(f"cipher is missing {component_id!r} {expected_type.__name__}")
    return component


def _permute(value: int, width: int, mapping: tuple[int, ...]) -> int:
    output = 0
    for output_position, input_position in enumerate(mapping):
        bit = (value >> (width - 1 - input_position)) & 1
        output |= bit << (width - 1 - output_position)
    return output
