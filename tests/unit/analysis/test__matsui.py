from fractions import Fraction

import pytest

from claasp.analysis._matsui import (
    MatsuiEdge,
    matsui_branch_and_bound,
    modular_add_differences_above,
)
from claasp.analysis._trail_propagation import xor_differential_component_transitions
from claasp.components import BitVectorSBox
from claasp.primitives import DES
from claasp.semantics.cryptanalysis import (
    ModularAddTransitionSemantics,
    SBoxTransitionSemantics,
    Trail,
    TrailKind,
    TrailStep,
    XorDifference,
)


def test_branch_and_bound_matches_complete_two_round_enumeration():
    transitions = {
        (0, "root"): (
            MatsuiEdge("a", Fraction(1, 2), "root-a"),
            MatsuiEdge("b", Fraction(3, 4), "root-b"),
        ),
        (1, "a"): (MatsuiEdge("done", Fraction(1, 2), "a-done"),),
        (1, "b"): (
            MatsuiEdge("done", Fraction(1, 4), "b-low"),
            MatsuiEdge("done", Fraction(1, 2), "b-best"),
        ),
    }

    def successors(round_index, state, strict_minimum):
        return tuple(
            edge for edge in transitions[round_index, state] if edge.probability > strict_minimum
        )

    outcome = matsui_branch_and_bound(
        rounds=2,
        initial_state="root",
        incumbent_probability=Fraction(1, 4),
        incumbent_payload=("seed-0", "seed-1"),
        suffix_probability_bounds=(Fraction(1), Fraction(1), Fraction(1)),
        successors=successors,
    )

    exhaustive = max(
        first.probability * second.probability
        for first in transitions[0, "root"]
        for second in transitions[1, first.state]
    )
    assert outcome.probability == exhaustive == Fraction(3, 8)
    assert outcome.payload == ("root-b", "b-best")
    assert outcome.statistics.incumbent_updates == 1
    assert outcome.statistics.generated_edges == 3


def test_branch_and_bound_rejects_a_non_improving_successor():
    with pytest.raises(ValueError, match="cannot improve"):
        matsui_branch_and_bound(
            rounds=1,
            initial_state=None,
            incumbent_probability=Fraction(1, 2),
            incumbent_payload=("seed",),
            suffix_probability_bounds=(Fraction(1), Fraction(1)),
            successors=lambda *_: (MatsuiEdge(None, Fraction(1, 2), "invalid"),),
        )


@pytest.mark.parametrize("width", range(1, 6))
@pytest.mark.parametrize("threshold", [Fraction(0), Fraction(1, 4), Fraction(1, 2)])
def test_partial_carry_search_matches_complete_modular_addition_ddt(width, threshold):
    semantics = ModularAddTransitionSemantics(width)
    expected = {
        (
            left,
            right,
            transition.output_pattern.value,
            Fraction(transition.numerator, transition.denominator),
        )
        for left in range(1 << width)
        for right in range(1 << width)
        for transition in semantics.possible_transitions(left, right)
        if Fraction(transition.numerator, transition.denominator) > threshold
    }
    actual = {
        (item.left, item.right, item.output, item.probability)
        for item in modular_add_differences_above(width, threshold)
    }

    assert actual == expected


def test_partial_carry_search_honors_fixed_round_inputs():
    transitions = modular_add_differences_above(
        5,
        Fraction(0),
        left=0b10101,
        right=0b00111,
    )

    assert transitions
    assert {(item.left, item.right) for item in transitions} == {(0b10101, 0b00111)}


def test_des_two_round_weight_two_witness_propagates_through_the_full_graph():
    primitive = DES(number_of_rounds=2)
    sboxes = tuple(item for item in primitive.graph.components if isinstance(item, BitVectorSBox))
    active_sbox = sboxes[13]
    assert active_sbox.component_id is not None
    transition = SBoxTransitionSemantics(
        active_sbox.table, output_width=active_sbox.output_bit_size
    ).xor_differential(0x08, 0x06)
    trail = Trail(
        TrailKind.XOR_DIFFERENTIAL,
        XorDifference(0x40000000000, 64),
        XorDifference(0x80100100000, 64),
        (TrailStep(active_sbox.component_id, transition),),
    )

    components = xor_differential_component_transitions(
        primitive,
        trail,
        input_differences={"plaintext": trail.input_pattern.value, "key": 0},
    )

    assert trail.total_weight == 2
    assert tuple(item.local_transition for item in components if item.weight) == (transition,)
