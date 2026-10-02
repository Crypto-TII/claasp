"""Whole-graph monomial-transition composition tests."""

from claasp.analysis import PresentMonomialSemantics, PresentRoundMonomialSemantics
from claasp.primitives import Present


def _permuted_mask(mapping, before_permutation):
    source = tuple((before_permutation >> (63 - index)) & 1 for index in range(64))
    result = 0
    for input_position in mapping:
        result = (result << 1) | source[input_position]
    return result


def test_present_round_composes_sbox_monomials_and_graph_permutation():
    primitive = Present(number_of_rounds=1)
    semantics = PresentRoundMonomialSemantics(primitive)
    local_output = 1
    local_input = min(semantics.tables[0][local_output])
    input_mask = local_input << 60
    before_permutation = local_output << 60
    output_mask = _permuted_mask(semantics.permutation.mapping, before_permutation)

    trail = semantics.trail(input_mask, output_mask)

    assert trail is not None
    assert trail.steps[0].component_id == "sbox_1_0"
    assert trail.steps[0].input_mask == local_input
    assert trail.steps[0].output_mask == local_output
    assert trail.steps[-1].component_id == "p_layer_1"
    assert semantics.check(trail)


def test_present_round_rejects_an_impossible_local_transition():
    primitive = Present(number_of_rounds=1)
    semantics = PresentRoundMonomialSemantics(primitive)
    local_output = 1
    impossible = next(mask for mask in range(16) if mask not in semantics.tables[0][local_output])
    output_mask = _permuted_mask(semantics.permutation.mapping, local_output << 60)

    assert semantics.trail(impossible << 60, output_mask) is None


def test_present_multi_round_predecessor_is_independently_checked():
    primitive = Present(number_of_rounds=3)
    semantics = PresentMonomialSemantics(primitive)

    trail = semantics.predecessor_trail(1)

    assert len(trail.rounds) == 3
    assert trail.rounds[0].input_mask == trail.input_mask
    assert trail.rounds[-1].output_mask == 1
    assert semantics.check(trail)
