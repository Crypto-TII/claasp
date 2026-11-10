"""Original labels survive shared unchanged observations in sliced graphs."""

from types import SimpleNamespace

from claasp.representations.constraints.sat._impossible_observations import _round_labels


def test_multiple_original_boundaries_can_refer_to_the_same_retained_state():
    def graph(rounds):
        return SimpleNamespace(
            round_output_boundaries=rounds, selection_bit_sources=lambda piece: (("state", 0),)
        )

    original = SimpleNamespace(graph=graph(((0, ("wire",)), (1, ("wire",)), (2, ("wire",)))))
    sliced = SimpleNamespace(
        source_map={"state": "state"}, primitive=SimpleNamespace(graph=graph(((0, ("wire",)),)))
    )
    assert _round_labels(original, sliced, start=0, stop=3) == {0: (1, 2, 3)}
