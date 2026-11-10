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


def test_complete_word_aliases_preserve_known_values_and_abstract_activity():
    from claasp import Primitive, UnitArrayType
    from claasp.representations.constraints.sat._impossible_observations import _decode_rounds
    from claasp.semantics.cryptanalysis import WordwiseDifferenceKind as Kind
    from claasp.semantics.cryptanalysis import WordwiseXorDifference as Difference
    from claasp.unit_types import Word

    primitive = Primitive("permuted_observation", {"plaintext": UnitArrayType(Word(4), (1,))})
    primitive._builder.add_round()
    bits = primitive._builder.unpack_bits(primitive.graph.input("plaintext"))
    observed = primitive._builder.pack_bits(bits[(2, 3, 0, 1)], 4)
    primitive._builder.set_round_output(observed)
    primitive._builder.set_output(observed)
    for value in range(16):
        source = Difference.known(4, value) if value else Difference(4, Kind.ZERO)
        model = SimpleNamespace(
            primitive=primitive,
            _unit_arrays={"plaintext": ()},
            _decode_words=lambda words, assignment, source=source: (source,),
        )
        decoded = _decode_rounds(model, {}, {0: (1,)}, wordwise=True)[0][1]
        expected = ((value << 2) | (value >> 2)) & 15
        assert decoded == (
            (Difference.known(4, expected) if expected else Difference(4, Kind.ZERO)),
        )
    for kind in (Kind.NONZERO, Kind.UNKNOWN):
        source = Difference(4, kind)
        model = SimpleNamespace(
            primitive=primitive,
            _unit_arrays={"plaintext": ()},
            _decode_words=lambda words, assignment, source=source: (source,),
        )
        assert _decode_rounds(model, {}, {0: (1,)}, wordwise=True)[0][1] == (source,)
