from claasp_next import ChaChaQuarterRound, ParallelSBoxLayer
from claasp_next.domains import Word
from claasp_next.representations.constraints.sat import BooleanCNFModel


def test_parallel_sbox_layer_handles_different_box_widths_and_counts():
    nibble = ParallelSBoxLayer((0xC, 5, 6, 0xB, 9, 0, 0xA, 0xD, 3, 0xE, 0xF, 8, 4, 7, 1, 2), 2)
    byte = ParallelSBoxLayer(tuple(value ^ 0xA5 for value in range(256)), 3, domain=Word(8))

    assert nibble.evaluate(0x0F) == 0xC2
    assert byte.evaluate(0x001122) == 0xA5B487
    assert len(nibble.rounds[0]) == 3
    assert len(byte.rounds[0]) == 4


def test_parallel_bit_sbox_scope_generates_constraints_and_a_valid_witness():
    layer = ParallelSBoxLayer((0, 2, 3, 1), 2)
    primitive = layer.as_primitive()
    evaluation = primitive.evaluate_with_trace(0b0111)
    model = BooleanCNFModel(primitive)
    formula = model.cnf_formula()

    assert primitive.evaluate(0b0111) == 0b1001
    assert formula.is_satisfied(model.witness(evaluation))
    assert any(label == "sbox_0" for label in formula.provenance)


def test_chacha_quarter_round_preserves_the_rfc_8439_vector_and_named_outputs():
    quarter_round = ChaChaQuarterRound()
    inputs = (0x11111111, 0x01020304, 0x9B8D6F43, 0x01234567)
    expected = (0xEA2A92F4, 0xCB1CF8CE, 0x4581472E, 0x5881C4BB)

    assert quarter_round.evaluate(*inputs) == int.from_bytes(
        b"".join(value.to_bytes(4, "big") for value in expected), "big"
    )
    for name, value in zip(("a", "b", "c", "d"), expected):
        assert quarter_round.evaluate(*inputs, output=name) == value


def test_composite_block_can_be_instantiated_and_queried_as_a_scope():
    from claasp_next import Primitive, ValueType

    primitive = Primitive("one_quarter_round", {
        name: ValueType(Word(32), (1,)) for name in ("a", "b", "c", "d")
    })
    primitive.add_round()
    scope = primitive.add_composite(
        ChaChaQuarterRound(),
        {name: primitive.input(name) for name in ("a", "b", "c", "d")},
        scope_id="quarter_round",
    )
    primitive.set_output(scope.output())

    assert scope.as_primitive().family_name == "ChaChaQuarterRound"
    assert len(scope.components) == 13
    assert primitive.evaluate(0x11111111, 0x01020304, 0x9B8D6F43, 0x01234567) == \
        0xEA2A92F4CB1CF8CE4581472E5881C4BB
