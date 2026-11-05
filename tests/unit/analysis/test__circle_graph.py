"""Graph-derived circle models checked against independent concrete round tables."""

from fractions import Fraction

import pytest

from claasp import Primitive, UnitArrayType
from claasp.components import Constant, Permutation, Rotate, SBox, Xor
from claasp.primitives import Craft
from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace
from claasp.semantics.cryptanalysis.circle_linear import CircleLookupLayer
from claasp.unit_types import Word


def _evaluate(primitive, **inputs):
    value = primitive.evaluate(**inputs)
    assert isinstance(value, int)
    return value


SBOX = (12, 10, 13, 3, 14, 11, 15, 7, 8, 9, 1, 5, 0, 2, 4, 6)


def _spn(rounds=3, *, offset=0, constant=1, permutation=(1, 0), diffuse=True):
    state_type = UnitArrayType(Word(4), (2,))
    primitive = Primitive(
        "unnamed_test_spn", {"plaintext": state_type, "key": state_type, "tweak": state_type}
    )
    b = primitive._builder
    state, key, tweak = (primitive.graph.input(name) for name in ("plaintext", "key", "tweak"))
    for r in range(offset, offset + rounds):
        b.add_round()
        rk = b.add_component(Rotate(key, r % 4, "left"))
        rc = b.add_component(Constant(state_type, (constant, r % 16)))
        left = b.add_component(Xor((state[0], state[1]))) if diffuse else state[0]
        mixed = b.join(left, state[1])
        state = b.add_component(Xor((mixed, rk, tweak, rc)))
        state = b.add_component(Permutation(state, permutation))
        state = b.add_component(SBox(state, SBOX))
        b.set_round_output(state)
    b.set_output(state)
    return primitive


def _model(primitive, tweak=0x12):
    return primitive.analysis.circle_linear_model(
        bibrace=BinaryBibrace.craft(), fixed_inputs={"tweak": tweak}
    )


def test_graph_derived_model_has_no_primitive_name_dependency_and_matches_real_round_tables():
    primitive = _spn()
    model = _model(primitive)
    # Use actual graph evaluation rather than the extracted affine maps to
    # independently construct each complete round's coefficient table.
    for key in (0, 0x5A, 0xF3):
        rounds = tuple(
            CircleLookupLayer(
                model.basis,
                model.basis,
                tuple(
                    _evaluate(_spn(1, offset=r), plaintext=x, key=key, tweak=0x12)
                    for x in range(256)
                ),
            )
            for r in range(3)
        )
        for code in range(1, 16):
            trail = model.trail(code)
            output = trail.output_mask
            product = Fraction(1)
            for affine, whole_round in zip(trail._affine_steps, reversed(rounds)):
                product *= whole_round.coefficient(affine.input_mask, output)
                output = affine.input_mask
            assert output == trail.input_mask
            assert trail.contribution(key) == product


def test_graph_edits_change_extracted_diffusion_permutation_and_affine_offsets():
    base = _model(_spn())
    assert _model(_spn(diffuse=False)).diffusion_rows != base.diffusion_rows
    assert _model(_spn(permutation=(0, 1))).permutation != base.permutation
    assert _model(_spn(constant=2)).affine_layers[0].offset != base.affine_layers[0].offset
    assert _model(_spn(), tweak=0x13).affine_layers[0].offset != base.affine_layers[0].offset
    assert base.affine_layers[0].key_rows != base.affine_layers[1].key_rows


def test_craft_convenience_method_delegates_to_graph_extraction(monkeypatch):
    primitive = Craft(number_of_rounds=8)
    from claasp.analysis import _circle_graph

    expected = object()
    calls = []

    def extract(actual, brace, **options):
        calls.append((actual, brace, options))
        return expected

    monkeypatch.setattr(_circle_graph, "subgroup_model_from_graph", extract)
    assert primitive.circle_linear_model(tweak=7) is expected
    assert calls[0][0] is primitive
    assert calls[0][2] == {"input_name": "plaintext", "fixed_inputs": {"tweak": 7}}


def test_graph_adapter_checks_fixed_inputs_and_non_affine_key_schedules():
    with pytest.raises(ValueError, match="fixed_inputs"):
        _spn().analysis.circle_linear_model(bibrace=BinaryBibrace.craft())
    with pytest.raises(ValueError, match="public"):
        _spn().analysis.circle_linear_model(bibrace=BinaryBibrace.craft(), input_name="key")
    primitive = _spn(1)
    # An S-box in the key schedule is not an affine master-key map.
    b = primitive._builder
    b.add_component(SBox(primitive.graph.input("key"), SBOX))
    with pytest.raises(ValueError, match="parallel S-box layer"):
        _model(primitive)


def test_graph_adapter_accepts_parallel_bit_sboxes_and_structural_cell_conversion():
    from claasp.components import BitVectorSBox
    from claasp.unit_types import Bit

    primitive = Primitive("bit_spn", {"plaintext": UnitArrayType(Bit(), (8,))})
    b = primitive._builder
    b.add_round()
    x = primitive.graph.input("plaintext")
    left = b.add_component(Xor((x[:4], x[4:])))
    state = b.join(left, x[4:])
    outputs = tuple(
        b.add_component(BitVectorSBox(state[4 * i : 4 * (i + 1)], SBOX)) for i in range(2)
    )
    out = b.join(*outputs)
    b.set_round_output(out)
    b.set_output(out)
    model = primitive.analysis.circle_linear_model(bibrace=BinaryBibrace.craft())
    whole = CircleLookupLayer(
        model.basis, model.basis, tuple(_evaluate(primitive, plaintext=x) for x in range(256))
    )
    for code in range(1, 16):
        trail = model.trail(code)
        assert trail.contribution(0) == whole.coefficient(trail.input_mask, trail.output_mask)


def test_retained_round_masks_magnitudes_and_key_dependent_signs_reproduce_trail():
    model = Craft(number_of_rounds=8).circle_linear_model()
    trail = model.trail(0x01190000)
    assert len(trail.round_transitions) == 8
    assert trail.round_transitions[0].input_mask == trail.input_mask
    assert trail.round_transitions[-1].output_mask == trail.output_mask
    magnitude = Fraction(1)
    for a, b in zip(trail.round_transitions, trail.round_transitions[1:]):
        assert a.output_mask == b.input_mask
    for step in trail.round_transitions:
        magnitude *= step.magnitude
    assert magnitude == Fraction(1, 1 << trail.cost)
    for key in (0, 1, 0x123456789ABCDEF0123456789ABCDEF0):
        coefficient = Fraction(1)
        for step in trail.round_transitions:
            coefficient *= step.sbox_sign * step.affine.coefficient(key)
        assert coefficient == trail.contribution(key)
