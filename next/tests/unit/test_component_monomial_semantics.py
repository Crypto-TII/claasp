"""Generic local component monomial semantics."""

from claasp_next.primitives import Present
from claasp_next.semantics.cryptanalysis import ComponentMonomialSemantics


def _component(primitive, component_id):
    return next(component for component in primitive.components if component.component_id == component_id)


def test_sbox_and_permutation_semantics_are_selected_from_typed_components():
    primitive = Present(number_of_rounds=1)
    sbox = _component(primitive, "sbox_1_0")
    permutation = _component(primitive, "p_layer_1")

    assert ComponentMonomialSemantics.is_possible(sbox, (1,), 1)
    assert not ComponentMonomialSemantics.is_possible(sbox, (0,), 1)
    permutation_input = ComponentMonomialSemantics._permutation_input(permutation, 1)
    assert ComponentMonomialSemantics.is_possible(permutation, (permutation_input,), 1)


def test_boolean_addition_partitions_selected_output_variables_between_inputs():
    primitive = Present(number_of_rounds=1)
    addition = _component(primitive, "add_round_key_1")

    assert ComponentMonomialSemantics.is_possible(addition, (0b1001, 0b0110), 0b1111)
    assert ComponentMonomialSemantics.is_possible(addition, (0b1111, 0), 0b1111)
    assert not ComponentMonomialSemantics.is_possible(addition, (0b1001, 0b1000), 0b1001)


def test_concatenation_and_constants_have_exact_structural_semantics():
    primitive = Present(number_of_rounds=1)
    concatenation = _component(primitive, "sbox_layer_1")
    counter = _component(primitive, "key_counter_1")

    masks = (1,) + (0,) * 15
    assert ComponentMonomialSemantics.is_possible(concatenation, masks, 1 << 60)
    assert not ComponentMonomialSemantics.is_possible(concatenation, masks, 1)
    assert ComponentMonomialSemantics.is_possible(counter, (), 1)
    assert not ComponentMonomialSemantics.is_possible(counter, (), 2)
