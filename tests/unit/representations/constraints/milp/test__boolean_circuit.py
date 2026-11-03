import pytest

from claasp.primitives import BitVectorSBox, ModularAdd, ModularSubtract, Present, Simon, Speck
from claasp.representations.constraints.milp._boolean_circuit import _boolean_circuit


@pytest.mark.parametrize(
    "primitive",
    [
        ModularAdd(word_bit_size=2),
        ModularSubtract(word_bit_size=2),
        BitVectorSBox(3, [7, 1, 2, 3, 4, 5, 6, 0]),
    ],
)
def test_boolean_circuit_lowering_matches_exhaustive_small_graphs(primitive):
    from itertools import product

    lowered = _boolean_circuit(primitive)
    names = tuple(primitive.graph.input_arrays)
    limits = [
        1 << array.array_type.encoded_bit_size for array in primitive.graph.input_arrays.values()
    ]
    for inputs in product(*(range(limit) for limit in limits)):
        assignment = dict(zip(names, inputs))
        assert lowered.evaluate(**assignment) == primitive.evaluate(**assignment)


@pytest.mark.parametrize(
    "primitive", [Present(number_of_rounds=1), Speck(number_of_rounds=2), Simon(number_of_rounds=2)]
)
def test_boolean_circuit_preserves_real_primitive_wiring(primitive):
    from random import Random

    lowered = _boolean_circuit(primitive)
    rng = Random(9)
    for _ in range(4):
        assignment = {
            name: rng.getrandbits(array.array_type.encoded_bit_size)
            for name, array in primitive.graph.input_arrays.items()
        }
        assert lowered.evaluate(**assignment) == primitive.evaluate(**assignment)


def test_circuit_does_not_invent_semantics_for_generic_word_addition():
    from claasp.primitives import Add
    from claasp.unit_types import Word

    with pytest.raises(NotImplementedError, match="Add requires Bit"):
        _boolean_circuit(Add(unit_type=Word(2)))
