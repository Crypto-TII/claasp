import pytest

from claasp_next import Primitive, ScalarEvaluator, ValueType, Word
from claasp_next.components import ModularAdd, Rotate, Xor


def test_word_operations_wrap_and_rotate():
    value_type = ValueType(Word(8), (1,))
    primitive = Primitive("word_operations", {"left": value_type, "right": value_type})
    primitive.add_round()
    added = primitive.add_component(
        ModularAdd((primitive.input("left"), primitive.input("right")), component_id="add")
    )
    rotated = primitive.add_component(Rotate(added, 3, "left", component_id="rotate"))
    output = primitive.add_component(Xor((rotated, primitive.input("right")), component_id="xor"))
    primitive.set_output(output)

    assert ScalarEvaluator().evaluate(primitive, {"left": (250,), "right": (10,)}).output == (42,)


def test_word_rejects_noncanonical_values():
    with pytest.raises(ValueError, match="canonical element"):
        Word(8).validate(256)


def test_modular_add_accepts_an_explicit_non_power_of_two_modulus():
    value_type = ValueType(Word(5), (1,))
    primitive = Primitive("explicit_modulus", {"left": value_type, "right": value_type})
    primitive.add_round()
    output = primitive.add_component(
        ModularAdd((primitive.input("left"), primitive.input("right")), modulus=31)
    )
    primitive.set_output(output)

    assert ScalarEvaluator().evaluate(primitive, {"left": (30,), "right": (2,)}).output == (1,)
