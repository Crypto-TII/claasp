import pytest

from claasp_next import Cipher, ScalarEvaluator, ValueType, Word
from claasp_next.components import ModularAdd, Rotate, Xor


def test_word_operations_wrap_and_rotate():
    value_type = ValueType(Word(8), (1,))
    cipher = Cipher("word_operations", {"left": value_type, "right": value_type})
    cipher.add_round()
    added = cipher.add_component(ModularAdd(
        "add", (cipher.input("left").select_all(), cipher.input("right").select_all())
    ))
    rotated = cipher.add_component(Rotate("rotate", added.select_all(), 3, "left"))
    output = cipher.add_component(Xor(
        "xor", (rotated.select_all(), cipher.input("right").select_all())
    ))
    cipher.set_output(output.select_all())

    assert ScalarEvaluator().evaluate(cipher, {"left": (250,), "right": (10,)}).output == (42,)


def test_word_rejects_noncanonical_values():
    with pytest.raises(ValueError, match="canonical element"):
        Word(8).validate(256)
