"""Concise helpers for typed word-oriented primitive graphs."""

from claasp.components import (
    BitwiseAnd,
    Constant,
    IDEAMultiply,
    ModularAdd,
    ModularMultiply,
    ModularSubtract,
    Permutation,
    Rotate,
    Shift,
    VariableRotate,
    VariableShift,
    Xor,
)
from claasp.domains import Word
from claasp.graph import ValueType, as_selection


def word_type(width, count=1):
    return ValueType(Word(width), (count,))


def select(source, index):
    return as_selection(source)[index]


def concatenate(primitive, *items, component_id=None):
    del component_id
    return primitive.join(*items)


def constant(primitive, width, value, component_id=None):
    return primitive.add_component(
        Constant(word_type(width), (value & ((1 << width) - 1),), component_id)
    )


def add(primitive, *items, component_id=None):
    return primitive.add_component(ModularAdd(items, component_id=component_id))


def subtract(primitive, *items, component_id=None):
    return primitive.add_component(ModularSubtract(items, component_id=component_id))


def multiply(primitive, *items, modulus=None, component_id=None):
    return primitive.add_component(
        ModularMultiply(items, modulus=modulus, component_id=component_id)
    )


def idea_multiply(primitive, *items, component_id=None):
    return primitive.add_component(IDEAMultiply(items, component_id=component_id))


def xor(primitive, *items, component_id=None):
    return primitive.add_component(Xor(items, component_id=component_id))


def bit_and(primitive, *items, component_id=None):
    return primitive.add_component(BitwiseAnd(items, component_id=component_id))


def rotate(primitive, item, amount, component_id=None):
    direction = "right" if amount >= 0 else "left"
    return primitive.add_component(Rotate(item, abs(amount), direction, component_id=component_id))


def shift(primitive, item, amount, component_id=None):
    direction = "right" if amount >= 0 else "left"
    return primitive.add_component(Shift(item, abs(amount), direction, component_id=component_id))


def variable_rotate(primitive, item, amount, *, left=True, component_id=None):
    return primitive.add_component(
        VariableRotate(item, amount, "left" if left else "right", component_id=component_id)
    )


def variable_shift(primitive, item, amount, *, left=True, component_id=None):
    return primitive.add_component(
        VariableShift(item, amount, "left" if left else "right", component_id=component_id)
    )


def byte_swap(primitive, item, width):
    if width % 8:
        raise ValueError("byte swapping requires a byte-aligned word")
    bits = primitive.unpack_bits(item)
    byte_count = width // 8
    mapping = tuple(byte * 8 + bit for byte in reversed(range(byte_count)) for bit in range(8))
    permuted = primitive.add_component(Permutation(bits, mapping))
    return primitive.pack_bits(permuted, width)


def low_bits(primitive, item, count):
    bits = primitive.unpack_bits(item)
    return primitive.pack_bits(
        bits[tuple(range(bits.value_type.unit_count - count, bits.value_type.unit_count))], count
    )


def split_word(primitive, item, part_width):
    bits = primitive.unpack_bits(item)
    return primitive.pack_bits(bits, part_width)


def join_words(primitive, items, width):
    joined = concatenate(primitive, *items)
    return primitive.pack_bits(primitive.unpack_bits(joined), width)
