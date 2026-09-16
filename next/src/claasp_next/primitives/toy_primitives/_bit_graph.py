"""Small helpers for authoring bit-oriented teaching primitives."""

from claasp_next.components import (
    BitVectorSBox,
    BitwiseAnd,
    Concatenate,
    Constant,
    PackBits,
    Permutation,
    UnpackBits,
    ModularAdd,
    Shift,
    Xor,
)
from claasp_next.domains import Bit
from claasp_next.encoding import bits_from_int
from claasp_next.graph import PortLike, ValueType, as_selection


def bit_type(width: int) -> ValueType:
    if not isinstance(width, int) or isinstance(width, bool) or width <= 0:
        raise ValueError("bit width must be a positive integer")
    return ValueType(Bit(), (width,))


def concatenate(primitive, selections, *, component_id=None):
    frozen = tuple(as_selection(item) for item in selections)
    if len(frozen) == 1:
        return frozen[0]
    return primitive.add_component(Concatenate(frozen, component_id=component_id))


def xor_bits(primitive, *operands, component_id=None):
    selections = tuple(as_selection(item) for item in operands)
    if len(selections) < 2:
        raise ValueError("bit XOR requires at least two operands")
    width = selections[0].value_type.unit_count
    if any(item.value_type != bit_type(width) for item in selections):
        raise ValueError("bit XOR operands must have the same Bit value type")
    words = tuple(primitive.add_component(PackBits(item, width)) for item in selections)
    output = primitive.add_component(Xor(words, component_id=component_id))
    return primitive.add_component(UnpackBits(output))


def and_bits(primitive, *operands, component_id=None):
    selections = tuple(as_selection(item) for item in operands)
    width = selections[0].value_type.unit_count
    if len(selections) < 2 or any(item.value_type != bit_type(width) for item in selections):
        raise ValueError("bit AND operands must have the same Bit value type")
    words = tuple(primitive.add_component(PackBits(item, width)) for item in selections)
    output = primitive.add_component(BitwiseAnd(words, component_id=component_id))
    return primitive.add_component(UnpackBits(output))


def modular_add_bits(primitive, *operands, component_id=None):
    selections = tuple(as_selection(item) for item in operands)
    width = selections[0].value_type.unit_count
    if len(selections) < 2 or any(item.value_type != bit_type(width) for item in selections):
        raise ValueError("modular-add operands must have the same Bit value type")
    words = tuple(primitive.add_component(PackBits(item, width)) for item in selections)
    output = primitive.add_component(ModularAdd(words, component_id=component_id))
    return primitive.add_component(UnpackBits(output))


def shift_bits(primitive, source: PortLike, amount: int, *, component_id=None):
    source = as_selection(source)
    width = source.value_type.unit_count
    word = primitive.add_component(PackBits(source, width))
    direction = "right" if amount >= 0 else "left"
    output = primitive.add_component(Shift(word, abs(amount), direction, component_id=component_id))
    return primitive.add_component(UnpackBits(output))


def constant_bits(primitive, width: int, value: int, *, component_id=None):
    return primitive.add_component(Constant(bit_type(width), bits_from_int(value, width), component_id=component_id))


def sbox_layer(primitive, source: PortLike, table, *, component_id_prefix="sbox"):
    source = as_selection(source)
    width = (len(table)).bit_length() - 1
    if 1 << width != len(table) or source.value_type.unit_count % width:
        raise ValueError("S-box table and input width are incompatible")
    outputs = []
    for index in range(source.value_type.unit_count // width):
        chunk = source[tuple(range(index * width, (index + 1) * width))]
        outputs.append(primitive.add_component(BitVectorSBox(
            chunk, table, component_id=f"{component_id_prefix}_{index}"
        )))
    return concatenate(primitive, outputs)


def rotate_bits(primitive, source: PortLike, amount: int, *, component_id=None):
    source = as_selection(source)
    width = source.value_type.unit_count
    mapping = tuple((index - amount) % width for index in range(width))
    return primitive.add_component(Permutation(source, mapping, component_id=component_id))


def permute_bits(primitive, source: PortLike, destination_by_source, *, component_id=None):
    source = as_selection(source)
    description = tuple(destination_by_source)
    if sorted(description) != list(range(source.value_type.unit_count)):
        raise ValueError("bit permutation must contain every destination exactly once")
    mapping = tuple(description.index(destination) for destination in range(len(description)))
    return primitive.add_component(Permutation(source, mapping, component_id=component_id))
