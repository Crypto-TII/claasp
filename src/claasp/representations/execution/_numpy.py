"""Sample-parallel execution for empirical binary analyses (NumPy is optional)."""

from functools import reduce
from typing import Any

from claasp.representations.execution.scalar import ScalarExecutionDriver


def _evaluate_samples(primitive, inputs, outputs):
    """Return bit arrays for selected outputs, vectorizing supported word operations.

    Unsupported operations use the scalar component handler per lane, preserving
    its semantics. Structural bindings are resolved directly on sample arrays.
    """
    import numpy as np

    from claasp.components.structural import Constant, Identity, Permutation
    from claasp.components.word import (
        BitwiseAnd,
        BitwiseNot,
        BitwiseOr,
        ModularAdd,
        ModularSubtract,
        Rotate,
        Shift,
        Xor,
    )

    size = len(next(iter(inputs.values())))
    values = {}
    for name, array in primitive.graph.input_arrays.items():
        width = array.array_type.unit_type.encoded_bit_size
        mask = (1 << width) - 1
        dtype = np.uint64 if width <= 64 else object
        values[name] = tuple(
            np.array([(value >> (width * position)) & mask for value in inputs[name]], dtype=dtype)
            for position in reversed(range(array.array_type.unit_count))
        )
    bindings = {binding.output.source_id: binding for binding in primitive.graph.bindings}
    cache = {}

    def select(selection):
        source_id = selection.source.source_id
        if source_id not in values and source_id not in cache:
            binding = bindings[source_id]
            operands = tuple(select(item) for item in binding.inputs)
            kind = binding.kind.value
            if kind == "join":
                value = tuple(unit for operand in operands for unit in operand)
            elif kind == "view":
                value = operands[0]
            elif kind == "unpack_bits":
                value = tuple(
                    (unit >> bit) & 1
                    for unit in operands[0]
                    for bit in reversed(range(binding.word_width))
                )
            elif kind == "pack_bits":
                width = binding.word_width
                value = tuple(
                    sum(
                        bit << (width - index - 1)
                        for index, bit in enumerate(operands[0][start : start + width])
                    )
                    for start in range(0, len(operands[0]), width)
                )
            else:
                raise NotImplementedError(f"unknown binding {kind}")
            cache[source_id] = value
        source = values[source_id] if source_id in values else cache[source_id]
        return tuple(source[position] for position in selection.positions)

    scalar = ScalarExecutionDriver()
    hybrid = False
    for component in primitive.graph.components:
        operands = tuple(select(item) for item in component.inputs)
        kind = type(component)
        width = component.output_type.unit_type.encoded_bit_size
        mask = (1 << width) - 1 if width is not None else None
        dtype = np.uint64 if width is not None and width <= 64 else object
        if kind is Constant:
            output = tuple(np.full(size, value, dtype=dtype) for value in component.values)
        elif kind is Identity:
            output = operands[0]
        elif kind is Permutation:
            output = tuple(operands[0][position] for position in component.mapping)
        elif kind in (Xor, BitwiseAnd, BitwiseOr, ModularAdd, ModularSubtract):
            operation = {
                Xor: np.bitwise_xor,
                BitwiseAnd: np.bitwise_and,
                BitwiseOr: np.bitwise_or,
                ModularAdd: np.add,
                ModularSubtract: np.subtract,
            }[kind]
            # A non-power-of-two modulus must not overflow a machine word.
            if kind is ModularAdd and component.modulus is not None:
                output = tuple(
                    sum(item.astype(object) for item in column) % component.modulus
                    for column in zip(*operands)
                )
            else:
                with np.errstate(over="ignore"):
                    output = tuple(reduce(operation, column) & mask for column in zip(*operands))
        elif kind is BitwiseNot:
            output = tuple((~unit) & mask for unit in operands[0])
        elif kind in (Rotate, Shift):
            amount = component.amount
            if kind is Shift:
                output = tuple(
                    ((unit << amount) & mask if component.direction == "left" else unit >> amount)
                    if amount < width
                    else np.zeros_like(unit)
                    for unit in operands[0]
                )
            elif component.direction == "left":
                output = tuple(
                    ((unit << amount) | (unit >> (width - amount))) & mask for unit in operands[0]
                )
            else:
                output = tuple(
                    ((unit >> amount) | (unit << (width - amount))) & mask for unit in operands[0]
                )
        else:
            hybrid = True
            try:
                handler = scalar._handlers[kind]
            except KeyError as error:
                raise NotImplementedError(
                    f"NumPy execution does not support {kind.__name__}"
                ) from error
            lanes = [
                tuple(
                    handler(
                        component,
                        tuple(tuple(int(unit[lane]) for unit in operand) for operand in operands),
                    )
                )
                for lane in range(size)
            ]
            output = tuple(np.array(column, dtype=dtype) for column in zip(*lanes))
        values[component.component_id] = output

    result = []
    for selections in outputs:
        bits: list[Any] = []
        for selection in selections:
            width = selection.array_type.unit_type.encoded_bit_size
            bits.extend(
                (unit >> bit) & 1 for unit in select(selection) for bit in reversed(range(width))
            )
        result.append(np.asarray(bits, dtype=np.uint8))
    return result, hybrid
