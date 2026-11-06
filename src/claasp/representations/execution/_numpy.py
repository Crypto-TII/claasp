"""Sample-parallel execution for empirical binary analyses (NumPy is optional)."""

from functools import reduce
from typing import Any

from claasp.graph import GraphPropagation
from claasp.graph.propagation import resolve_selection
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

    def select(selection, values, cache):
        return resolve_selection(
            selection,
            values,
            bindings,
            cache,
            pack=lambda group, width: sum(
                bit << (width - index - 1) for index, bit in enumerate(group)
            ),
            unpack=lambda unit, width: tuple((unit >> bit) & 1 for bit in reversed(range(width))),
        )

    scalar = ScalarExecutionDriver()
    hybrid = False

    def rule(component, operands):
        nonlocal hybrid
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
        return output

    propagated = GraphPropagation(primitive).run(values, rule, select=select)
    values, cache = propagated.values, propagated.bindings

    result = []
    for selections in outputs:
        bits: list[Any] = []
        for selection in selections:
            width = selection.array_type.unit_type.encoded_bit_size
            bits.extend(
                (unit >> bit) & 1
                for unit in select(selection, values, cache)
                for bit in reversed(range(width))
            )
        result.append(np.asarray(bits, dtype=np.uint8))
    return result, hybrid
