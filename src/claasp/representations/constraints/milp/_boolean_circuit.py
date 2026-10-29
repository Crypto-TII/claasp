"""Polynomial-size Boolean circuit lowering for monomial-path analysis."""

from claasp import Primitive, UnitArrayType
from claasp.components import (
    Add,
    BitVectorSBox,
    BitwiseAnd,
    BitwiseNot,
    BitwiseOr,
    Constant,
    Identity,
    ModularAdd,
    ModularSubtract,
    Multiply,
    Permutation,
    Rotate,
    SBox,
    Shift,
    Xor,
)
from claasp.graph import as_selection
from claasp.representations.constraints.polynomial import anf_from_truth_table
from claasp.unit_types import Bit, Word


def _boolean_circuit(primitive):
    domains = [array.array_type for array in primitive.graph.input_arrays.values()] + [
        component.output_type for component in primitive.graph.components
    ]
    if any(not isinstance(array.unit_type, (Bit, Word)) for array in domains):
        raise NotImplementedError("Boolean monomial circuits require Bit or Word units")
    derived = Primitive(
        primitive.family_name + "_boolean",
        {
            name: UnitArrayType(Word(1), (array.array_type.encoded_bit_size,))
            for name, array in primitive.graph.input_arrays.items()
        },
    )
    derived._builder.add_round()
    values = {
        name: tuple(
            derived.graph.input(name)[bit] for bit in range(array.array_type.encoded_bit_size)
        )
        for name, array in primitive.graph.input_arrays.items()
    }
    constants, gates = {}, {}

    def constant(value):
        if value not in constants:
            constants[value] = derived._builder.add_component(
                Constant(UnitArrayType(Word(1), (1,)), (value,))
            )
        return constants[value]

    def gate(kind, operands):
        if len(operands) == 1:
            return operands[0]
        selected = tuple(as_selection(operand) for operand in operands)
        key = (kind, tuple((operand.source.source_id, operand.positions) for operand in selected))
        if key not in gates:
            gates[key] = derived._builder.add_component(
                (Xor if kind == "xor" else BitwiseAnd)(tuple(operands))
            )
        return gates[key]

    def add_words(left, right, subtract=False):
        carry, output = constant(int(subtract)), []
        for a, raw_b in zip(reversed(left), reversed(right)):
            b = gate("xor", (raw_b, constant(1))) if subtract else raw_b
            output.append(gate("xor", (a, b, carry)))
            carry = gate(
                "xor", (gate("and", (a, b)), gate("and", (a, carry)), gate("and", (b, carry)))
            )
        return tuple(reversed(output))

    for component in primitive.graph.components:
        operands = tuple(
            tuple(
                values[name][bit] for name, bit in primitive.graph.selection_bit_sources(selection)
            )
            for selection in component.inputs
        )
        unit_type = component.output_type.unit_type
        assert isinstance(unit_type, (Bit, Word))
        width = 1 if isinstance(unit_type, Bit) else unit_type.width
        if isinstance(component, Constant):
            output = tuple(
                constant((value >> bit) & 1)
                for value in component.values
                for bit in reversed(range(width))
            )
        elif isinstance(component, Identity):
            output = operands[0]
        elif isinstance(component, Permutation):
            output = tuple(
                operands[0][index * width + bit]
                for index in component.mapping
                for bit in range(width)
            )
        elif isinstance(component, (Rotate, Shift)):
            shifted_output = []
            for start in range(0, len(operands[0]), width):
                word = operands[0][start : start + width]
                for bit in range(width):
                    source = (
                        bit + component.amount
                        if component.direction == "left"
                        else bit - component.amount
                    )
                    shifted_output.append(
                        word[source % width]
                        if isinstance(component, Rotate)
                        else (word[source] if 0 <= source < width else constant(0))
                    )
            output = tuple(shifted_output)
        elif isinstance(component, BitwiseNot):
            output = tuple(gate("xor", (bit, constant(1))) for bit in operands[0])
        elif isinstance(
            component, (Xor, BitwiseAnd, BitwiseOr, Add, Multiply, ModularAdd, ModularSubtract)
        ):
            if isinstance(component, (ModularAdd, ModularSubtract)) or (
                isinstance(component, Add) and isinstance(component.output_type.unit_type, Word)
            ):
                output = operands[0]
                for right in operands[1:]:
                    output = tuple(
                        bit
                        for start in range(0, len(output), width)
                        for bit in add_words(
                            output[start : start + width],
                            right[start : start + width],
                            isinstance(component, ModularSubtract),
                        )
                    )
            elif isinstance(component, BitwiseOr):
                output = operands[0]
                for right in operands[1:]:
                    output = tuple(
                        gate("xor", (a, b, gate("and", (a, b)))) for a, b in zip(output, right)
                    )
            else:
                if isinstance(component, Multiply) and not isinstance(
                    component.output_type.unit_type, Bit
                ):
                    raise NotImplementedError("monomial Multiply currently requires Bit units")
                kind = "and" if isinstance(component, (BitwiseAnd, Multiply)) else "xor"
                output = tuple(gate(kind, bits) for bits in zip(*operands))
        elif isinstance(component, (SBox, BitVectorSBox)):
            input_width = (
                len(operands[0])
                if isinstance(component, BitVectorSBox)
                else component.inputs[0].array_type.unit_type.encoded_bit_size
            )
            output_width = (
                component.output_bit_size if isinstance(component, BitVectorSBox) else width
            )
            assert input_width is not None
            if input_width > 8:
                raise NotImplementedError(
                    "monomial lookup lowering supports at most eight input bits"
                )
            sbox_output = []
            for start in range(0, len(operands[0]), input_width):
                for bit in reversed(range(output_width)):
                    polynomial = anf_from_truth_table(
                        tuple((value >> bit) & 1 for value in component.table)
                    )
                    terms = tuple(
                        gate(
                            "and",
                            tuple(
                                operands[0][start + int(name[1:])] for name in monomial.variables
                            ),
                        )
                        if monomial.variables
                        else constant(1)
                        for monomial in polynomial.monomials
                    )
                    sbox_output.append(gate("xor", terms) if terms else constant(0))
            output = tuple(sbox_output)
        else:
            raise NotImplementedError(
                f"monomial circuit does not support {type(component).__name__}"
            )
        values[component.component_id] = tuple(output)
    selected = tuple(
        values[name][bit]
        for name, bit in primitive.graph.selection_bit_sources(primitive.graph.output)
    )
    derived._builder.set_output(derived._builder.join(*selected))
    return derived
