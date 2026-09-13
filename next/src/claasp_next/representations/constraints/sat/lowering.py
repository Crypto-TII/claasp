"""Lower typed bit graphs to the Boolean CNF representation."""

from collections.abc import Mapping

from claasp_next.representations.constraints.sat.cnf import CNFFormula
from claasp_next.representations.constraints.sat.encoding import encode_unit, unit_variable_names
from claasp_next.components import (
    Add,
    BitVectorSBox,
    Concatenate,
    Constant,
    Identity,
    ModularAdd,
    Permutation,
    Rotate,
    Xor,
)
from claasp_next.graph import Cipher
from claasp_next.domains import Bit, Word
from claasp_next.representations.execution import EvaluationResult


class BooleanCNFModel:
    """Compile a homogeneous Bit or Word graph to CNF.

    The lowering currently supports constants, wiring components, bitwise
    :class:`~claasp_next.components.Add` (XOR), and
    :class:`~claasp_next.components.BitVectorSBox`. It deliberately owns no
    SAT-solver dependency.
    """

    def __init__(self, cipher: Cipher) -> None:
        if not isinstance(cipher, Cipher):
            raise TypeError("cipher must be a Cipher")
        self.cipher = cipher
        self._auxiliary_definitions: tuple[tuple[str, tuple[str, ...]], ...] = ()
        self._formula: CNFFormula | None = None

    @staticmethod
    def _name(source_id: str, position: int) -> str:
        return f"{source_id}_{position}"

    def cnf_formula(self) -> CNFFormula:
        """Return the deterministic CNF representation, compiling it once."""

        if self._formula is not None:
            return self._formula
        sources = list(self.cipher.inputs.values()) + [component.output for component in self.cipher.components]
        for port in sources:
            if not isinstance(port.value_type.domain, (Bit, Word)):
                raise ValueError(
                    f"Boolean CNF requires the Bit or Word domain; {port.owner_id!r} uses "
                    f"{type(port.value_type.domain).__name__}"
                )
        domains = {type(port.value_type.domain) for port in sources}
        if len(domains) != 1:
            raise ValueError("Boolean CNF requires a homogeneous Bit or Word graph")

        variables = [
            name
            for port in sources
            for position in range(port.value_type.unit_count)
            for name in unit_variable_names(port.owner_id, port.value_type, position)
        ]
        indices = {name: index + 1 for index, name in enumerate(variables)}
        clauses: list[tuple[int, ...]] = []
        provenance: list[str] = []
        auxiliary: list[tuple[str, tuple[str, ...]]] = []

        def allocate(name: str) -> str:
            indices[name] = len(variables) + 1
            variables.append(name)
            return name

        def add_clause(literals: tuple[int, ...], label: str) -> None:
            clauses.append(literals)
            provenance.append(label)

        def equal(output: str, input_: str, label: str) -> None:
            x, y = indices[input_], indices[output]
            add_clause((-x, y), label)
            add_clause((x, -y), label)

        def xor(output: str, left: str, right: str, label: str) -> None:
            a, b, y = indices[left], indices[right], indices[output]
            add_clause((-a, -b, -y), label)
            add_clause((a, b, -y), label)
            add_clause((a, -b, y), label)
            add_clause((-a, b, y), label)

        def majority(output: str, left: str, right: str, carry: str, label: str) -> None:
            a, b, c, y = indices[left], indices[right], indices[carry], indices[output]
            add_clause((-a, -b, y), label)
            add_clause((-a, -c, y), label)
            add_clause((-b, -c, y), label)
            add_clause((a, b, -y), label)
            add_clause((a, c, -y), label)
            add_clause((b, c, -y), label)

        def and_(output: str, left: str, right: str, label: str) -> None:
            a, b, y = indices[left], indices[right], indices[output]
            add_clause((-a, -b, y), label)
            add_clause((a, -y), label)
            add_clause((b, -y), label)

        for component in self.cipher.components:
            label = component.component_id
            outputs = [
                unit_variable_names(label, component.output_type, i)
                for i in range(component.output_type.unit_count)
            ]
            selected = [
                [unit_variable_names(item.source.owner_id, item.source.value_type, position) for position in item.positions]
                for item in component.inputs
            ]
            if isinstance(component, Constant):
                for output, value in zip(outputs, component.values):
                    for bit_name, bit in zip(output, encode_unit(value, component.output_type)):
                        add_clause(((indices[bit_name] if bit else -indices[bit_name]),), label)
            elif isinstance(component, Identity):
                for output, input_ in zip(outputs, selected[0]):
                    for output_bit, input_bit in zip(output, input_):
                        equal(output_bit, input_bit, label)
            elif isinstance(component, Permutation):
                for output, position in zip(outputs, component.mapping):
                    for output_bit, input_bit in zip(output, selected[0][position]):
                        equal(output_bit, input_bit, label)
            elif isinstance(component, Concatenate):
                inputs = [name for group in selected for name in group]
                for output, input_ in zip(outputs, inputs):
                    for output_bit, input_bit in zip(output, input_):
                        equal(output_bit, input_bit, label)
            elif isinstance(component, Add):
                for position, output in enumerate(outputs):
                    operands = [group[position][0] for group in selected]
                    accumulator = operands[0]
                    for operand_number, operand in enumerate(operands[1:], start=1):
                        is_last = operand_number == len(operands) - 1
                        target = output[0] if is_last else f"__aux_{label}_{position}_{operand_number}"
                        if not is_last:
                            allocate(target)
                            auxiliary.append(("xor", (target, accumulator, operand)))
                        xor(target, accumulator, operand, label)
                        accumulator = target
            elif isinstance(component, Xor):
                for position, output in enumerate(outputs):
                    for bit, target_output in enumerate(output):
                        operands = [group[position][bit] for group in selected]
                        accumulator = operands[0]
                        for operand_number, operand in enumerate(operands[1:], start=1):
                            is_last = operand_number == len(operands) - 1
                            target = target_output if is_last else allocate(
                                f"__aux_{label}_{position}_{bit}_{operand_number}"
                            )
                            if not is_last:
                                auxiliary.append(("xor", (target, accumulator, operand)))
                            xor(target, accumulator, operand, label)
                            accumulator = target
            elif isinstance(component, Rotate):
                width = component.output_type.domain.width
                offset = component.amount if component.direction == "left" else -component.amount
                for output, input_ in zip(outputs, selected[0]):
                    for bit, output_bit in enumerate(output):
                        equal(output_bit, input_[(bit + offset) % width], label)
            elif isinstance(component, ModularAdd):
                width = component.output_type.domain.width
                for position, output in enumerate(outputs):
                    accumulator = selected[0][position]
                    for operand_number, operand in enumerate(
                        (group[position] for group in selected[1:]), start=1
                    ):
                        is_last = operand_number == len(selected) - 1
                        target = output if is_last else tuple(
                            allocate(f"__aux_{label}_{position}_{operand_number}_{bit}")
                            for bit in range(width)
                        )
                        carry = None
                        for bit in range(width - 1, -1, -1):
                            if carry is None:
                                xor(target[bit], accumulator[bit], operand[bit], label)
                                if not is_last:
                                    auxiliary.append(("xor", (target[bit], accumulator[bit], operand[bit])))
                            else:
                                partial = allocate(
                                    f"__aux_{label}_{position}_{operand_number}_xor_{bit}"
                                )
                                xor(partial, accumulator[bit], operand[bit], label)
                                xor(target[bit], partial, carry, label)
                                auxiliary.append(("xor", (partial, accumulator[bit], operand[bit])))
                                if not is_last:
                                    auxiliary.append(("xor", (target[bit], partial, carry)))
                            if bit:
                                next_carry = allocate(
                                    f"__aux_{label}_{position}_{operand_number}_carry_{bit}"
                                )
                                if carry is None:
                                    and_(next_carry, accumulator[bit], operand[bit], label)
                                    auxiliary.append(("and", (next_carry, accumulator[bit], operand[bit])))
                                else:
                                    majority(next_carry, accumulator[bit], operand[bit], carry, label)
                                    auxiliary.append(("majority", (next_carry, accumulator[bit], operand[bit], carry)))
                                carry = next_carry
                        accumulator = target
            elif isinstance(component, BitVectorSBox):
                inputs = [group[0] for group in selected[0]]
                outputs = [group[0] for group in outputs]
                width = len(inputs)
                for input_value, output_value in enumerate(component.table):
                    antecedent = tuple(
                        -indices[name] if (input_value >> (width - 1 - i)) & 1 else indices[name]
                        for i, name in enumerate(inputs)
                    )
                    for i, output in enumerate(outputs):
                        expected = (output_value >> (width - 1 - i)) & 1
                        literal = indices[output] if expected else -indices[output]
                        add_clause(antecedent + (literal,), label)
            else:
                raise NotImplementedError(
                    f"BooleanCNFModel does not support {type(component).__name__} "
                    f"component {label!r}"
                )

        self._auxiliary_definitions = tuple(auxiliary)
        self._formula = CNFFormula(tuple(variables), tuple(clauses), tuple(provenance))
        return self._formula

    def witness(self, evaluation: EvaluationResult) -> Mapping[str, int]:
        """Build a satisfying named assignment from a scalar evaluation result."""

        if not isinstance(evaluation, EvaluationResult):
            raise TypeError("evaluation must be an EvaluationResult")
        formula = self.cnf_formula()
        assignment = {
            name: bit
            for source_id, values in evaluation.values.items()
            for position, value in enumerate(values)
            for name, bit in zip(
                unit_variable_names(source_id, self._port_type(source_id), position),
                encode_unit(value, self._port_type(source_id)),
            )
        }
        for operation, names in self._auxiliary_definitions:
            target, operands = names[0], names[1:]
            if operation == "xor":
                assignment[target] = assignment[operands[0]] ^ assignment[operands[1]]
            elif operation == "and":
                assignment[target] = assignment[operands[0]] & assignment[operands[1]]
            else:
                assignment[target] = int(sum(assignment[item] for item in operands) >= 2)
        return {name: assignment[name] for name in formula.variables}

    def _port_type(self, owner_id: str):
        for port in list(self.cipher.inputs.values()) + [item.output for item in self.cipher.components]:
            if port.owner_id == owner_id:
                return port.value_type
        raise KeyError(owner_id)
