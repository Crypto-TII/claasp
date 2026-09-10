"""Lower typed bit graphs to Boolean CNF."""

from collections.abc import Mapping

from claasp_next.boolean.cnf import CNFFormula
from claasp_next.components import Add, BitVectorSBox, Concatenate, Constant, Identity, Permutation
from claasp_next.core import Cipher
from claasp_next.domains import Bit
from claasp_next.evaluators import EvaluationResult


class BooleanCNFModel:
    """Compile a homogeneous :class:`~claasp_next.domains.Bit` graph to CNF.

    The lowering currently supports constants, wiring components, bitwise
    :class:`~claasp_next.components.Add` (XOR), and
    :class:`~claasp_next.components.BitVectorSBox`. It deliberately owns no
    SAT-solver dependency.
    """

    def __init__(self, cipher: Cipher) -> None:
        if not isinstance(cipher, Cipher):
            raise TypeError("cipher must be a Cipher")
        self.cipher = cipher
        self._auxiliary_definitions: tuple[tuple[str, str, str], ...] = ()
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
            if not isinstance(port.value_type.domain, Bit):
                raise ValueError(
                    f"Boolean CNF requires the Bit domain; {port.owner_id!r} uses "
                    f"{type(port.value_type.domain).__name__}"
                )

        variables = [
            self._name(port.owner_id, position)
            for port in sources
            for position in range(port.value_type.unit_count)
        ]
        indices = {name: index + 1 for index, name in enumerate(variables)}
        clauses: list[tuple[int, ...]] = []
        provenance: list[str] = []
        auxiliary: list[tuple[str, str, str]] = []

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

        for component in self.cipher.components:
            label = component.component_id
            outputs = [self._name(label, i) for i in range(component.output_type.unit_count)]
            selected = [
                [self._name(item.source.owner_id, position) for position in item.positions]
                for item in component.inputs
            ]
            if isinstance(component, Constant):
                for output, value in zip(outputs, component.values):
                    add_clause(((indices[output] if value else -indices[output]),), label)
            elif isinstance(component, Identity):
                for output, input_ in zip(outputs, selected[0]):
                    equal(output, input_, label)
            elif isinstance(component, Permutation):
                for output, position in zip(outputs, component.mapping):
                    equal(output, selected[0][position], label)
            elif isinstance(component, Concatenate):
                inputs = [name for group in selected for name in group]
                for output, input_ in zip(outputs, inputs):
                    equal(output, input_, label)
            elif isinstance(component, Add):
                for position, output in enumerate(outputs):
                    operands = [group[position] for group in selected]
                    accumulator = operands[0]
                    for operand_number, operand in enumerate(operands[1:], start=1):
                        is_last = operand_number == len(operands) - 1
                        target = output if is_last else f"__aux_{label}_{position}_{operand_number}"
                        if not is_last:
                            indices[target] = len(variables) + 1
                            variables.append(target)
                            auxiliary.append((target, accumulator, operand))
                        xor(target, accumulator, operand, label)
                        accumulator = target
            elif isinstance(component, BitVectorSBox):
                inputs = selected[0]
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
            self._name(source_id, position): value
            for source_id, values in evaluation.values.items()
            for position, value in enumerate(values)
        }
        for target, left, right in self._auxiliary_definitions:
            assignment[target] = assignment[left] ^ assignment[right]
        return {name: assignment[name] for name in formula.variables}
