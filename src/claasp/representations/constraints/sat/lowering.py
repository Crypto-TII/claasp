"""Lower typed bit graphs to the Boolean CNF representation."""

from collections.abc import Mapping

from claasp.components import (
    Add,
    BitVectorSBox,
    BitwiseAnd,
    Constant,
    Identity,
    ModularAdd,
    Permutation,
    Rotate,
    Xor,
)
from claasp.domains import Bit, Word
from claasp.graph import Primitive
from claasp.representations.constraints.sat.components import (
    BooleanFunctionalSATModel,
    ModularAddFunctionalSATModel,
    SBoxFunctionalSATModel,
    WiringFunctionalSATModel,
)
from claasp.representations.constraints.sat.encoding import encode_unit, unit_variable_names
from claasp.representations.constraints.sat.model import CNFFormula
from claasp.representations.execution import EvaluationResult


class _CNFEncodingContext:
    def __init__(self, variables) -> None:
        self.variables = variables
        self.indices = {name: index + 1 for index, name in enumerate(variables)}
        self.clauses = []
        self.provenance = []
        self.auxiliary = []

    def allocate(self, name):
        self.indices[name] = len(self.variables) + 1
        self.variables.append(name)
        return name

    def add_clause(self, literals, label):
        self.clauses.append(literals)
        self.provenance.append(label)

    def equal(self, output, input_, label):
        x, y = self.indices[input_], self.indices[output]
        self.add_clause((-x, y), label)
        self.add_clause((x, -y), label)

    def xor(self, output, left, right, label):
        a, b, y = self.indices[left], self.indices[right], self.indices[output]
        self.add_clause((-a, -b, -y), label)
        self.add_clause((a, b, -y), label)
        self.add_clause((a, -b, y), label)
        self.add_clause((-a, b, y), label)

    def majority(self, output, left, right, carry, label):
        a, b, c, y = (
            self.indices[left],
            self.indices[right],
            self.indices[carry],
            self.indices[output],
        )
        self.add_clause((-a, -b, y), label)
        self.add_clause((-a, -c, y), label)
        self.add_clause((-b, -c, y), label)
        self.add_clause((a, b, -y), label)
        self.add_clause((a, c, -y), label)
        self.add_clause((b, c, -y), label)

    def and_(self, output, left, right, label):
        a, b, y = self.indices[left], self.indices[right], self.indices[output]
        self.add_clause((-a, -b, y), label)
        self.add_clause((a, -y), label)
        self.add_clause((b, -y), label)


class BooleanCNFModel:
    """Compile a homogeneous Bit or Word graph to CNF.

    The lowering currently supports constants, wiring components, bitwise
    :class:`~claasp.components.Add` (XOR), and
    :class:`~claasp.components.BitVectorSBox`. It deliberately owns no
    SAT-solver dependency.


    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> primitive = Speck(number_of_rounds=1)
        >>> formula = BooleanCNFModel(primitive).cnf_formula()
        >>> (len(formula.variables), len(formula.clauses))
        (206, 403)
        >>> "modular_add_0_1" in formula.provenance
        True
    """

    def __init__(self, primitive: Primitive) -> None:
        if not isinstance(primitive, Primitive):
            raise TypeError("primitive must be a Primitive")
        self.primitive = primitive
        self._auxiliary_definitions: tuple[tuple[str, tuple[str, ...]], ...] = ()
        self._formula: CNFFormula | None = None

    @staticmethod
    def _name(source_id: str, position: int) -> str:
        return f"{source_id}_{position}"

    def cnf_formula(self) -> CNFFormula:
        """Return the deterministic CNF representation, compiling it once."""

        if self._formula is not None:
            return self._formula
        sources = list(self.primitive.input_ports.values()) + [
            component.output for component in self.primitive.components
        ]
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
        context = _CNFEncodingContext(variables)

        for component in self.primitive.components:
            label = component.component_id
            outputs = [
                unit_variable_names(label, component.output_type, i)
                for i in range(component.output_type.unit_count)
            ]
            selected = []
            for item in component.inputs:
                width = item.value_type.domain.encoded_bit_size
                names = [
                    self._bit_name(owner_id, bit)
                    for owner_id, bit in self.primitive.selection_bit_sources(item)
                ]
                selected.append(
                    [tuple(names[start : start + width]) for start in range(0, len(names), width)]
                )
            if isinstance(component, (Constant, Identity, Permutation, Rotate)):
                WiringFunctionalSATModel(component).encode(context, outputs, selected)
            elif isinstance(component, (Add, Xor, BitwiseAnd)):
                BooleanFunctionalSATModel(component).encode(context, outputs, selected)
            elif isinstance(component, ModularAdd):
                ModularAddFunctionalSATModel(component).encode(context, outputs, selected)
            elif isinstance(component, BitVectorSBox):
                SBoxFunctionalSATModel(component).encode(context, outputs, selected)
            else:
                raise NotImplementedError(
                    f"BooleanCNFModel does not support {type(component).__name__} "
                    f"component {label!r}"
                )

        self._auxiliary_definitions = tuple(context.auxiliary)
        self._formula = CNFFormula(
            tuple(context.variables), tuple(context.clauses), tuple(context.provenance)
        )
        return self._formula

    def witness(self, evaluation: EvaluationResult) -> Mapping[str, int]:
        """Build a satisfying named assignment from a scalar evaluation result."""

        if not isinstance(evaluation, EvaluationResult):
            raise TypeError("evaluation must be an EvaluationResult")
        formula = self.cnf_formula()
        assignment = {
            name: bit
            for source_id, values in evaluation.values.items()
            if source_id in self.primitive.input_ports
            or any(component.component_id == source_id for component in self.primitive.components)
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
        for port in list(self.primitive.input_ports.values()) + [
            item.output for item in self.primitive.components
        ]:
            if port.owner_id == owner_id:
                return port.value_type
        raise KeyError(owner_id)

    def _bit_name(self, owner_id: str, flat_bit: int) -> str:
        value_type = self._port_type(owner_id)
        width = value_type.domain.encoded_bit_size
        position, local_bit = divmod(flat_bit, width)
        return unit_variable_names(owner_id, value_type, position)[local_bit]
