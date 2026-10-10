"""Lower typed bit graphs to the Boolean CNF representation."""

from collections import defaultdict
from collections.abc import Mapping
from typing import cast

from claasp.components import (
    Add,
    BitVectorSBox,
    BitwiseAnd,
    BitwiseNot,
    BitwiseOr,
    Constant,
    Identity,
    ModularAdd,
    ModularMultiply,
    ModularSubtract,
    Multiply,
    Permutation,
    Rotate,
    Shift,
    VariableRotate,
    VariableShift,
    Xor,
)
from claasp.domains import Bit, Word
from claasp.graph import Primitive
from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _direct_model,
)
from claasp.representations.constraints.sat.components import (
    BooleanFunctionalSATModel,
    BooleanNativeXorSATModel,
    ModularAddFunctionalSATModel,
    ModularAddNativeXorSATModel,
    ModularMultiplyFunctionalSATModel,
    ModularMultiplyNativeXorSATModel,
    ModularSubtractFunctionalSATModel,
    ModularSubtractNativeXorSATModel,
    SBoxFunctionalSATModel,
    VariableWiringFunctionalSATModel,
    WiringFunctionalSATModel,
)
from claasp.representations.constraints.sat.encoding import encode_unit, unit_variable_names
from claasp.representations.constraints.sat.model import CNFFormula, NativeXorCNFFormula
from claasp.representations.execution import EvaluationResult


class _CNFEncodingContext:
    def __init__(self, variables) -> None:
        self.variables = variables
        self.indices = {name: index + 1 for index, name in enumerate(variables)}
        self.clauses = []
        self.provenance = []
        self.auxiliary = []
        self.constraint_models = []

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

    def or_(self, output, left, right, label):
        a, b, y = self.indices[left], self.indices[right], self.indices[output]
        self.add_clause((a, b, -y), label)
        self.add_clause((-a, y), label)
        self.add_clause((-b, y), label)

    def not_(self, output, input_, label):
        x, y = self.indices[input_], self.indices[output]
        self.add_clause((x, y), label)
        self.add_clause((-x, -y), label)

    def relation(self, output, inputs, function, label):
        names = (*inputs, output)
        for assignment in range(1 << len(names)):
            values = tuple(
                (assignment >> (len(names) - position - 1)) & 1 for position in range(len(names))
            )
            if values[-1] == function(*values[:-1]):
                continue
            self.add_clause(
                tuple(
                    -self.indices[name] if value else self.indices[name]
                    for name, value in zip(names, values)
                ),
                label,
            )


class _NativeXorEncodingContext(_CNFEncodingContext):
    def __init__(self, variables) -> None:
        super().__init__(variables)
        self.xor_clauses: list[tuple[int, ...]] = []
        self.xor_provenance: list[str] = []

    def xor(self, output, left, right, label):
        self.xor_clauses.append((-self.indices[output], self.indices[left], self.indices[right]))
        self.xor_provenance.append(label)


def _native_xor_formula(formula: CNFFormula) -> NativeXorCNFFormula:
    """Replace only complete canonical parity-CNF groups with native XOR records."""

    grouped = defaultdict(list)
    for position, clause in enumerate(formula.clauses):
        support = tuple(sorted(abs(literal) for literal in clause))
        if len(support) >= 2 and len(set(support)) == len(support):
            grouped[support].append(position)

    removed = set()
    xor_clauses = []
    xor_provenance = []
    for support, positions in grouped.items():
        forbidden_even: set[frozenset[int]] = set()
        forbidden_odd: set[frozenset[int]] = set()
        for assignment in range(1 << len(support)):
            values = tuple(
                (assignment >> (len(support) - 1 - bit)) & 1 for bit in range(len(support))
            )
            expected_clause = frozenset(
                -index if value else index for index, value in zip(support, values)
            )
            (forbidden_odd if sum(values) % 2 else forbidden_even).add(expected_clause)
        actual = {frozenset(formula.clauses[position]) for position in positions}
        if len(actual) != len(positions):
            continue
        if actual == forbidden_even:
            native = support
        elif actual == forbidden_odd:
            native = (-support[0], *support[1:])
        else:
            continue
        removed.update(positions)
        xor_clauses.append(native)
        labels = tuple(dict.fromkeys(formula.provenance[position] for position in positions))
        xor_provenance.append("native_xor:" + "+".join(labels))

    return NativeXorCNFFormula(
        formula.variables,
        tuple(clause for position, clause in enumerate(formula.clauses) if position not in removed),
        tuple(
            label for position, label in enumerate(formula.provenance) if position not in removed
        ),
        formula.constraint_models,
        tuple(xor_clauses),
        tuple(xor_provenance),
    )


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

    model_provenance = _direct_model(
        ConstraintBackend.SAT,
        "BooleanCNFModel",
        "functional",
        "graph composition of declared component CNF encodings",
        "The compiler only wires and composes the component-level declarations it retains.",
    )

    def __init__(self, primitive: Primitive, *, native_xor: bool = False) -> None:
        if not isinstance(primitive, Primitive):
            raise TypeError("primitive must be a Primitive")
        self.primitive = primitive
        self.native_xor = native_xor
        self._auxiliary_definitions: tuple[tuple[str, tuple[str, ...]], ...] = ()
        self._formula: CNFFormula | NativeXorCNFFormula | None = None

    @staticmethod
    def _name(source_id: str, position: int) -> str:
        return f"{source_id}_{position}"

    def cnf_formula(self) -> CNFFormula | NativeXorCNFFormula:
        """Return the deterministic CNF representation, compiling it once."""

        if self._formula is not None:
            return self._formula
        sources = list(self.primitive.graph.input_ports.values()) + [
            component.output for component in self.primitive.graph.components
        ]
        for port in sources:
            if not isinstance(port.array_type.domain, (Bit, Word)):
                raise ValueError(
                    f"Boolean CNF requires the Bit or Word domain; {port.owner_id!r} uses "
                    f"{type(port.array_type.domain).__name__}"
                )
        domains = {type(port.array_type.domain) for port in sources}
        if len(domains) != 1:
            raise ValueError("Boolean CNF requires a homogeneous Bit or Word graph")

        variables = [
            name
            for port in sources
            for position in range(port.array_type.unit_count)
            for name in unit_variable_names(port.owner_id, port.array_type, position)
        ]
        context = (
            _NativeXorEncodingContext(variables)
            if self.native_xor
            else _CNFEncodingContext(variables)
        )

        for component in self.primitive.graph.components:
            label = cast(str, component.component_id)
            outputs = [
                unit_variable_names(label, component.output_type, i)
                for i in range(component.output_type.unit_count)
            ]
            selected = []
            for item in component.inputs:
                width = item.array_type.domain.encoded_bit_size
                names = [
                    self._bit_name(owner_id, bit)
                    for owner_id, bit in self.primitive.graph.selection_bit_sources(item)
                ]
                selected.append(
                    [tuple(names[start : start + width]) for start in range(0, len(names), width)]
                )
            encoding: (
                WiringFunctionalSATModel
                | BooleanFunctionalSATModel
                | ModularAddFunctionalSATModel
                | ModularSubtractFunctionalSATModel
                | SBoxFunctionalSATModel
                | VariableWiringFunctionalSATModel
            )
            if isinstance(component, (Constant, Identity, Permutation, Rotate, Shift)):
                encoding = WiringFunctionalSATModel(component)
            elif isinstance(component, (VariableRotate, VariableShift)):
                encoding = VariableWiringFunctionalSATModel(component)
            elif isinstance(component, (Add, Multiply, Xor, BitwiseAnd, BitwiseOr, BitwiseNot)):
                encoding = (
                    BooleanNativeXorSATModel(component)
                    if self.native_xor
                    else BooleanFunctionalSATModel(component)
                )
            elif isinstance(component, ModularAdd):
                encoding = (
                    ModularAddNativeXorSATModel(component)
                    if self.native_xor
                    else ModularAddFunctionalSATModel(component)
                )
            elif isinstance(component, ModularSubtract):
                encoding = (
                    ModularSubtractNativeXorSATModel(component)
                    if self.native_xor
                    else ModularSubtractFunctionalSATModel(component)
                )
            elif isinstance(component, ModularMultiply):
                encoding = (
                    ModularMultiplyNativeXorSATModel(component)
                    if self.native_xor
                    else ModularMultiplyFunctionalSATModel(component)
                )
            elif isinstance(component, BitVectorSBox):
                encoding = SBoxFunctionalSATModel(component)
            else:
                raise NotImplementedError(
                    f"BooleanCNFModel does not support {type(component).__name__} "
                    f"component {label!r}"
                )
            encoding.encode(context, outputs, selected)
            context.constraint_models.append(
                ConstraintModelApplication(encoding.model_provenance, (label,))
            )

        self._auxiliary_definitions = tuple(context.auxiliary)
        arguments = (
            tuple(context.variables),
            tuple(context.clauses),
            tuple(context.provenance),
            tuple(context.constraint_models),
        )
        self._formula = (
            NativeXorCNFFormula(
                *arguments,
                tuple(context.xor_clauses),
                tuple(context.xor_provenance),
            )
            if isinstance(context, _NativeXorEncodingContext)
            else CNFFormula(*arguments)
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
            if source_id in self.primitive.graph.input_ports
            or any(
                component.component_id == source_id for component in self.primitive.graph.components
            )
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
            elif operation == "or":
                assignment[target] = assignment[operands[0]] | assignment[operands[1]]
            elif operation == "borrow":
                left, right, borrow = (assignment[item] for item in operands)
                assignment[target] = int((not left and (right or borrow)) or (right and borrow))
            elif operation == "borrow2":
                left, right = (assignment[item] for item in operands)
                assignment[target] = int(not left and right)
            elif operation == "mux":
                selector, direct, alternate = (assignment[item] for item in operands)
                assignment[target] = alternate if selector else direct
            elif operation == "mux_zero":
                selector, direct = (assignment[item] for item in operands)
                assignment[target] = 0 if selector else direct
            elif operation == "zero":
                assignment[target] = 0
            elif operation.startswith("prefix_mod:"):
                _, remainder, width = operation.split(":")
                value = sum(
                    assignment[item] << (len(operands) - position - 1)
                    for position, item in enumerate(operands)
                )
                assignment[target] = int(value % int(width) == int(remainder))
            else:
                assignment[target] = int(sum(assignment[item] for item in operands) >= 2)
        return {name: assignment[name] for name in formula.variables}

    def _port_type(self, owner_id: str):
        for port in list(self.primitive.graph.input_ports.values()) + [
            item.output for item in self.primitive.graph.components
        ]:
            if port.owner_id == owner_id:
                return port.array_type
        raise KeyError(owner_id)

    def _bit_name(self, owner_id: str, flat_bit: int) -> str:
        array_type = self._port_type(owner_id)
        width = array_type.domain.encoded_bit_size
        position, local_bit = divmod(flat_bit, width)
        return unit_variable_names(owner_id, array_type, position)[local_bit]


class BooleanNativeXorModel(BooleanCNFModel):
    """Compile a Boolean graph using native parity constraints where possible.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> formula = BooleanNativeXorModel(Speck(number_of_rounds=1)).cnf_formula()
        >>> (formula.native_xor_count > 0, formula.clause_count < 403)
        (True, True)
    """

    model_provenance = _direct_model(
        ConstraintBackend.SAT,
        "BooleanNativeXorModel",
        "functional",
        "graph composition with exact native parity records",
        "Native XOR extraction is an exact mechanical replacement of canonical parity clauses.",
    )

    def __init__(self, primitive: Primitive) -> None:
        super().__init__(primitive, native_xor=True)

    def cnf_formula(self) -> NativeXorCNFFormula:
        """Return CNF plus native XOR constraints."""

        formula = super().cnf_formula()
        if not isinstance(formula, NativeXorCNFFormula):  # pragma: no cover - constructor invariant
            raise RuntimeError("native XOR lowering returned an ordinary CNF formula")
        return formula
