"""S-box-sized word activity on mixed Bit/Word graphs, with certified branches."""

from collections import Counter
from hashlib import sha256

from claasp.analysis.component_properties import (
    ComponentProperty,
    PropertyClaim,
    PropertyDomain,
    semantic_component_key,
)
from claasp.analysis.linear_properties import matrix_rank
from claasp.components import BitVectorSBox, Constant, Identity, LinearMap, Permutation, Rotate, Xor
from claasp.representations.constraints import ConstraintModelApplication
from claasp.representations.constraints.milp.model import (
    ConstraintSense,
    LinearConstraint,
    LinearExpression,
    LinearVariable,
    MILPModel,
    ObjectiveSense,
    VariableKind,
)
from claasp.unit_types import Bit


def word_size_for_graph(primitive):
    widths = {
        c.inputs[0].array_type.encoded_bit_size
        for c in primitive.graph.components
        if isinstance(c, BitVectorSBox)
    }
    if len(widths) != 1:
        raise NotImplementedError("wordwise bit graphs require one bijective S-box word size")
    width = widths.pop()
    assert width is not None
    return width


def certified_branch(component, certificate, word_size):
    key = semantic_component_key(component, PropertyDomain.WORD_LINEAR)
    digest = sha256(repr(key).encode()).hexdigest()[:16]
    identity = (
        f"{key.component_type.rsplit('.', 1)[-1]}:{PropertyDomain.WORD_LINEAR.value}:{digest}"
    )
    if (
        certificate is None
        or certificate.claim is not PropertyClaim.EXACT
        or not certificate.complete
        or certificate.request.property is not ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER
        or certificate.request.domain is not PropertyDomain.WORD_LINEAR
        or certificate.request.option_map.get("word_size") != word_size
        or certificate.provenance.semantic_identity != identity
        or not isinstance(certificate.value, int)
        or isinstance(certificate.value, bool)
        or certificate.value < 1
    ):
        raise ValueError(
            "an exact branch result for this matrix and word size is required; use primitive.analysis.active_sboxes() to compute it"
        )
    return certificate.value


class _BitWordActivityCompiler:
    def __init__(self, model):
        self.owner = model
        self.primitive = model.primitive
        self.graph = model.primitive.graph
        if model.word_size is not None and (
            not isinstance(model.word_size, int)
            or isinstance(model.word_size, bool)
            or model.word_size < 1
        ):
            raise ValueError("word_size must be a positive integer")
        self.width = model.word_size or word_size_for_graph(self.primitive)
        if self.width != word_size_for_graph(self.primitive):
            raise ValueError("word_size must match the S-box input size")
        self.variables = []
        self.constraints = []
        self.names: dict[str, tuple[str, ...]] = {}
        self.sboxes = []
        self._parents = {}
        self._zeros: set[str] = set()
        self._nonzero_groups = []
        self._serial = 0
        for name, array in self.graph.input_arrays.items():
            self._source(name, array.array_type.encoded_bit_size)
        for component in self.graph.components:
            self._source(component.component_id, component.output_type.encoded_bit_size)
        for name in model.zero_difference_inputs:
            self._zeros.update(self.names[name])
        self._nonzero_groups.append(self.names[model.active_input])

    def _source(self, name, bits):
        if bits is None or bits % self.width:
            raise NotImplementedError("every encoded source must align to the S-box word size")
        serial = len(self.names)
        self.names[name] = tuple(
            self.binary(f"activity_source_{serial}_{i}") for i in range(bits // self.width)
        )

    def binary(self, name):
        self.variables.append(LinearVariable(name, VariableKind.BINARY))
        self._parents[name] = name
        return name

    def constrain(self, coefficients, sense, rhs, label):
        self.constraints.append(
            LinearConstraint(LinearExpression.from_terms(coefficients), sense, rhs, label)
        )

    def root(self, name):
        while self._parents[name] != name:
            self._parents[name] = self._parents[self._parents[name]]
            name = self._parents[name]
        return name

    def is_zero(self, name):
        return self.root(name) in self._zeros

    def mark_zero(self, name):
        self._zeros.add(self.root(name))

    def equal(self, left, right):
        a, b = self.root(left), self.root(right)
        zero = a in self._zeros or b in self._zeros
        self._parents[b] = a
        self._zeros.discard(b)
        if zero:
            self._zeros.add(a)
        coefficients = Counter((left,))
        coefficients.subtract((right,))
        self.constrain(
            coefficients, ConstraintSense.EQUAL, 0, f"word_wiring_{len(self.constraints)}"
        )

    def groups(self, bits):
        result = []
        for start in range(0, len(bits), self.width):
            chunk = bits[start : start + self.width]
            source, bit = chunk[0]
            word = bit // self.width
            if len(chunk) != self.width or set(chunk) != {
                (source, word * self.width + i) for i in range(self.width)
            }:
                raise NotImplementedError(
                    "wordwise activity boundary mixes bits from different words"
                )
            result.append(self.names[source][word])
        return tuple(result)

    def relation(self, local, branch, *, invertible=False, input_count=0):
        indicator = self.binary(f"active_relation_{self._serial}")
        self._serial += 1
        for name in local:
            self.constrain(
                {name: 1, indicator: -1},
                ConstraintSense.LESS_EQUAL,
                0,
                f"activate_{len(self.constraints)}",
            )
        coefficients = Counter(local)
        coefficients[indicator] -= branch
        self.constrain(
            coefficients, ConstraintSense.GREATER_EQUAL, 0, f"branch_{len(self.constraints)}"
        )
        if invertible:
            source, output = local[:input_count], local[input_count:]
            available = {self.root(name) for name in source if not self.is_zero(name)}
            for group in self._nonzero_groups:
                required = {self.root(name) for name in group if not self.is_zero(name)}
                if required and required <= available:
                    # This is implied by integer activity constraints, but greatly
                    # strengthens the LP relaxation for full-state linear layers.
                    self.constrain(
                        {indicator: 1}, ConstraintSense.EQUAL, 1, f"known_nonzero_{self._serial}"
                    )
                    self._nonzero_groups.append(output)
                    break
            if not available:
                for name in output:
                    self.mark_zero(name)
            for portion in (source, output):
                coefficients = Counter(portion)
                coefficients[indicator] -= 1
                self.constrain(
                    coefficients,
                    ConstraintSense.GREATER_EQUAL,
                    0,
                    f"nonzero_side_{len(self.constraints)}",
                )

    def build(self):
        for component in self.graph.components:
            output = self.names[component.component_id]
            bits = tuple(
                self.graph.selection_bit_sources(selection) for selection in component.inputs
            )
            operands = tuple(self.groups(vector) for vector in bits)
            if isinstance(component, BitVectorSBox):
                if component.inputs[
                    0
                ].array_type.encoded_bit_size != component.output_bit_size or sorted(
                    component.table
                ) != list(range(len(component.table))):
                    raise NotImplementedError("wordwise activity requires bijective S-boxes")
                if len(output) != 1 or len(operands[0]) != 1:
                    raise NotImplementedError("one S-box must cover one activity word")
                self.equal(output[0], operands[0][0])
                self.sboxes.append(output[0])
            elif isinstance(component, Constant):
                for target in output:
                    self.mark_zero(target)
                    self.constrain(
                        {target: 1},
                        ConstraintSense.EQUAL,
                        0,
                        f"constant_difference_{len(self.constraints)}",
                    )
            elif isinstance(component, Identity):
                for target, source in zip(output, operands[0]):
                    self.equal(target, source)
            elif isinstance(component, Permutation):
                width = component.output_type.unit_type.encoded_bit_size
                assert width is not None
                reordered = tuple(
                    bits[0][position * width + bit]
                    for position in component.mapping
                    for bit in range(width)
                )
                for target, source in zip(output, self.groups(reordered)):
                    self.equal(target, source)
            elif isinstance(component, Rotate):
                width = component.output_type.unit_type.encoded_bit_size
                assert width is not None
                offset = component.amount if component.direction == "left" else -component.amount
                reordered = tuple(
                    bits[0][start + (bit + offset) % width]
                    for start in range(0, len(bits[0]), width)
                    for bit in range(width)
                )
                for target, source in zip(output, self.groups(reordered)):
                    self.equal(target, source)
            elif isinstance(component, Xor):
                if any(len(operand) != len(output) for operand in operands):
                    raise NotImplementedError("wordwise XOR operands must align")
                for position, target in enumerate(output):
                    sources = tuple(operand[position] for operand in operands)
                    live = [name for name in sources if not self.is_zero(name)]
                    if len(live) == 1:
                        self.equal(target, live[0])
                    elif not live:
                        self.mark_zero(target)
                    self.relation(sources + (target,), 2)
            elif isinstance(component, LinearMap) and isinstance(
                component.output_type.unit_type, Bit
            ):
                matrix = component.matrix
                if len(matrix) != len(matrix[0]) or matrix_rank(matrix, Bit()) != len(matrix):
                    raise NotImplementedError(
                        "wordwise activity linear layers must be square and invertible"
                    )
                branch = certified_branch(
                    component, self.owner.branch_numbers.get(component.component_id), self.width
                )
                self.relation(
                    operands[0] + output, branch, invertible=True, input_count=len(operands[0])
                )
            else:
                raise NotImplementedError(
                    f"no grouped wordwise activity semantics for {type(component).__name__}"
                )
        self.constrain(
            Counter(self.names[self.owner.active_input]),
            ConstraintSense.GREATER_EQUAL,
            1,
            "nonzero_activity_input",
        )
        for name in self.owner.zero_difference_inputs:
            for target in self.names[name]:
                self.constrain(
                    {target: 1}, ConstraintSense.EQUAL, 0, f"zero_input_{len(self.constraints)}"
                )
        self.owner._sbox_variables = tuple(self.sboxes)
        return MILPModel(
            tuple(self.variables),
            tuple(self.constraints),
            LinearExpression.from_terms(Counter(self.sboxes)),
            ObjectiveSense.MINIMIZE,
            (ConstraintModelApplication(self.owner.model_provenance),),
        )
