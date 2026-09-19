"""Whole-word graph linear characteristics, including key-schedule fanout."""

from dataclasses import dataclass
from contextlib import nullcontext
from hashlib import sha256

from claasp_next.components import BitwiseAnd, Constant, Identity, ModularAdd, Rotate, Xor
from claasp_next.domains import Word
from claasp_next.drivers.solvers import SatStatus
from claasp_next.representations.constraints.smt.formula import SMTFormula
from claasp_next.representations.constraints.smt.transitions import ModularAddLinearSMTModel, _xor_equivalence
from claasp_next.representations.constraints.smt.trails import _at_most
from claasp_next.semantics.cryptanalysis import BitwiseAndSemantics, ModularAddLinearSemantics, TrailStep


@dataclass(frozen=True, slots=True)
class WordLinearCharacteristic:
    """Exact component characteristic, not a whole-primitive linear hull."""

    input_masks: tuple[tuple[str, int], ...]
    output_mask: int
    steps: tuple[TrailStep, ...]
    constant_sign: int
    semantic_assignment: tuple[tuple[str, int], ...]

    @property
    def total_weight(self):
        return sum(step.transition.weight for step in self.steps)

    @property
    def sign(self):
        result = self.constant_sign
        for step in self.steps:
            result *= step.transition.sign
        return result


@dataclass(frozen=True, slots=True)
class WordLinearEnumeration:
    """Enumeration is proof-complete only after terminal solver UNSAT."""

    trails: tuple[WordLinearCharacteristic, ...]
    complete: bool
    runtime_seconds: float
    reproducibility: tuple[tuple[str, str], ...] = ()

    def require_complete(self):
        if not self.complete:
            raise RuntimeError("linear characteristic enumeration is incomplete")
        return self


class WordLinearSMTModel:
    """Exact XOR/rotation/addition mask wiring with explicit external masks.

    Constants contribute a sign and zero weight. Fanout XORs all consumer
    masks back to the producer. Native XOR-aware execution is not required.


    EXAMPLES::

        >>> try:
        ...     WordLinearSMTModel()
        ... except TypeError:
        ...     print("required configuration rejected")
        required configuration rejected
    """

    def __init__(self, primitive, *, maximum_weight, nonzero_input=None,
                 fixed_input_masks=None, fixed_inputs=None):
        if (not isinstance(maximum_weight, int) or isinstance(maximum_weight, bool)
                or maximum_weight < 0):
            raise ValueError("maximum_weight must be a nonnegative integer")
        self.primitive = primitive
        self.maximum_weight = maximum_weight
        self.nonzero_input = nonzero_input
        self.fixed_input_masks = dict(fixed_input_masks or {})
        self.fixed_inputs = dict(fixed_inputs or {})
        for name, value in self.fixed_inputs.items():
            if name not in primitive.input_ports:
                raise ValueError("unknown fixed concrete input")
            primitive._decode_boundary(value, primitive.input_ports[name].value_type)
        if nonzero_input in self.fixed_inputs:
            raise ValueError("a concrete fixed input cannot have a nonzero external mask")
        if nonzero_input is not None and nonzero_input not in primitive.input_ports:
            raise ValueError("unknown nonzero input")
        for name, value in self.fixed_input_masks.items():
            if name not in primitive.input_ports:
                raise ValueError("unknown fixed input")
            value_type = primitive.input_ports[name].value_type
            if (not isinstance(value_type.domain, Word) or not isinstance(value, int)
                    or isinstance(value, bool) or not 0 <= value < (1 << (value_type.unit_count * value_type.domain.width))):
                raise ValueError("fixed masks must fit the input word type")
        self._formula = None

    def _constant_subgraph(self):
        """Fold only nodes whose complete dependency set has concrete fixed inputs."""
        if not self.fixed_inputs:
            return {}
        trace = self.primitive.evaluate_with_trace({name: self.fixed_inputs.get(name, 0)
                                                    for name in self.primitive.input_ports}).trace
        known = {name: tuple(trace.value_of(name)) for name in self.fixed_inputs}
        for component in self.primitive.components:
            if all(
                all(owner_id in known for owner_id, _ in self.primitive.selection_bit_sources(selection))
                for selection in component.inputs
            ):
                known[component.component_id] = tuple(trace.value_of(component.component_id))
        return known

    @staticmethod
    def _names(prefix, value_type):
        if not isinstance(value_type.domain, Word):
            raise NotImplementedError("word linear lowering requires Word domains")
        return tuple(f"{prefix}_{bit}" for bit in range(value_type.unit_count * value_type.domain.width))

    def smt_formula(self):
        """Compute the smt formula for this public typed contract."""

        variables, indices, clauses, provenance = [], {}, [], []

        def allocate(name):
            if name not in indices:
                variables.append(name)
                indices[name] = len(variables)
            return name

        def add(items, label):
            clauses.append(tuple(items))
            provenance.append(label)

        sources = [(name, port.value_type) for name, port in self.primitive.input_ports.items()]
        sources += [(item.component_id, item.output_type) for item in self.primitive.components]
        ports = {name: tuple(allocate(n) for n in self._names(f"mask_{name}", vt)) for name, vt in sources}
        consumers = {name: [[] for _ in names] for name, names in ports.items()}
        edges, records, weights = {}, [], []
        folded = self._constant_subgraph()
        for component in self.primitive.components:
            if component.component_id in folded:
                edges[component.component_id] = ()
                continue
            operands = []
            for operand, selection in enumerate(component.inputs):
                names = tuple(allocate(n) for n in self._names(f"edge_{component.component_id}_{operand}", selection.value_type))
                operands.append(names)
                for edge_name, (owner_id, source_bit) in zip(
                    names, self.primitive.selection_bit_sources(selection)
                ):
                    consumers[owner_id][source_bit].append(edge_name)
            edges[component.component_id] = tuple(operands)
            output = ports[component.component_id]
            width = component.output_type.domain.width
            if isinstance(component, ModularAdd):
                if len(operands) != 2:
                    raise NotImplementedError("linear modular addition requires two operands")
                for unit in range(component.output_type.unit_count):
                    local = ModularAddLinearSMTModel(width).smt_formula()
                    prefix = f"add_{component.component_id}_{unit}"
                    local_names = {name: allocate(f"{prefix}_{name}") for name in local.variables}
                    mapping = {i: indices[local_names[name]] for i, name in enumerate(local.variables, 1)}
                    for clause, label in zip(local.assertions, local.provenance):
                        add((mapping[abs(literal)] * (1 if literal > 0 else -1) for literal in clause), label)
                    groups = [operand[unit * width:(unit + 1) * width] for operand in operands]
                    groups.append(output[unit * width:(unit + 1) * width])
                    for label, names in zip(("left", "right", "output"), groups):
                        for bit, name in enumerate(names):
                            _xor_equivalence((name, local_names[f"{label}_{bit}"]), indices, clauses, provenance)
                    weights.extend(local_names[f"weight_{bit}"] for bit in range(width))
                    records.append((component.component_id, unit, width, prefix))
            elif isinstance(component, BitwiseAnd):
                for bit, target in enumerate(output):
                    for operand in operands:
                        add((indices[target], -indices[operand[bit]]), "and_linear_support")
                weights.extend(output)
                for unit in range(component.output_type.unit_count):
                    records.append((component.component_id, unit, width, None))
            elif isinstance(component, Xor):
                for operand in operands:
                    for source, target in zip(operand, output):
                        _xor_equivalence((source, target), indices, clauses, provenance)
            elif isinstance(component, Identity):
                flattened = tuple(name for operand in operands for name in operand)
                for source, target in zip(flattened, output):
                    _xor_equivalence((source, target), indices, clauses, provenance)
            elif isinstance(component, Rotate):
                amount = component.amount if component.direction == "right" else -component.amount
                for unit in range(component.output_type.unit_count):
                    for bit in range(width):
                        _xor_equivalence((operands[0][unit * width + bit], output[unit * width + (bit + amount) % width]), indices, clauses, provenance)
            elif not isinstance(component, Constant):
                raise NotImplementedError(f"no word linear semantics for {type(component).__name__}")
        output = tuple(allocate(n) for n in self._names("external_output", self.primitive.output.value_type))
        for output_name, (owner_id, source_bit) in zip(
            output, self.primitive.selection_bit_sources(self.primitive.output)
        ):
            consumers[owner_id][source_bit].append(output_name)
        for name, names in ports.items():
            for bit, target in enumerate(names):
                _xor_equivalence((target, *consumers[name][bit]), indices, clauses, provenance)
        if self.nonzero_input is not None:
            add((indices[n] for n in ports[self.nonzero_input]), "nonzero_external_mask")
        for name, value in self.fixed_input_masks.items():
            if name in self.fixed_inputs:
                if value != 0:
                    raise ValueError("fixed concrete inputs cannot have nonzero external masks")
                continue
            for bit, variable in enumerate(ports[name]):
                literal = indices[variable]
                add((literal if value & (1 << (len(ports[name]) - 1 - bit)) else -literal,), "fixed_external_mask")
        semantic_names = tuple(variables)
        _at_most(weights, self.maximum_weight, allocate, indices, add)
        self._ports, self._edges, self._records, self._output = ports, edges, records, output
        self._folded_values = folded
        self._semantic_names = semantic_names
        self._formula = SMTFormula(tuple(variables), tuple(clauses), tuple(provenance))
        return self._formula

    def decode_characteristic(self, assignment):
        """Validate the full Boolean witness and independently recount additions."""
        if self._formula is None:
            raise ValueError("build the formula before decoding")
        from claasp_next.representations.constraints.sat import CNFFormula
        if not CNFFormula(self._formula.variables, self._formula.assertions, self._formula.provenance).is_satisfied(assignment):
            raise ValueError("invalid word linear witness")
        steps = []
        for component_id, unit, width, prefix in self._records:
            if prefix is None:
                masks = [_packed(names[unit * width:(unit + 1) * width], assignment)
                         for names in self._edges[component_id]]
                output = _packed(self._ports[component_id][unit * width:(unit + 1) * width], assignment)
                transition = BitwiseAndSemantics(width).xor_linear(*masks, output)
            else:
                local = ModularAddLinearSMTModel(width)
                projected = {name: assignment[f"{prefix}_{name}"] for name in local.smt_formula().variables}
                transition = local.decode_transition(projected)
            steps.append(TrailStep(f"{component_id}[{unit}]", transition))
        constant_sign = 1
        for name in self.fixed_inputs:
            for unit, value in enumerate(self._folded_values[name]):
                width = self.primitive.input_ports[name].value_type.domain.width
                mask = _packed(self._ports[name][unit * width:(unit + 1) * width], assignment)
                if (mask & value).bit_count() % 2:
                    constant_sign *= -1
        for component in self.primitive.components:
            if isinstance(component, Constant) or component.component_id in self._folded_values:
                value = 0
                for unit in self._folded_values.get(component.component_id, getattr(component, "values", ())):
                    value = (value << component.output_type.domain.width) | unit
                if (value & _packed(self._ports[component.component_id], assignment)).bit_count() % 2:
                    constant_sign *= -1
        result = WordLinearCharacteristic(
            tuple((name, 0 if name in self.fixed_inputs else _packed(self._ports[name], assignment)) for name in self.primitive.input_ports),
            _packed(self._output, assignment), tuple(steps), constant_sign,
            tuple((name, assignment[name]) for name in self._semantic_names),
        )
        if result.total_weight > self.maximum_weight:
            raise ValueError("word linear witness exceeds weight bound")
        if not self.check_characteristic(result):
            raise ValueError("word linear witness violates independent graph mask rules")
        return result

    def check_characteristic(self, trail):
        """Check arithmetic pullbacks and fanout, without consulting SMT clauses."""
        if self._formula is None:
            raise ValueError("build the formula before checking")
        values = dict(trail.semantic_assignment)
        if (len(values) != len(trail.semantic_assignment) or set(values) != set(self._semantic_names)
                or any(value not in (0, 1) for value in values.values())):
            return False
        sources = [(name, port.value_type) for name, port in self.primitive.input_ports.items()]
        sources += [(item.component_id, item.output_type) for item in self.primitive.components]
        fanout = {name: [0] * vt.unit_count for name, vt in sources}
        steps, constant_sign = [], 1

        def units(names, width):
            return tuple(_packed(names[i:i + width], values) for i in range(0, len(names), width))

        for name in self.fixed_inputs:
            masks = units(self._ports[name], self.primitive.input_ports[name].value_type.domain.width)
            if sum((mask & value).bit_count() for mask, value in zip(masks, self._folded_values[name])) % 2:
                constant_sign *= -1

        for component in self.primitive.components:
            width = component.output_type.domain.width
            output = units(self._ports[component.component_id], width)
            operands = [units(names, selection.value_type.domain.width)
                        for names, selection in zip(self._edges[component.component_id], component.inputs)]
            for selection, edge_names in zip(component.inputs, self._edges[component.component_id]):
                for edge_name, (owner_id, source_bit) in zip(
                    edge_names, self.primitive.selection_bit_sources(selection)
                ):
                    source_type = dict(sources)[owner_id]
                    source_width = source_type.domain.width
                    position, bit = divmod(source_bit, source_width)
                    fanout[owner_id][position] ^= values[edge_name] << (source_width - 1 - bit)
            if component.component_id in self._folded_values:
                if sum((mask & value).bit_count() for mask, value in zip(output, self._folded_values[component.component_id])) % 2:
                    constant_sign *= -1
            elif isinstance(component, ModularAdd):
                for unit, mask in enumerate(output):
                    transition = ModularAddLinearSemantics(width).xor_linear(operands[0][unit], operands[1][unit], mask)
                    if not transition.is_possible:
                        return False
                    steps.append(TrailStep(f"{component.component_id}[{unit}]", transition))
            elif isinstance(component, BitwiseAnd):
                for unit, mask in enumerate(output):
                    transition = BitwiseAndSemantics(width).xor_linear(operands[0][unit], operands[1][unit], mask)
                    if not transition.is_possible:
                        return False
                    steps.append(TrailStep(f"{component.component_id}[{unit}]", transition))
            elif isinstance(component, Xor):
                if any(operand != output for operand in operands):
                    return False
            elif isinstance(component, Identity):
                if tuple(value for operand in operands for value in operand) != output:
                    return False
            elif isinstance(component, Rotate):
                amount = component.amount if component.direction == "right" else -component.amount
                amount %= width
                expected = tuple(((mask << amount) | (mask >> (width - amount))) & ((1 << width) - 1)
                                 for mask in output)
                if operands[0] != expected:
                    return False
            elif isinstance(component, Constant):
                if sum((mask & value).bit_count() for mask, value in zip(output, component.values)) % 2:
                    constant_sign *= -1
            else:
                return False
        for output_name, (owner_id, source_bit) in zip(
            self._output, self.primitive.selection_bit_sources(self.primitive.output)
        ):
            source_type = dict(sources)[owner_id]
            source_width = source_type.domain.width
            position, bit = divmod(source_bit, source_width)
            fanout[owner_id][position] ^= values[output_name] << (source_width - 1 - bit)
        if any(tuple(fanout[name]) != units(self._ports[name], vt.domain.width) for name, vt in sources):
            return False
        inputs = tuple((name, 0 if name in self.fixed_inputs else _packed(self._ports[name], values)) for name in self.primitive.input_ports)
        input_dict = dict(inputs)
        return (trail.input_masks == inputs and trail.output_mask == _packed(self._output, values)
                and trail.steps == tuple(steps) and trail.constant_sign == constant_sign
                and trail.total_weight <= self.maximum_weight
                and (self.nonzero_input is None or input_dict[self.nonzero_input] != 0)
                and all(input_dict[name] == value for name, value in self.fixed_input_masks.items()))

    def enumerate_trails(self, solver, *, limit=1000):
        """Block semantic assignments, excluding auxiliary counter multiplicity."""
        if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
            raise ValueError("limit must be a positive integer")
        formula = self.smt_formula()
        metadata = (
            ("primitive", self.primitive.family_name),
            ("realization", getattr(getattr(self.primitive, "realization", None), "name", "default")),
            ("solver", type(solver).__name__),
            ("executable", str(getattr(solver, "executable", "embedded"))),
            ("version", solver.version() if callable(getattr(solver, "version", None)) else "unreported"),
            ("graph_sha256", sha256(repr((self.primitive.input_ports, self.primitive.bindings, tuple(self.primitive.components), self.primitive.output)).encode()).hexdigest()),
            ("formula_sha256", sha256(repr(formula).encode()).hexdigest()),
            ("fixed_inputs", repr(tuple(sorted(self.fixed_inputs.items())))),
        )
        indices = {name: i for i, name in enumerate(formula.variables, 1)}
        trails, blocks, runtime = [], [], 0.0
        context = solver.incremental(formula) if callable(getattr(solver, "incremental", None)) else nullcontext(solver)
        with context as execution:
            while True:
                current = SMTFormula(formula.variables, formula.assertions + tuple(blocks),
                                     formula.provenance + ("characteristic_block",) * len(blocks))
                result = execution.solve(current)
                runtime += result.runtime_seconds
                if result.status is SatStatus.UNSATISFIABLE:
                    return WordLinearEnumeration(tuple(trails), True, runtime, metadata)
                if result.status is not SatStatus.SATISFIABLE:
                    return WordLinearEnumeration(tuple(trails), False, runtime, metadata)
                if len(trails) == limit:
                    return WordLinearEnumeration(tuple(trails), False, runtime, metadata)
                trail = self.decode_characteristic(result.assignment)
                trails.append(trail)
                blocks.append(tuple(-indices[name] if value else indices[name]
                                    for name, value in trail.semantic_assignment))


def _packed(names, assignment):
    value = 0
    for name in names:
        value = (value << 1) | assignment[name]
    return value
