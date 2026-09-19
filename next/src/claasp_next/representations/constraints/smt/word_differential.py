"""Word-graph differential characteristics, including related-key paths."""

from contextlib import nullcontext
from dataclasses import dataclass
from hashlib import sha256
from fractions import Fraction

from claasp_next.components import BitwiseAnd, Constant, Identity, ModularAdd, Rotate, Xor
from claasp_next.domains import Word
from claasp_next.drivers.solvers import SatStatus
from claasp_next.representations.constraints.smt.formula import SMTFormula
from claasp_next.representations.constraints.smt.transitions import ModularAddDifferentialSMTModel, _xor_equivalence
from claasp_next.representations.constraints.smt.trails import _at_most
from claasp_next.semantics.cryptanalysis import BitwiseAndSemantics, ModularAddTransitionSemantics, TrailStep
from .word_linear import _packed


@dataclass(frozen=True, slots=True)
class WordDifferentialCharacteristic:
    """Component-product differential evidence, not an aggregated differential."""

    input_differences: tuple[tuple[str, int], ...]
    output_difference: int
    steps: tuple[TrailStep, ...]
    semantic_assignment: tuple[tuple[str, int], ...]

    @property
    def total_weight(self):
        return sum(step.transition.weight for step in self.steps)


@dataclass(frozen=True, slots=True)
class WordDifferentialEnumeration:
    trails: tuple[WordDifferentialCharacteristic, ...]
    complete: bool
    runtime_seconds: float
    reproducibility: tuple[tuple[str, str], ...] = ()

    def require_complete(self):
        if not self.complete:
            raise RuntimeError("differential characteristic enumeration is incomplete")
        return self

    def cluster_probability(self):
        """Sum exact component products for a complete fixed-boundary cluster.

        This is the characteristic-model probability, not an experimentally
        measured probability of the concrete primitive or an unrestricted
        differential: the declared search weight range still applies.
        """
        self.require_complete()
        boundaries = {(trail.input_differences, trail.output_difference) for trail in self.trails}
        if len(boundaries) > 1:
            raise ValueError("a differential cluster requires common fixed boundaries")
        total = Fraction(0)
        for trail in self.trails:
            probability = Fraction(1)
            for step in trail.steps:
                probability *= Fraction(step.transition.numerator, step.transition.denominator)
            total += probability
        return total


class WordDifferentialSMTModel:
    """Forward difference wiring with explicit input and weight restrictions.

    EXAMPLES::

        >>> try:
        ...     WordDifferentialSMTModel()
        ... except TypeError:
        ...     print("required configuration rejected")
        required configuration rejected
    """

    def __init__(self, primitive, *, maximum_weight=None, fixed_weight=None,
                 nonzero_input=None, fixed_input_differences=None, output_difference=None):
        if maximum_weight is not None and fixed_weight is not None:
            raise ValueError("choose a maximum or fixed weight, not both")
        for weight in (maximum_weight, fixed_weight):
            if weight is not None and (not isinstance(weight, int) or isinstance(weight, bool) or weight < 0):
                raise ValueError("weights must be nonnegative integers")
        if nonzero_input is not None and nonzero_input not in primitive.input_ports:
            raise ValueError("unknown nonzero input")
        self.primitive, self.maximum_weight, self.fixed_weight = primitive, maximum_weight, fixed_weight
        self.nonzero_input = nonzero_input
        self.fixed_input_differences = dict(fixed_input_differences or {})
        self.output_difference = output_difference
        for name, value in self.fixed_input_differences.items():
            if name not in primitive.input_ports:
                raise ValueError("unknown fixed input difference")
            self._validate(value, primitive.input_ports[name].value_type)
        if output_difference is not None:
            self._validate(output_difference, primitive.output.value_type)
        self._formula = None

    @staticmethod
    def _validate(value, value_type):
        if not isinstance(value_type.domain, Word):
            raise NotImplementedError("word differential lowering requires Word domains")
        if (not isinstance(value, int) or isinstance(value, bool)
                or not 0 <= value < 1 << (value_type.unit_count * value_type.domain.width)):
            raise ValueError("differences must fit their word type")

    def smt_formula(self):
        """Compute the smt formula for this public typed contract."""

        variables, indices, clauses, provenance = [], {}, [], []

        def allocate(name):
            if name not in indices:
                variables.append(name)
                indices[name] = len(variables)
            return name

        def add(literals, label):
            clauses.append(tuple(literals))
            provenance.append(label)

        sources = [(name, port.value_type) for name, port in self.primitive.input_ports.items()]
        sources += [(item.component_id, item.output_type) for item in self.primitive.components]
        ports = {}
        for name, value_type in sources:
            self._validate(0, value_type)
            ports[name] = tuple(allocate(f"difference_{name}_{bit}")
                                for bit in range(value_type.unit_count * value_type.domain.width))

        def selected(selection):
            return tuple(
                ports[owner_id][bit]
                for owner_id, bit in self.primitive.selection_bit_sources(selection)
            )

        weights, operands_by_id = [], {}
        for component in self.primitive.components:
            operands = tuple(selected(selection) for selection in component.inputs)
            operands_by_id[component.component_id] = operands
            output = ports[component.component_id]
            width = component.output_type.domain.width
            if isinstance(component, ModularAdd):
                if len(operands) != 2:
                    raise NotImplementedError("differential modular addition requires two operands")
                for unit in range(component.output_type.unit_count):
                    local = ModularAddDifferentialSMTModel(width).smt_formula()
                    local_names = {}
                    for prefix, names in zip(("left", "right", "output"), (*operands, output)):
                        for bit in range(width):
                            local_names[f"{prefix}_{bit}"] = names[unit * width + bit]
                    for bit in range(width - 1):
                        local_names[f"weight_{bit}"] = allocate(f"weight_{component.component_id}_{unit}_{bit}")
                        weights.append(local_names[f"weight_{bit}"])
                    mapping = {i: indices[local_names[name]] for i, name in enumerate(local.variables, 1)}
                    for clause, label in zip(local.assertions, local.provenance):
                        add((mapping[abs(lit)] * (1 if lit > 0 else -1) for lit in clause), label)
            elif isinstance(component, BitwiseAnd):
                for bit, target in enumerate(output):
                    left, right = (indices[operand[bit]] for operand in operands)
                    weight = indices[allocate(f"weight_{component.component_id}_{bit}")]
                    weights.append(variables[weight - 1])
                    add((left, right, -indices[target]), "and_differential_support")
                    add((-left, weight), "and_differential_weight")
                    add((-right, weight), "and_differential_weight")
                    add((left, right, -weight), "and_differential_weight")
            elif isinstance(component, Xor):
                for bit, target in enumerate(output):
                    _xor_equivalence((target, *(operand[bit] for operand in operands)), indices, clauses, provenance)
            elif isinstance(component, Identity):
                for source, target in zip((name for operand in operands for name in operand), output):
                    _xor_equivalence((source, target), indices, clauses, provenance)
            elif isinstance(component, Rotate):
                amount = component.amount if component.direction == "right" else -component.amount
                for unit in range(component.output_type.unit_count):
                    for bit in range(width):
                        _xor_equivalence((operands[0][unit * width + bit], output[unit * width + (bit + amount) % width]), indices, clauses, provenance)
            elif isinstance(component, Constant):
                for name in output:
                    add((-indices[name],), "zero_constant_difference")
            else:
                raise NotImplementedError(f"no word differential semantics for {type(component).__name__}")
        output = selected(self.primitive.output)
        if self.nonzero_input is not None:
            add((indices[name] for name in ports[self.nonzero_input]), "nonzero_external_difference")
        for names, value in [(ports[name], value) for name, value in self.fixed_input_differences.items()] + [(output, self.output_difference)]:
            if value is not None:
                for bit, name in enumerate(names):
                    add((indices[name] if value & (1 << (len(names) - 1 - bit)) else -indices[name],), "fixed_difference")
        self._semantic_names = tuple(variables)
        bound = self.fixed_weight if self.fixed_weight is not None else self.maximum_weight
        if bound is not None:
            _at_most(weights, bound, allocate, indices, add)
        if self.fixed_weight is not None:
            if self.fixed_weight > len(weights):
                impossible = indices[allocate("impossible_fixed_weight")]
                add((impossible,), "impossible_fixed_weight")
                add((-impossible,), "impossible_fixed_weight")
            else:
                complements = []
                for bit, name in enumerate(weights):
                    complement = allocate(f"weight_complement_{bit}")
                    add((indices[name], indices[complement]), "weight_complement")
                    add((-indices[name], -indices[complement]), "weight_complement")
                    complements.append(complement)
                _at_most(complements, len(weights) - self.fixed_weight,
                         lambda name: allocate("lower_" + name), indices, add)
        self._ports, self._operands, self._output = ports, operands_by_id, output
        self._formula = SMTFormula(tuple(variables), tuple(clauses), tuple(provenance))
        return self._formula

    def _steps_and_wiring(self, values):
        steps = []
        for component in self.primitive.components:
            width = component.output_type.domain.width
            units = lambda names: tuple(_packed(names[i:i + width], values) for i in range(0, len(names), width))
            output = units(self._ports[component.component_id])
            operands = tuple(units(names) for names in self._operands[component.component_id])
            if isinstance(component, (ModularAdd, BitwiseAnd)):
                semantics = (ModularAddTransitionSemantics(width) if isinstance(component, ModularAdd)
                             else BitwiseAndSemantics(width))
                for unit, target in enumerate(output):
                    transition = semantics.xor_differential(operands[0][unit], operands[1][unit], target)
                    if not transition.is_possible:
                        return None
                    if isinstance(component, ModularAdd):
                        for bit in range(width - 1):
                            lower = width - 2 - bit
                            triple = tuple((value >> lower) & 1 for value in (operands[0][unit], operands[1][unit], target))
                            if values[f"weight_{component.component_id}_{unit}_{bit}"] != int(not (triple[0] == triple[1] == triple[2])):
                                return None
                    else:
                        for bit in range(width):
                            if values[f"weight_{component.component_id}_{unit * width + bit}"] != ((operands[0][unit] | operands[1][unit]) >> (width - 1 - bit)) & 1:
                                return None
                    steps.append(TrailStep(f"{component.component_id}[{unit}]", transition))
            else:
                if isinstance(component, Xor):
                    from functools import reduce
                    expected = tuple(reduce(int.__xor__, items, 0) for items in zip(*operands))
                elif isinstance(component, Rotate):
                    amount = (component.amount if component.direction == "right" else -component.amount) % width
                    expected = tuple(((value >> amount) | (value << (width - amount))) & ((1 << width) - 1) for value in operands[0])
                elif isinstance(component, Constant):
                    expected = (0,) * len(output)
                else:
                    expected = tuple(value for operand in operands for value in operand)
                if output != expected:
                    return None
        return tuple(steps)

    def decode_characteristic(self, assignment):
        """Compute the decode characteristic for this public typed contract."""

        from claasp_next.representations.constraints.sat import CNFFormula
        if self._formula is None:
            raise ValueError("build the formula before decoding")
        if not CNFFormula(self._formula.variables, self._formula.assertions, self._formula.provenance).is_satisfied(assignment):
            raise ValueError("invalid word differential witness")
        result = WordDifferentialCharacteristic(
            tuple((name, _packed(self._ports[name], assignment)) for name in self.primitive.input_ports),
            _packed(self._output, assignment), self._steps_and_wiring(assignment),
            tuple((name, assignment[name]) for name in self._semantic_names),
        )
        if not self.check_characteristic(result):
            raise ValueError("word differential witness violates exact graph semantics")
        return result

    def check_characteristic(self, trail):
        """Compute the check characteristic for this public typed contract."""

        if self._formula is None:
            raise ValueError("build the formula before checking")
        values = dict(trail.semantic_assignment)
        if (len(values) != len(trail.semantic_assignment) or set(values) != set(self._semantic_names)
                or any(value not in (0, 1) for value in values.values())):
            return False
        steps = self._steps_and_wiring(values)
        inputs = tuple((name, _packed(self._ports[name], values)) for name in self.primitive.input_ports)
        output = _packed(self._output, values)
        return (steps is not None and trail.steps == steps and trail.input_differences == inputs
                and trail.output_difference == output
                and (self.maximum_weight is None or trail.total_weight <= self.maximum_weight)
                and (self.fixed_weight is None or trail.total_weight == self.fixed_weight)
                and (self.output_difference is None or output == self.output_difference)
                and (self.nonzero_input is None or dict(inputs)[self.nonzero_input] != 0)
                and all(dict(inputs)[name] == value for name, value in self.fixed_input_differences.items()))

    def enumerate_trails(self, solver, *, limit=1000):
        """Compute the enumerate trails for this public typed contract."""

        if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
            raise ValueError("limit must be a positive integer")
        formula = self.smt_formula()
        metadata = (("primitive", self.primitive.family_name),
                    ("realization", getattr(getattr(self.primitive, "realization", None), "name", "default")),
                    ("solver", type(solver).__name__), ("executable", str(getattr(solver, "executable", "embedded"))),
                    ("version", solver.version() if callable(getattr(solver, "version", None)) else "unreported"),
                    ("weight_range", repr((self.fixed_weight, self.maximum_weight))),
                    ("fixed_input_differences", repr(tuple(sorted(self.fixed_input_differences.items())))),
                    ("output_difference", repr(self.output_difference)),
                    ("graph_sha256", sha256(repr((self.primitive.input_ports, self.primitive.bindings, tuple(self.primitive.components), self.primitive.output)).encode()).hexdigest()),
                    ("formula_sha256", sha256(repr(formula).encode()).hexdigest()))
        indices = {name: index for index, name in enumerate(formula.variables, 1)}
        trails, blocks, runtime = [], [], 0.0
        context = solver.incremental(formula) if callable(getattr(solver, "incremental", None)) else nullcontext(solver)
        with context as execution:
            while True:
                current = SMTFormula(formula.variables, formula.assertions + tuple(blocks),
                                     formula.provenance + ("characteristic_block",) * len(blocks))
                result = execution.solve(current)
                runtime += result.runtime_seconds
                if result.status is SatStatus.UNSATISFIABLE:
                    return WordDifferentialEnumeration(tuple(trails), True, runtime, metadata)
                if result.status is not SatStatus.SATISFIABLE or len(trails) == limit:
                    return WordDifferentialEnumeration(tuple(trails), False, runtime, metadata)
                trail = self.decode_characteristic(result.assignment)
                trails.append(trail)
                blocks.append(tuple(-indices[name] if value else indices[name] for name, value in trail.semantic_assignment))
