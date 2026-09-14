"""Weighted full-trail SMT representation lowering."""

from claasp_next.semantics.cryptanalysis import (
    PropagationProblem,
    SBoxTransitionSemantics,
    Trail,
    TrailKind,
    TrailStep,
    XorDifference,
    XorMask,
)
from claasp_next.semantics import XOR_DIFFERENTIAL, XOR_LINEAR
from claasp_next.components import BitVectorSBox, Permutation
from claasp_next.graph import Primitive
from claasp_next.representations.constraints.smt.formula import SMTFormula


class PresentDifferentialSMTModel:
    """Exact two-round PRESENT XOR-differential model with a weight bound."""

    def __init__(self, primitive: Primitive | PropagationProblem, maximum_weight: int | None = None) -> None:
        problem = (
            primitive
            if isinstance(primitive, PropagationProblem)
            else PropagationProblem(
                primitive, XOR_DIFFERENTIAL, maximum_weight=maximum_weight,
                provenance=("PRESENT-2 SMT convenience constructor",),
            )
        )
        if problem.semantics != XOR_DIFFERENTIAL:
            raise ValueError("differential SMT lowering requires the XOR-differential semantics")
        if problem.maximum_weight is None:
            raise ValueError("differential SMT lowering requires maximum_weight")
        primitive = problem.primitive
        if primitive.family_name != "present" or len(primitive.rounds) != 2:
            raise NotImplementedError("weighted SMT trail model currently supports PRESENT-2")
        maximum_weight = problem.maximum_weight
        self.primitive = primitive
        self.maximum_weight = maximum_weight
        self.problem = problem
        self._transition_records = ()
        self._input_names = ()
        self._second_output_names = ()

    def smt_formula(self) -> SMTFormula:
        """Lower graph wiring, transition support, and total-weight bound."""

        variables = []
        indices = {}
        clauses = []
        provenance = []

        def allocate(name):
            if name not in indices:
                variables.append(name)
                indices[name] = len(variables)
            return name

        def add(items, label):
            clauses.append(tuple(items))
            provenance.append(label)

        plaintext = tuple(allocate(f"plaintext_{bit}") for bit in range(64))
        first_output = tuple(allocate(f"round_1_sbox_output_{bit}") for bit in range(64))
        second_output = tuple(allocate(f"round_2_sbox_output_{bit}") for bit in range(64))
        first_sboxes = _round_sboxes(self.primitive, 1)
        second_sboxes = _round_sboxes(self.primitive, 2)
        permutation = _component(self.primitive, "p_layer_1", Permutation)
        second_input = tuple(first_output[position] for position in permutation.mapping)
        weight_names = []
        records = []
        for round_number, (inputs, outputs, sboxes) in enumerate((
            (plaintext, first_output, first_sboxes),
            (second_input, second_output, second_sboxes),
        ), start=1):
            for nibble, component in enumerate(sboxes):
                start = 4 * nibble
                input_names = inputs[start : start + 4]
                output_names = outputs[start : start + 4]
                local_weights = tuple(
                    allocate(f"round_{round_number}_sbox_{nibble}_weight_{bit}")
                    for bit in range(3)
                )
                weight_names.extend(local_weights)
                records.append((component.component_id, input_names, output_names))
                semantics = self.problem.provider_for(component)
                for source in range(16):
                    for target in range(16):
                        transition = semantics.transition((source,), target)
                        assignment = _bits(source, 4) + _bits(target, 4)
                        forbid = tuple(
                            -indices[name] if value else indices[name]
                            for name, value in zip(input_names + output_names, assignment)
                        )
                        if not transition.is_possible:
                            add(forbid, f"{component.component_id}_support")
                            continue
                        weight = int(transition.weight)
                        for bit, name in enumerate(local_weights):
                            expected = bit < weight
                            add(
                                forbid + ((indices[name] if expected else -indices[name]),),
                                f"{component.component_id}_weight",
                            )
        add(tuple(indices[name] for name in plaintext), "nonzero_input")
        _at_most(
            weight_names,
            self.maximum_weight,
            allocate,
            indices,
            add,
        )
        self._transition_records = tuple(records)
        self._input_names = plaintext
        self._second_output_names = second_output
        return SMTFormula(tuple(variables), tuple(clauses), tuple(provenance))

    def decode_trail(self, assignment: dict[str, int]) -> Trail:
        """Project a satisfying assignment to shared, independently checkable semantics."""

        if not self._transition_records:
            raise ValueError("build the SMT formula before decoding a trail")
        components = {component.component_id: component for component in self.primitive.components}
        steps = []
        for component_id, input_names, output_names in self._transition_records:
            component = components[component_id]
            semantics = self.problem.provider_for(component)
            source = _integer(tuple(assignment[name] for name in input_names))
            target = _integer(tuple(assignment[name] for name in output_names))
            steps.append(TrailStep(component_id, semantics.transition((source,), target)))
        raw_output = _integer(tuple(assignment[name] for name in self._second_output_names))
        final_permutation = _component(self.primitive, "p_layer_2", Permutation)
        output = _permute(raw_output, final_permutation.mapping)
        return Trail(
            TrailKind.XOR_DIFFERENTIAL,
            XorDifference(_integer(tuple(assignment[name] for name in self._input_names)), 64),
            XorDifference(output, 64),
            tuple(steps),
        )


class PresentLinearSMTModel:
    """Exact three-round PRESENT XOR-linear model with a weight bound."""

    def __init__(self, primitive: Primitive | PropagationProblem, maximum_weight: int | None = None) -> None:
        problem = (
            primitive
            if isinstance(primitive, PropagationProblem)
            else PropagationProblem(
                primitive, XOR_LINEAR, maximum_weight=maximum_weight,
                provenance=("PRESENT-3 SMT convenience constructor",),
            )
        )
        if problem.semantics != XOR_LINEAR:
            raise ValueError("linear SMT lowering requires the XOR-linear semantics")
        if problem.maximum_weight is None:
            raise ValueError("linear SMT lowering requires maximum_weight")
        primitive = problem.primitive
        if primitive.family_name != "present" or len(primitive.rounds) != 3:
            raise NotImplementedError("weighted linear SMT model currently supports PRESENT-3")
        maximum_weight = problem.maximum_weight
        self.primitive = primitive
        self.maximum_weight = maximum_weight
        self.problem = problem
        self._transition_records = ()
        self._input_names = ()
        self._last_output_names = ()

    def smt_formula(self) -> SMTFormula:
        """Lower three signed-LAT support layers and their weight bound."""

        variables = []
        indices = {}
        clauses = []
        provenance = []

        def allocate(name):
            if name not in indices:
                variables.append(name)
                indices[name] = len(variables)
            return name

        def add(items, label):
            clauses.append(tuple(items))
            provenance.append(label)

        input_names = tuple(allocate(f"plaintext_mask_{bit}") for bit in range(64))
        current_input = input_names
        records = []
        weight_names = []
        last_output = ()
        for round_number in range(1, 4):
            output_names = tuple(
                allocate(f"round_{round_number}_sbox_mask_{bit}") for bit in range(64)
            )
            for nibble, component in enumerate(_round_sboxes(self.primitive, round_number)):
                start = 4 * nibble
                local_input = current_input[start : start + 4]
                local_output = output_names[start : start + 4]
                local_weights = tuple(
                    allocate(f"round_{round_number}_linear_{nibble}_weight_{bit}")
                    for bit in range(2)
                )
                weight_names.extend(local_weights)
                records.append((component.component_id, local_input, local_output))
                semantics = self.problem.provider_for(component)
                for source in range(16):
                    for target in range(16):
                        transition = semantics.transition((source,), target)
                        assignment = _bits(source, 4) + _bits(target, 4)
                        forbid = tuple(
                            -indices[name] if value else indices[name]
                            for name, value in zip(local_input + local_output, assignment)
                        )
                        if not transition.is_possible:
                            add(forbid, f"{component.component_id}_linear_support")
                            continue
                        weight = int(transition.weight)
                        for bit, name in enumerate(local_weights):
                            add(
                                forbid
                                + ((indices[name] if bit < weight else -indices[name]),),
                                f"{component.component_id}_linear_weight",
                            )
            permutation = _component(self.primitive, f"p_layer_{round_number}", Permutation)
            current_input = tuple(output_names[position] for position in permutation.mapping)
            last_output = output_names
        add(tuple(indices[name] for name in input_names), "nonzero_linear_input")
        _at_most(weight_names, self.maximum_weight, allocate, indices, add)
        self._transition_records = tuple(records)
        self._input_names = input_names
        self._last_output_names = last_output
        return SMTFormula(tuple(variables), tuple(clauses), tuple(provenance))

    def decode_trail(self, assignment: dict[str, int]) -> Trail:
        """Project a model to shared transitions, including correlation signs."""

        if not self._transition_records:
            raise ValueError("build the SMT formula before decoding a trail")
        components = {component.component_id: component for component in self.primitive.components}
        steps = []
        for component_id, input_names, output_names in self._transition_records:
            component = components[component_id]
            semantics = self.problem.provider_for(component)
            source = _integer(tuple(assignment[name] for name in input_names))
            target = _integer(tuple(assignment[name] for name in output_names))
            steps.append(TrailStep(component_id, semantics.transition((source,), target)))
        raw_output = _integer(tuple(assignment[name] for name in self._last_output_names))
        final_output = _permute(
            raw_output, _component(self.primitive, "p_layer_3", Permutation).mapping
        )
        return Trail(
            TrailKind.XOR_LINEAR,
            XorMask(_integer(tuple(assignment[name] for name in self._input_names)), 64),
            XorMask(final_output, 64),
            tuple(steps),
        )


def check_present_smt_trail(primitive: Primitive, trail: Trail) -> bool:
    """Check every transition, both layers' wiring, and boundary patterns."""

    if trail.kind is not TrailKind.XOR_DIFFERENTIAL or len(trail.steps) != 32:
        return False
    components = {component.component_id: component for component in primitive.components}
    for step in trail.steps:
        component = components.get(step.component_id)
        if not isinstance(component, BitVectorSBox):
            return False
        if not SBoxTransitionSemantics(component.table).check(step.transition):
            return False
    first_output = _join_nibbles(step.transition.output_pattern.value for step in trail.steps[:16])
    expected_second = _permute(
        first_output, _component(primitive, "p_layer_1", Permutation).mapping
    )
    actual_second = _join_nibbles(step.transition.input_pattern.value for step in trail.steps[16:])
    if expected_second != actual_second:
        return False
    first_input = _join_nibbles(step.transition.input_pattern.value for step in trail.steps[:16])
    second_output = _join_nibbles(step.transition.output_pattern.value for step in trail.steps[16:])
    expected_output = _permute(
        second_output, _component(primitive, "p_layer_2", Permutation).mapping
    )
    return first_input == trail.input_pattern.value and expected_output == trail.output_pattern.value


def check_present_linear_smt_trail(primitive: Primitive, trail: Trail) -> bool:
    """Check 48 signed LAT entries and all three permutation boundaries."""

    if trail.kind is not TrailKind.XOR_LINEAR or len(trail.steps) != 48:
        return False
    components = {component.component_id: component for component in primitive.components}
    for step in trail.steps:
        component = components.get(step.component_id)
        if not isinstance(component, BitVectorSBox):
            return False
        if not SBoxTransitionSemantics(component.table).check(step.transition):
            return False
    state = _join_nibbles(step.transition.input_pattern.value for step in trail.steps[:16])
    if state != trail.input_pattern.value:
        return False
    for round_index in range(3):
        layer = trail.steps[16 * round_index : 16 * (round_index + 1)]
        actual_input = _join_nibbles(step.transition.input_pattern.value for step in layer)
        if actual_input != state:
            return False
        output = _join_nibbles(step.transition.output_pattern.value for step in layer)
        state = _permute(
            output,
            _component(primitive, f"p_layer_{round_index + 1}", Permutation).mapping,
        )
    return state == trail.output_pattern.value


def _at_most(names, bound, allocate, indices, add):
    if bound >= len(names):
        return
    if bound == 0:
        for name in names:
            add((-indices[name],), "weight_bound")
        return
    previous = ()
    for position, name in enumerate(names):
        current = tuple(
            allocate(f"__weight_counter_{position}_{count}")
            for count in range(1, bound + 1)
        )
        add((-indices[name], indices[current[0]]), "weight_bound")
        if previous:
            for count in range(bound):
                add((-indices[previous[count]], indices[current[count]]), "weight_bound")
            for count in range(1, bound):
                add(
                    (-indices[name], -indices[previous[count - 1]], indices[current[count]]),
                    "weight_bound",
                )
            add((-indices[name], -indices[previous[-1]]), "weight_bound")
        previous = current


def _round_sboxes(primitive, round_number):
    prefix = f"sbox_{round_number}_"
    result = tuple(
        component
        for component in primitive.components
        if isinstance(component, BitVectorSBox) and component.component_id.startswith(prefix)
    )
    if len(result) != 16:
        raise ValueError(f"PRESENT round {round_number} must contain 16 state S-boxes")
    return result


def _component(primitive, component_id, expected_type):
    component = next((item for item in primitive.components if item.component_id == component_id), None)
    if not isinstance(component, expected_type):
        raise ValueError(f"primitive is missing {component_id!r}")
    return component


def _bits(value, width):
    return tuple((value >> (width - 1 - bit)) & 1 for bit in range(width))


def _integer(bits):
    value = 0
    for bit in bits:
        value = (value << 1) | bit
    return value


def _join_nibbles(values):
    return _integer(tuple(bit for value in values for bit in _bits(value, 4)))


def _permute(value, mapping):
    bits = _bits(value, len(mapping))
    return _integer(tuple(bits[position] for position in mapping))
