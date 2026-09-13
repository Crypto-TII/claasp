"""Weighted full-trail SMT models."""

from claasp_next.analysis import (
    SBoxTransitionSemantics,
    Trail,
    TrailKind,
    TrailStep,
    XorDifference,
)
from claasp_next.components import BitVectorSBox, Permutation
from claasp_next.core import Cipher
from claasp_next.smt.formula import SMTFormula


class PresentDifferentialSMTModel:
    """Exact two-round PRESENT XOR-differential model with a weight bound."""

    def __init__(self, cipher: Cipher, maximum_weight: int) -> None:
        if cipher.family_name != "present" or len(cipher.rounds) != 2:
            raise NotImplementedError("weighted SMT trail model currently supports PRESENT-2")
        if not isinstance(maximum_weight, int) or isinstance(maximum_weight, bool) or maximum_weight < 0:
            raise ValueError("maximum_weight must be a nonnegative integer")
        self.cipher = cipher
        self.maximum_weight = maximum_weight
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
        first_sboxes = _round_sboxes(self.cipher, 1)
        second_sboxes = _round_sboxes(self.cipher, 2)
        permutation = _component(self.cipher, "p_layer_1", Permutation)
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
                semantics = SBoxTransitionSemantics(component.table)
                for source in range(16):
                    for target in range(16):
                        transition = semantics.xor_differential(source, target)
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
        components = {component.component_id: component for component in self.cipher.components}
        steps = []
        for component_id, input_names, output_names in self._transition_records:
            component = components[component_id]
            semantics = SBoxTransitionSemantics(component.table)
            source = _integer(tuple(assignment[name] for name in input_names))
            target = _integer(tuple(assignment[name] for name in output_names))
            steps.append(TrailStep(component_id, semantics.xor_differential(source, target)))
        raw_output = _integer(tuple(assignment[name] for name in self._second_output_names))
        final_permutation = _component(self.cipher, "p_layer_2", Permutation)
        output = _permute(raw_output, final_permutation.mapping)
        return Trail(
            TrailKind.XOR_DIFFERENTIAL,
            XorDifference(_integer(tuple(assignment[name] for name in self._input_names)), 64),
            XorDifference(output, 64),
            tuple(steps),
        )


def check_present_smt_trail(cipher: Cipher, trail: Trail) -> bool:
    """Check every transition, both layers' wiring, and boundary patterns."""

    if trail.kind is not TrailKind.XOR_DIFFERENTIAL or len(trail.steps) != 32:
        return False
    components = {component.component_id: component for component in cipher.components}
    for step in trail.steps:
        component = components.get(step.component_id)
        if not isinstance(component, BitVectorSBox):
            return False
        if not SBoxTransitionSemantics(component.table).check(step.transition):
            return False
    first_output = _join_nibbles(step.transition.output_pattern.value for step in trail.steps[:16])
    expected_second = _permute(
        first_output, _component(cipher, "p_layer_1", Permutation).mapping
    )
    actual_second = _join_nibbles(step.transition.input_pattern.value for step in trail.steps[16:])
    if expected_second != actual_second:
        return False
    first_input = _join_nibbles(step.transition.input_pattern.value for step in trail.steps[:16])
    second_output = _join_nibbles(step.transition.output_pattern.value for step in trail.steps[16:])
    expected_output = _permute(
        second_output, _component(cipher, "p_layer_2", Permutation).mapping
    )
    return first_input == trail.input_pattern.value and expected_output == trail.output_pattern.value


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


def _round_sboxes(cipher, round_number):
    prefix = f"sbox_{round_number}_"
    result = tuple(
        component
        for component in cipher.components
        if isinstance(component, BitVectorSBox) and component.component_id.startswith(prefix)
    )
    if len(result) != 16:
        raise ValueError(f"PRESENT round {round_number} must contain 16 state S-boxes")
    return result


def _component(cipher, component_id, expected_type):
    component = next((item for item in cipher.components if item.component_id == component_id), None)
    if not isinstance(component, expected_type):
        raise ValueError(f"cipher is missing {component_id!r}")
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
