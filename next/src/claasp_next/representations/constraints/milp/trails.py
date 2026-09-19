"""Exact weighted trail lowering to the portable MILP representation."""

from claasp_next.components import BitVectorSBox, Permutation
from claasp_next.graph import Primitive
from claasp_next.representations.constraints.milp.model import (
    ConstraintSense,
    LinearConstraint,
    LinearExpression,
    LinearVariable,
    MILPModel,
    ObjectiveSense,
    VariableKind,
)
from claasp_next.representations.constraints.smt.trails import check_present_smt_trail
from claasp_next.semantics import XOR_DIFFERENTIAL
from claasp_next.semantics.cryptanalysis import (
    PropagationProblem,
    Trail,
    TrailKind,
    TrailStep,
    XorDifference,
)


class PresentDifferentialMILPModel:
    """Exact two-round PRESENT XOR-differential optimization model.

    EXAMPLES::

        >>> try:
        ...     PresentDifferentialMILPModel()
        ... except TypeError:
        ...     print("required configuration rejected")
        required configuration rejected
    """

    def __init__(self, primitive: Primitive | PropagationProblem) -> None:
        problem = (
            primitive
            if isinstance(primitive, PropagationProblem)
            else PropagationProblem(
                primitive,
                XOR_DIFFERENTIAL,
                provenance=("PRESENT-2 MILP convenience constructor",),
            )
        )
        if problem.semantics != XOR_DIFFERENTIAL:
            raise ValueError("differential MILP lowering requires the XOR-differential semantics")
        primitive = problem.primitive
        if primitive.family_name != "present" or len(primitive.rounds) != 2:
            raise NotImplementedError("weighted MILP trail model currently supports PRESENT-2")
        self.primitive = primitive
        self.problem = problem
        self._records = ()
        self._input_names = ()
        self._last_output_names = ()

    def milp_model(self) -> MILPModel:
        """Lower graph wiring and exact DDT weights to a linear model."""

        variables: list[LinearVariable] = []
        constraints: list[LinearConstraint] = []
        objective: dict[str, float] = {}

        def binary(name):
            variables.append(LinearVariable(name, VariableKind.BINARY))
            return name

        plaintext = tuple(binary(f"plaintext_{bit}") for bit in range(64))
        first_output = tuple(binary(f"round_1_sbox_output_{bit}") for bit in range(64))
        second_output = tuple(binary(f"round_2_sbox_output_{bit}") for bit in range(64))
        permutation = _component(self.primitive, "p_layer_1", Permutation)
        second_input = tuple(first_output[position] for position in permutation.mapping)
        records = []
        for round_number, (inputs, outputs) in enumerate(
            ((plaintext, first_output), (second_input, second_output)), start=1
        ):
            for nibble, component in enumerate(_round_sboxes(self.primitive, round_number)):
                start = 4 * nibble
                local_input = inputs[start : start + 4]
                local_output = outputs[start : start + 4]
                semantics = self.problem.provider_for(component)
                choices = []
                for source in range(16):
                    for target in range(16):
                        transition = semantics.transition((source,), target)
                        if transition.is_possible:
                            selector = binary(
                                f"round_{round_number}_sbox_{nibble}_choice_{source}_{target}"
                            )
                            choices.append((selector, source, target))
                            objective[selector] = transition.weight
                constraints.append(_equal({name: 1 for name, _, _ in choices}, 1))
                for bit, name in enumerate(local_input):
                    terms = {name: 1}
                    terms.update(
                        {selector: -1 for selector, source, _ in choices if _bit(source, bit)}
                    )
                    constraints.append(_equal(terms, 0))
                for bit, name in enumerate(local_output):
                    terms = {name: 1}
                    terms.update(
                        {selector: -1 for selector, _, target in choices if _bit(target, bit)}
                    )
                    constraints.append(_equal(terms, 0))
                records.append((component.component_id, local_input, local_output))
        constraints.append(
            LinearConstraint(
                LinearExpression.from_terms({name: 1 for name in plaintext}),
                ConstraintSense.GREATER_EQUAL,
                1,
                "nonzero_input",
            )
        )
        self._records = tuple(records)
        self._input_names = plaintext
        self._last_output_names = second_output
        return MILPModel(
            tuple(variables),
            tuple(constraints),
            LinearExpression.from_terms(objective),
            ObjectiveSense.MINIMIZE,
        )

    def decode_trail(self, assignment) -> Trail:
        """Project a solver witness to the shared trail semantics."""

        if not self._records:
            raise ValueError("build the MILP model before decoding a trail")
        components = {component.component_id: component for component in self.primitive.components}
        steps = []
        for component_id, inputs, outputs in self._records:
            semantics = self.problem.provider_for(components[component_id])
            source = _integer(round(assignment[name]) for name in inputs)
            target = _integer(round(assignment[name]) for name in outputs)
            steps.append(TrailStep(component_id, semantics.transition((source,), target)))
        raw_output = _integer(round(assignment[name]) for name in self._last_output_names)
        final = _permute(raw_output, _component(self.primitive, "p_layer_2", Permutation).mapping)
        return Trail(
            TrailKind.XOR_DIFFERENTIAL,
            XorDifference(_integer(round(assignment[name]) for name in self._input_names), 64),
            XorDifference(final, 64),
            tuple(steps),
        )


def check_present_milp_trail(primitive: Primitive, trail: Trail) -> bool:
    """Independently check a decoded trail using shared semantics and wiring.

    EXAMPLES::

        >>> try:
        ...     check_present_milp_trail()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    return check_present_smt_trail(primitive, trail)


def _equal(terms, rhs):
    return LinearConstraint(LinearExpression.from_terms(terms), ConstraintSense.EQUAL, rhs)


def _bit(value, position):
    return (value >> (3 - position)) & 1


def _integer(bits):
    value = 0
    for bit in bits:
        value = (value << 1) | bit
    return value


def _permute(value, mapping):
    bits = tuple((value >> (len(mapping) - 1 - bit)) & 1 for bit in range(len(mapping)))
    return _integer(bits[position] for position in mapping)


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
    component = next(
        (item for item in primitive.components if item.component_id == component_id), None
    )
    if not isinstance(component, expected_type):
        raise ValueError(f"primitive is missing {component_id!r}")
    return component
