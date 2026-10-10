"""Weighted full-trail SMT representation lowering."""

from contextlib import nullcontext
from dataclasses import dataclass
from fractions import Fraction
from hashlib import sha256

from claasp.components import (
    BitVectorSBox,
    BitwiseAnd,
    Constant,
    Identity,
    ModularAdd,
    Permutation,
    Rotate,
    Xor,
)
from claasp.domains import Word
from claasp.drivers.solvers import SatStatus
from claasp.graph import Primitive
from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _direct_model,
)
from claasp.representations.constraints.smt.components.modular_add import (
    ModularAddDifferentialSMTModel,
    ModularAddLinearSMTModel,
    _xor_equivalence,
)
from claasp.representations.constraints.smt.model import SMTFormula
from claasp.semantics import XOR_DIFFERENTIAL, XOR_LINEAR
from claasp.semantics.cryptanalysis import (
    BitwiseAndSemantics,
    ModularAddLinearSemantics,
    ModularAddTransitionSemantics,
    PropagationProblem,
    SBoxTransitionSemantics,
    Trail,
    TrailKind,
    TrailStep,
    XorDifference,
    XorMask,
)


def _component_applications(primitive, default, specialized=()):
    """Group graph components by the concrete encoding that lowered them."""

    grouped = {model: [] for _, model in specialized}
    grouped[default] = []
    for component in primitive.graph.components:
        model = next(
            (
                model
                for component_type, model in specialized
                if isinstance(component, component_type)
            ),
            default,
        )
        grouped[model].append(component.component_id)
    return tuple(
        ConstraintModelApplication(model, tuple(component_ids))
        for model, component_ids in grouped.items()
        if component_ids
    )


class PresentDifferentialSMTModel:
    """Exact two-round PRESENT XOR-differential model with a weight bound.

    EXAMPLES::

        >>> from claasp.primitives import Present
        >>> model = PresentDifferentialSMTModel(Present(number_of_rounds=2), 4)
        >>> formula = model.smt_formula()
        >>> (len(formula.variables) < 700, formula.assertion_count < 30000)
        (True, True)
    """

    model_provenance = _direct_model(
        ConstraintBackend.SMT,
        "PresentDifferentialSMTModel",
        "xor_differential",
        "exhaustive S-box transition clauses",
        "The S-box support and weights are enumerated directly from the supplied table.",
    )

    def __init__(
        self, primitive: Primitive | PropagationProblem, maximum_weight: int | None = None
    ) -> None:
        problem = (
            primitive
            if isinstance(primitive, PropagationProblem)
            else PropagationProblem(
                primitive,
                XOR_DIFFERENTIAL,
                maximum_weight=maximum_weight,
                provenance=("PRESENT-2 SMT convenience constructor",),
            )
        )
        if problem.semantics != XOR_DIFFERENTIAL:
            raise ValueError("differential SMT lowering requires the XOR-differential semantics")
        if problem.maximum_weight is None:
            raise ValueError("differential SMT lowering requires maximum_weight")
        primitive = problem.primitive
        if primitive.family_name != "present" or len(primitive.graph.rounds) != 2:
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
        for round_number, (inputs, outputs, sboxes) in enumerate(
            (
                (plaintext, first_output, first_sboxes),
                (second_input, second_output, second_sboxes),
            ),
            start=1,
        ):
            for nibble, component in enumerate(sboxes):
                start = 4 * nibble
                input_names = inputs[start : start + 4]
                output_names = outputs[start : start + 4]
                local_weights = tuple(
                    allocate(f"round_{round_number}_sbox_{nibble}_weight_{bit}") for bit in range(3)
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
        return SMTFormula(
            tuple(variables),
            tuple(clauses),
            tuple(provenance),
            (
                ConstraintModelApplication(
                    self.model_provenance,
                    tuple(component_id for component_id, _, _ in self._transition_records),
                ),
            ),
        )

    def decode_trail(self, assignment: dict[str, int]) -> Trail:
        """Project a satisfying assignment to shared, independently checkable semantics."""

        if not self._transition_records:
            raise ValueError("build the SMT formula before decoding a trail")
        components = {
            component.component_id: component for component in self.primitive.graph.components
        }
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
    """Exact three-round PRESENT XOR-linear model with a weight bound.

    EXAMPLES::

        >>> from claasp.primitives import Present
        >>> model = PresentLinearSMTModel(Present(number_of_rounds=3), 4)
        >>> formula = model.smt_formula()
        >>> (len(formula.variables) < 1000, formula.assertion_count < 40000)
        (True, True)
    """

    model_provenance = _direct_model(
        ConstraintBackend.SMT,
        "PresentLinearSMTModel",
        "xor_linear",
        "exhaustive S-box transition clauses",
        "The signed S-box support and weights are enumerated directly from the supplied table.",
    )

    def __init__(
        self, primitive: Primitive | PropagationProblem, maximum_weight: int | None = None
    ) -> None:
        problem = (
            primitive
            if isinstance(primitive, PropagationProblem)
            else PropagationProblem(
                primitive,
                XOR_LINEAR,
                maximum_weight=maximum_weight,
                provenance=("PRESENT-3 SMT convenience constructor",),
            )
        )
        if problem.semantics != XOR_LINEAR:
            raise ValueError("linear SMT lowering requires the XOR-linear semantics")
        if problem.maximum_weight is None:
            raise ValueError("linear SMT lowering requires maximum_weight")
        primitive = problem.primitive
        if primitive.family_name != "present" or len(primitive.graph.rounds) != 3:
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
                                forbid + ((indices[name] if bit < weight else -indices[name]),),
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
        return SMTFormula(
            tuple(variables),
            tuple(clauses),
            tuple(provenance),
            (
                ConstraintModelApplication(
                    self.model_provenance,
                    tuple(component_id for component_id, _, _ in self._transition_records),
                ),
            ),
        )

    def decode_trail(self, assignment: dict[str, int]) -> Trail:
        """Project a model to shared transitions, including correlation signs."""

        if not self._transition_records:
            raise ValueError("build the SMT formula before decoding a trail")
        components = {
            component.component_id: component for component in self.primitive.graph.components
        }
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
    components = {component.component_id: component for component in primitive.graph.components}
    for step in trail.steps:
        component = components.get(step.component_id)
        if not isinstance(component, BitVectorSBox):
            return False
        if not SBoxTransitionSemantics(
            component.table, output_width=component.output_bit_size
        ).check(step.transition):
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
    return (
        first_input == trail.input_pattern.value and expected_output == trail.output_pattern.value
    )


def check_present_linear_smt_trail(primitive: Primitive, trail: Trail) -> bool:
    """Check 48 signed LAT entries and all three permutation boundaries."""

    if trail.kind is not TrailKind.XOR_LINEAR or len(trail.steps) != 48:
        return False
    components = {component.component_id: component for component in primitive.graph.components}
    for step in trail.steps:
        component = components.get(step.component_id)
        if not isinstance(component, BitVectorSBox):
            return False
        if not SBoxTransitionSemantics(
            component.table, output_width=component.output_bit_size
        ).check(step.transition):
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
            allocate(f"__weight_counter_{position}_{count}") for count in range(1, bound + 1)
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
        for component in primitive.graph.components
        if isinstance(component, BitVectorSBox) and component.component_id.startswith(prefix)
    )
    if len(result) != 16:
        raise ValueError(f"PRESENT round {round_number} must contain 16 state S-boxes")
    return result


def _component(primitive, component_id, expected_type):
    component = next(
        (item for item in primitive.graph.components if item.component_id == component_id), None
    )
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


class SpeckLinearSMTModel:
    """Compose data-path masks with zero round-key masks and explicit weights.

    The plaintext mask is nonzero. Key-schedule masks and related-key linear
    characteristics are deliberately outside this model's scope.


    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> model = SpeckLinearSMTModel(Speck(number_of_rounds=3), maximum_weight=1)
        >>> "nonzero_linear_input" in model.smt_formula().provenance
        True
    """

    model_provenance = _direct_model(
        ConstraintBackend.SMT,
        "SpeckLinearSMTModel",
        "xor_linear",
        "direct graph-mask composition",
        "Rotation and XOR mask relations are expressed directly from graph wiring.",
    )

    def __init__(
        self,
        primitive,
        *,
        maximum_weight=None,
        fixed_weight=None,
        input_mask=None,
        output_mask=None,
    ):
        plaintext = primitive.graph.input_ports.get("plaintext")
        if (
            primitive.family_name != "speck"
            or plaintext is None
            or not isinstance(plaintext.value_type.domain, Word)
            or not primitive.graph.rounds
        ):
            raise NotImplementedError("linear SMT composition requires a typed Speck primitive")
        if maximum_weight is not None and fixed_weight is not None:
            raise ValueError("choose maximum_weight or fixed_weight, not both")
        for weight in (maximum_weight, fixed_weight):
            if weight is not None and (
                not isinstance(weight, int) or isinstance(weight, bool) or weight < 0
            ):
                raise ValueError("weights must be nonnegative integers")
        self.primitive = primitive
        self.width = plaintext.value_type.domain.width
        for mask in (input_mask, output_mask):
            if mask is not None and (
                not isinstance(mask, int)
                or isinstance(mask, bool)
                or not 0 <= mask < (1 << (2 * self.width))
            ):
                raise ValueError("boundary masks must fit the primitive block width")
        self.input_mask = input_mask
        self.output_mask = output_mask
        self.maximum_weight = maximum_weight
        self.fixed_weight = fixed_weight
        self._states = ()

    def smt_formula(self):
        """Build deterministic Boolean constraints and sequential weight bounds."""
        variables, indices, clauses, provenance = [], {}, [], []

        def allocate(name):
            if name not in indices:
                variables.append(name)
                indices[name] = len(variables)
            return name

        def add(items, label):
            clauses.append(tuple(items))
            provenance.append(label)

        width = self.width
        states = tuple(
            tuple(allocate(f"state_{r}_{bit}") for bit in range(2 * width))
            for r in range(len(self.primitive.graph.rounds) + 1)
        )
        weights = []
        for r in range(len(self.primitive.graph.rounds)):
            local = ModularAddLinearSMTModel(width).smt_formula()
            mapping = {
                i: indices[allocate(f"round_{r}_{name}")]
                for i, name in enumerate(local.variables, 1)
            }
            for clause, label in zip(local.assertions, local.provenance):
                add(
                    (mapping[abs(literal)] * (1 if literal > 0 else -1) for literal in clause),
                    label,
                )
            alpha = self._rotation(r, "right")
            beta = self._rotation(r, "left")
            for bit in range(width):
                relations = (
                    (f"round_{r}_left_{bit}", states[r][(bit - alpha) % width]),
                    (
                        f"round_{r}_right_{bit}",
                        states[r][width + bit],
                        states[r + 1][width + (bit - beta) % width],
                    ),
                    (f"round_{r}_output_{bit}", states[r + 1][bit], states[r + 1][width + bit]),
                )
                for names in relations:
                    _xor_equivalence(names, indices, clauses, provenance)
                weights.append(f"round_{r}_weight_{bit}")
        add((indices[name] for name in states[0]), "nonzero_linear_input")
        for names, mask, label in (
            (states[0], self.input_mask, "fixed_linear_input"),
            (states[-1], self.output_mask, "fixed_linear_output"),
        ):
            if mask is not None:
                for bit, name in enumerate(names):
                    value = (mask >> (2 * width - 1 - bit)) & 1
                    add((indices[name] if value else -indices[name],), label)
        bound = self.fixed_weight if self.fixed_weight is not None else self.maximum_weight
        if bound is not None:
            _at_most(weights, bound, allocate, indices, add)
        if self.fixed_weight is not None:
            complements = tuple(allocate(f"not_{name}") for name in weights)
            for name, complement in zip(weights, complements):
                add((indices[name], indices[complement]), "weight_complement")
                add((-indices[name], -indices[complement]), "weight_complement")
            if self.fixed_weight > len(weights):
                add((indices[weights[0]],), "impossible_fixed_weight")
                add((-indices[weights[0]],), "impossible_fixed_weight")
            else:
                _at_most(
                    complements,
                    len(weights) - self.fixed_weight,
                    lambda name: allocate("lower" + name),
                    indices,
                    add,
                )
        self._states = states
        return SMTFormula(
            tuple(variables),
            tuple(clauses),
            tuple(provenance),
            _component_applications(
                self.primitive,
                self.model_provenance,
                ((ModularAdd, ModularAddLinearSMTModel.model_provenance),),
            ),
        )

    def decode_trail(self, assignment):
        """Recount correlations and reject invalid wiring or requested weights."""

        from claasp.analysis.arx import check_speck_linear_trail

        if not self._states:
            raise ValueError("build the SMT formula before decoding a trail")
        steps = []
        for r in range(len(self.primitive.graph.rounds)):
            local = ModularAddLinearSMTModel(self.width)
            projected = {
                name: assignment[f"round_{r}_{name}"] for name in local.smt_formula().variables
            }
            component_id = self.primitive.graph._intermediate_components[r][
                "modular_add"
            ].component_id
            steps.append(TrailStep(component_id, local.decode_transition(projected)))

        def packed(names):
            value = 0
            for name in names:
                value = (value << 1) | assignment[name]
            return value

        trail = Trail(
            TrailKind.XOR_LINEAR,
            XorMask(packed(self._states[0]), 2 * self.width),
            XorMask(packed(self._states[-1]), 2 * self.width),
            tuple(steps),
        )
        if (
            not trail.input_pattern.value
            or not check_speck_linear_trail(self.primitive, trail)
            or (self.maximum_weight is not None and trail.total_weight > self.maximum_weight)
            or (self.fixed_weight is not None and trail.total_weight != self.fixed_weight)
            or (self.input_mask is not None and trail.input_pattern.value != self.input_mask)
            or (self.output_mask is not None and trail.output_pattern.value != self.output_mask)
        ):
            raise ValueError("assignment disagrees with Speck linear semantics or weight")
        return trail

    def _rotation(self, round_number, direction):
        component = self.primitive.graph._intermediate_components[round_number][
            f"rotate_{direction}"
        ]
        if not isinstance(component, Rotate):
            raise ValueError(f"Speck round {round_number} is missing its {direction} rotation")
        return component.amount


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

        >>> from claasp.primitives import ToySpeck
        >>> model = WordLinearSMTModel(
        ...     ToySpeck(), maximum_weight=2, nonzero_input="key"
        ... )
        >>> "nonzero_external_mask" in model.smt_formula().provenance
        True
    """

    model_provenance = _direct_model(
        ConstraintBackend.SMT,
        "WordLinearSMTModel",
        "xor_linear",
        "direct word-graph mask composition",
        "Non-addition component relations are derived directly from graph wiring and truth tables.",
    )

    def __init__(
        self,
        primitive,
        *,
        maximum_weight,
        nonzero_input=None,
        fixed_input_masks=None,
        fixed_inputs=None,
    ):
        if (
            not isinstance(maximum_weight, int)
            or isinstance(maximum_weight, bool)
            or maximum_weight < 0
        ):
            raise ValueError("maximum_weight must be a nonnegative integer")
        self.primitive = primitive
        self.maximum_weight = maximum_weight
        self.nonzero_input = nonzero_input
        self.fixed_input_masks = dict(fixed_input_masks or {})
        self.fixed_inputs = dict(fixed_inputs or {})
        for name, value in self.fixed_inputs.items():
            if name not in primitive.graph.input_ports:
                raise ValueError("unknown fixed concrete input")
            primitive._decode_boundary(value, primitive.graph.input_ports[name].value_type)
        if nonzero_input in self.fixed_inputs:
            raise ValueError("a concrete fixed input cannot have a nonzero external mask")
        if nonzero_input is not None and nonzero_input not in primitive.graph.input_ports:
            raise ValueError("unknown nonzero input")
        for name, value in self.fixed_input_masks.items():
            if name not in primitive.graph.input_ports:
                raise ValueError("unknown fixed input")
            value_type = primitive.graph.input_ports[name].value_type
            if (
                not isinstance(value_type.domain, Word)
                or not isinstance(value, int)
                or isinstance(value, bool)
                or not 0 <= value < (1 << (value_type.unit_count * value_type.domain.width))
            ):
                raise ValueError("fixed masks must fit the input word type")
        self._formula = None

    def _constant_subgraph(self):
        """Fold only nodes whose complete dependency set has concrete fixed inputs."""
        if not self.fixed_inputs:
            return {}
        trace = self.primitive.evaluate_with_trace(
            {name: self.fixed_inputs.get(name, 0) for name in self.primitive.graph.input_ports}
        ).trace
        known = {name: tuple(trace.value_of(name)) for name in self.fixed_inputs}
        for component in self.primitive.graph.components:
            if all(
                all(
                    owner_id in known
                    for owner_id, _ in self.primitive.graph.selection_bit_sources(selection)
                )
                for selection in component.inputs
            ):
                known[component.component_id] = tuple(trace.value_of(component.component_id))
        return known

    @staticmethod
    def _names(prefix, value_type):
        if not isinstance(value_type.domain, Word):
            raise NotImplementedError("word linear lowering requires Word domains")
        return tuple(
            f"{prefix}_{bit}" for bit in range(value_type.unit_count * value_type.domain.width)
        )

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

        sources = [
            (name, port.value_type) for name, port in self.primitive.graph.input_ports.items()
        ]
        sources += [
            (item.component_id, item.output_type) for item in self.primitive.graph.components
        ]
        ports = {
            name: tuple(allocate(n) for n in self._names(f"mask_{name}", vt))
            for name, vt in sources
        }
        consumers = {name: [[] for _ in names] for name, names in ports.items()}
        edges, records, weights = {}, [], []
        folded = self._constant_subgraph()
        for component in self.primitive.graph.components:
            if component.component_id in folded:
                edges[component.component_id] = ()
                continue
            operands = []
            for operand, selection in enumerate(component.inputs):
                names = tuple(
                    allocate(n)
                    for n in self._names(
                        f"edge_{component.component_id}_{operand}", selection.value_type
                    )
                )
                operands.append(names)
                for edge_name, (owner_id, source_bit) in zip(
                    names, self.primitive.graph.selection_bit_sources(selection)
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
                    mapping = {
                        i: indices[local_names[name]] for i, name in enumerate(local.variables, 1)
                    }
                    for clause, label in zip(local.assertions, local.provenance):
                        add(
                            (
                                mapping[abs(literal)] * (1 if literal > 0 else -1)
                                for literal in clause
                            ),
                            label,
                        )
                    groups = [operand[unit * width : (unit + 1) * width] for operand in operands]
                    groups.append(output[unit * width : (unit + 1) * width])
                    for label, names in zip(("left", "right", "output"), groups):
                        for bit, name in enumerate(names):
                            _xor_equivalence(
                                (name, local_names[f"{label}_{bit}"]), indices, clauses, provenance
                            )
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
                        _xor_equivalence(
                            (
                                operands[0][unit * width + bit],
                                output[unit * width + (bit + amount) % width],
                            ),
                            indices,
                            clauses,
                            provenance,
                        )
            elif not isinstance(component, Constant):
                raise NotImplementedError(
                    f"no word linear semantics for {type(component).__name__}"
                )
        output = tuple(
            allocate(n)
            for n in self._names("external_output", self.primitive.graph.output.value_type)
        )
        for output_name, (owner_id, source_bit) in zip(
            output, self.primitive.graph.selection_bit_sources(self.primitive.graph.output)
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
                add(
                    (literal if value & (1 << (len(ports[name]) - 1 - bit)) else -literal,),
                    "fixed_external_mask",
                )
        semantic_names = tuple(variables)
        _at_most(weights, self.maximum_weight, allocate, indices, add)
        self._ports, self._edges, self._records, self._output = ports, edges, records, output
        self._folded_values = folded
        self._semantic_names = semantic_names
        self._formula = SMTFormula(
            tuple(variables),
            tuple(clauses),
            tuple(provenance),
            _component_applications(
                self.primitive,
                self.model_provenance,
                ((ModularAdd, ModularAddLinearSMTModel.model_provenance),),
            ),
        )
        return self._formula

    def decode_characteristic(self, assignment):
        """Validate the full Boolean witness and independently recount additions."""
        if self._formula is None:
            raise ValueError("build the formula before decoding")
        from claasp.representations.constraints.sat import CNFFormula

        if not CNFFormula(
            self._formula.variables, self._formula.assertions, self._formula.provenance
        ).is_satisfied(assignment):
            raise ValueError("invalid word linear witness")
        steps = []
        for component_id, unit, width, prefix in self._records:
            if prefix is None:
                masks = [
                    _packed(names[unit * width : (unit + 1) * width], assignment)
                    for names in self._edges[component_id]
                ]
                output = _packed(
                    self._ports[component_id][unit * width : (unit + 1) * width], assignment
                )
                transition = BitwiseAndSemantics(width).xor_linear(*masks, output)
            else:
                local = ModularAddLinearSMTModel(width)
                projected = {
                    name: assignment[f"{prefix}_{name}"] for name in local.smt_formula().variables
                }
                transition = local.decode_transition(projected)
            steps.append(TrailStep(f"{component_id}[{unit}]", transition))
        constant_sign = 1
        for name in self.fixed_inputs:
            for unit, value in enumerate(self._folded_values[name]):
                width = self.primitive.graph.input_ports[name].value_type.domain.width
                mask = _packed(self._ports[name][unit * width : (unit + 1) * width], assignment)
                if (mask & value).bit_count() % 2:
                    constant_sign *= -1
        for component in self.primitive.graph.components:
            if isinstance(component, Constant) or component.component_id in self._folded_values:
                value = 0
                for unit in self._folded_values.get(
                    component.component_id, getattr(component, "values", ())
                ):
                    value = (value << component.output_type.domain.width) | unit
                if (
                    value & _packed(self._ports[component.component_id], assignment)
                ).bit_count() % 2:
                    constant_sign *= -1
        result = WordLinearCharacteristic(
            tuple(
                (name, 0 if name in self.fixed_inputs else _packed(self._ports[name], assignment))
                for name in self.primitive.graph.input_ports
            ),
            _packed(self._output, assignment),
            tuple(steps),
            constant_sign,
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
        if (
            len(values) != len(trail.semantic_assignment)
            or set(values) != set(self._semantic_names)
            or any(value not in (0, 1) for value in values.values())
        ):
            return False
        sources = [
            (name, port.value_type) for name, port in self.primitive.graph.input_ports.items()
        ]
        sources += [
            (item.component_id, item.output_type) for item in self.primitive.graph.components
        ]
        fanout = {name: [0] * vt.unit_count for name, vt in sources}
        steps, constant_sign = [], 1

        def units(names, width):
            return tuple(_packed(names[i : i + width], values) for i in range(0, len(names), width))

        for name in self.fixed_inputs:
            masks = units(
                self._ports[name], self.primitive.graph.input_ports[name].value_type.domain.width
            )
            if (
                sum(
                    (mask & value).bit_count()
                    for mask, value in zip(masks, self._folded_values[name])
                )
                % 2
            ):
                constant_sign *= -1

        for component in self.primitive.graph.components:
            width = component.output_type.domain.width
            output = units(self._ports[component.component_id], width)
            operands = [
                units(names, selection.value_type.domain.width)
                for names, selection in zip(self._edges[component.component_id], component.inputs)
            ]
            for selection, edge_names in zip(component.inputs, self._edges[component.component_id]):
                for edge_name, (owner_id, source_bit) in zip(
                    edge_names, self.primitive.graph.selection_bit_sources(selection)
                ):
                    source_type = dict(sources)[owner_id]
                    source_width = source_type.domain.width
                    position, bit = divmod(source_bit, source_width)
                    fanout[owner_id][position] ^= values[edge_name] << (source_width - 1 - bit)
            if component.component_id in self._folded_values:
                if (
                    sum(
                        (mask & value).bit_count()
                        for mask, value in zip(output, self._folded_values[component.component_id])
                    )
                    % 2
                ):
                    constant_sign *= -1
            elif isinstance(component, ModularAdd):
                for unit, mask in enumerate(output):
                    transition = ModularAddLinearSemantics(width).xor_linear(
                        operands[0][unit], operands[1][unit], mask
                    )
                    if not transition.is_possible:
                        return False
                    steps.append(TrailStep(f"{component.component_id}[{unit}]", transition))
            elif isinstance(component, BitwiseAnd):
                for unit, mask in enumerate(output):
                    transition = BitwiseAndSemantics(width).xor_linear(
                        operands[0][unit], operands[1][unit], mask
                    )
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
                expected = tuple(
                    ((mask << amount) | (mask >> (width - amount))) & ((1 << width) - 1)
                    for mask in output
                )
                if operands[0] != expected:
                    return False
            elif isinstance(component, Constant):
                if (
                    sum((mask & value).bit_count() for mask, value in zip(output, component.values))
                    % 2
                ):
                    constant_sign *= -1
            else:
                return False
        for output_name, (owner_id, source_bit) in zip(
            self._output, self.primitive.graph.selection_bit_sources(self.primitive.graph.output)
        ):
            source_type = dict(sources)[owner_id]
            source_width = source_type.domain.width
            position, bit = divmod(source_bit, source_width)
            fanout[owner_id][position] ^= values[output_name] << (source_width - 1 - bit)
        if any(
            tuple(fanout[name]) != units(self._ports[name], vt.domain.width) for name, vt in sources
        ):
            return False
        inputs = tuple(
            (name, 0 if name in self.fixed_inputs else _packed(self._ports[name], values))
            for name in self.primitive.graph.input_ports
        )
        input_dict = dict(inputs)
        return (
            trail.input_masks == inputs
            and trail.output_mask == _packed(self._output, values)
            and trail.steps == tuple(steps)
            and trail.constant_sign == constant_sign
            and trail.total_weight <= self.maximum_weight
            and (self.nonzero_input is None or input_dict[self.nonzero_input] != 0)
            and all(input_dict[name] == value for name, value in self.fixed_input_masks.items())
        )

    def enumerate_trails(self, solver, *, limit=1000):
        """Block semantic assignments, excluding auxiliary counter multiplicity."""
        if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
            raise ValueError("limit must be a positive integer")
        formula = self.smt_formula()
        metadata = (
            ("primitive", self.primitive.family_name),
            (
                "realization",
                getattr(getattr(self.primitive, "realization", None), "name", "default"),
            ),
            ("solver", type(solver).__name__),
            ("executable", str(getattr(solver, "executable", "embedded"))),
            (
                "version",
                solver.version() if callable(getattr(solver, "version", None)) else "unreported",
            ),
            (
                "graph_sha256",
                sha256(
                    repr(
                        (
                            self.primitive.graph.input_ports,
                            self.primitive.graph.bindings,
                            tuple(self.primitive.graph.components),
                            self.primitive.graph.output,
                        )
                    ).encode()
                ).hexdigest(),
            ),
            ("formula_sha256", sha256(repr(formula).encode()).hexdigest()),
            ("fixed_inputs", repr(tuple(sorted(self.fixed_inputs.items())))),
        )
        indices = {name: i for i, name in enumerate(formula.variables, 1)}
        trails, blocks, runtime = [], [], 0.0
        context = (
            solver.incremental(formula)
            if callable(getattr(solver, "incremental", None))
            else nullcontext(solver)
        )
        with context as execution:
            while True:
                current = SMTFormula(
                    formula.variables,
                    formula.assertions + tuple(blocks),
                    formula.provenance + ("characteristic_block",) * len(blocks),
                )
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
                blocks.append(
                    tuple(
                        -indices[name] if value else indices[name]
                        for name, value in trail.semantic_assignment
                    )
                )


class WordDeterministicTruncatedSMTModel:
    """Assemble deterministic-truncated Word graphs as Boolean SMT.

    Graph wiring and paired-carry clauses reuse the independently checked SAT
    construction, then cross the explicit immutable SMT container boundary.
    Decoding replays the typed three-valued graph semantics.

    EXAMPLES::

        >>> from claasp.primitives import ToySpeck
        >>> model = WordDeterministicTruncatedSMTModel(
        ...     ToySpeck(2),
        ...     fixed_input_patterns={"key": "0" * 16},
        ...     nonzero_input="plaintext",
        ... )
        >>> formula = model.smt_formula()
        >>> (formula.assertion_count > 0, formula.constraint_models[0].model.backend.value)
        (True, 'smt')
    """

    model_provenance = _direct_model(
        ConstraintBackend.SMT,
        "WordDeterministicTruncatedSMTModel",
        "deterministic_truncated_xor",
        "Boolean SMT translation of deterministic-truncated Word graph clauses",
        "The graph and paired-carry clauses are translated without changing their semantics.",
    )

    def __init__(
        self,
        primitive,
        *,
        fixed_input_patterns=None,
        output_pattern=None,
        nonzero_input=None,
    ) -> None:
        from claasp.representations.constraints.sat.trails import (
            WordDeterministicTruncatedSATModel,
        )

        self._sat_model = WordDeterministicTruncatedSATModel(
            primitive,
            fixed_input_patterns=fixed_input_patterns,
            output_pattern=output_pattern,
            nonzero_input=nonzero_input,
        )
        self.primitive = primitive
        self._formula: SMTFormula | None = None

    def smt_formula(self) -> SMTFormula:
        """Return the complete deterministic-truncated graph formula."""

        cnf = self._sat_model.cnf_formula()
        self._formula = SMTFormula(
            cnf.variables,
            cnf.clauses,
            cnf.provenance,
            (ConstraintModelApplication(self.model_provenance),),
        )
        return self._formula

    def decode_characteristic(self, assignment):
        """Decode and independently validate a complete SMT assignment."""

        if self._formula is None:
            raise ValueError("build the SMT formula before decoding")
        return self._sat_model.decode_characteristic(assignment)

    def check_characteristic(self, trail) -> bool:
        """Recheck graph propagation and requested boundary restrictions."""

        if self._formula is None:
            raise ValueError("build the SMT formula before checking")
        return self._sat_model.check_characteristic(trail)


def _packed(names, assignment):
    value = 0
    for name in names:
        value = (value << 1) | assignment[name]
    return value


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

        >>> from claasp.primitives import ToySpeck
        >>> model = WordDifferentialSMTModel(
        ...     ToySpeck(2), fixed_weight=1, nonzero_input="plaintext",
        ...     fixed_input_differences={"key": 0},
        ... )
        >>> "fixed_difference" in model.smt_formula().provenance
        True
    """

    model_provenance = _direct_model(
        ConstraintBackend.SMT,
        "WordDifferentialSMTModel",
        "xor_differential",
        "direct word-graph difference composition",
        "Non-addition component relations are derived directly from graph wiring and truth tables.",
    )

    def __init__(
        self,
        primitive,
        *,
        maximum_weight=None,
        fixed_weight=None,
        nonzero_input=None,
        fixed_input_differences=None,
        output_difference=None,
    ):
        if maximum_weight is not None and fixed_weight is not None:
            raise ValueError("choose a maximum or fixed weight, not both")
        for weight in (maximum_weight, fixed_weight):
            if weight is not None and (
                not isinstance(weight, int) or isinstance(weight, bool) or weight < 0
            ):
                raise ValueError("weights must be nonnegative integers")
        if nonzero_input is not None and nonzero_input not in primitive.graph.input_ports:
            raise ValueError("unknown nonzero input")
        self.primitive, self.maximum_weight, self.fixed_weight = (
            primitive,
            maximum_weight,
            fixed_weight,
        )
        self.nonzero_input = nonzero_input
        self.fixed_input_differences = dict(fixed_input_differences or {})
        self.output_difference = output_difference
        for name, value in self.fixed_input_differences.items():
            if name not in primitive.graph.input_ports:
                raise ValueError("unknown fixed input difference")
            self._validate(value, primitive.graph.input_ports[name].value_type)
        if output_difference is not None:
            self._validate(output_difference, primitive.graph.output.value_type)
        self._formula = None

    @staticmethod
    def _validate(value, value_type):
        if not isinstance(value_type.domain, Word):
            raise NotImplementedError("word differential lowering requires Word domains")
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or not 0 <= value < 1 << (value_type.unit_count * value_type.domain.width)
        ):
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

        sources = [
            (name, port.value_type) for name, port in self.primitive.graph.input_ports.items()
        ]
        sources += [
            (item.component_id, item.output_type) for item in self.primitive.graph.components
        ]
        ports = {}
        for name, value_type in sources:
            self._validate(0, value_type)
            ports[name] = tuple(
                allocate(f"difference_{name}_{bit}")
                for bit in range(value_type.unit_count * value_type.domain.width)
            )

        def selected(selection):
            return tuple(
                ports[owner_id][bit]
                for owner_id, bit in self.primitive.graph.selection_bit_sources(selection)
            )

        weights, operands_by_id = [], {}
        for component in self.primitive.graph.components:
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
                        local_names[f"weight_{bit}"] = allocate(
                            f"weight_{component.component_id}_{unit}_{bit}"
                        )
                        weights.append(local_names[f"weight_{bit}"])
                    mapping = {
                        i: indices[local_names[name]] for i, name in enumerate(local.variables, 1)
                    }
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
                    _xor_equivalence(
                        (target, *(operand[bit] for operand in operands)),
                        indices,
                        clauses,
                        provenance,
                    )
            elif isinstance(component, Identity):
                for source, target in zip(
                    (name for operand in operands for name in operand), output
                ):
                    _xor_equivalence((source, target), indices, clauses, provenance)
            elif isinstance(component, Rotate):
                amount = component.amount if component.direction == "right" else -component.amount
                for unit in range(component.output_type.unit_count):
                    for bit in range(width):
                        _xor_equivalence(
                            (
                                operands[0][unit * width + bit],
                                output[unit * width + (bit + amount) % width],
                            ),
                            indices,
                            clauses,
                            provenance,
                        )
            elif isinstance(component, Constant):
                for name in output:
                    add((-indices[name],), "zero_constant_difference")
            else:
                raise NotImplementedError(
                    f"no word differential semantics for {type(component).__name__}"
                )
        output = selected(self.primitive.graph.output)
        if self.nonzero_input is not None:
            add(
                (indices[name] for name in ports[self.nonzero_input]), "nonzero_external_difference"
            )
        for names, value in [
            (ports[name], value) for name, value in self.fixed_input_differences.items()
        ] + [(output, self.output_difference)]:
            if value is not None:
                for bit, name in enumerate(names):
                    add(
                        (
                            indices[name]
                            if value & (1 << (len(names) - 1 - bit))
                            else -indices[name],
                        ),
                        "fixed_difference",
                    )
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
                _at_most(
                    complements,
                    len(weights) - self.fixed_weight,
                    lambda name: allocate("lower_" + name),
                    indices,
                    add,
                )
        self._ports, self._operands, self._output = ports, operands_by_id, output
        self._formula = SMTFormula(
            tuple(variables),
            tuple(clauses),
            tuple(provenance),
            _component_applications(
                self.primitive,
                self.model_provenance,
                ((ModularAdd, ModularAddDifferentialSMTModel.model_provenance),),
            ),
        )
        return self._formula

    def _steps_and_wiring(self, values):
        steps = []
        for component in self.primitive.graph.components:
            width = component.output_type.domain.width

            def units(names, width=width):
                return tuple(
                    _packed(names[i : i + width], values) for i in range(0, len(names), width)
                )

            output = units(self._ports[component.component_id])
            operands = tuple(units(names) for names in self._operands[component.component_id])
            if isinstance(component, (ModularAdd, BitwiseAnd)):
                semantics = (
                    ModularAddTransitionSemantics(width)
                    if isinstance(component, ModularAdd)
                    else BitwiseAndSemantics(width)
                )
                for unit, target in enumerate(output):
                    transition = semantics.xor_differential(
                        operands[0][unit], operands[1][unit], target
                    )
                    if not transition.is_possible:
                        return None
                    if isinstance(component, ModularAdd):
                        for bit in range(width - 1):
                            lower = width - 2 - bit
                            triple = tuple(
                                (value >> lower) & 1
                                for value in (operands[0][unit], operands[1][unit], target)
                            )
                            if values[f"weight_{component.component_id}_{unit}_{bit}"] != int(
                                not (triple[0] == triple[1] == triple[2])
                            ):
                                return None
                    else:
                        for bit in range(width):
                            if (
                                values[f"weight_{component.component_id}_{unit * width + bit}"]
                                != ((operands[0][unit] | operands[1][unit]) >> (width - 1 - bit))
                                & 1
                            ):
                                return None
                    steps.append(TrailStep(f"{component.component_id}[{unit}]", transition))
            else:
                if isinstance(component, Xor):
                    from functools import reduce

                    expected = tuple(reduce(int.__xor__, items, 0) for items in zip(*operands))
                elif isinstance(component, Rotate):
                    amount = (
                        component.amount if component.direction == "right" else -component.amount
                    ) % width
                    expected = tuple(
                        ((value >> amount) | (value << (width - amount))) & ((1 << width) - 1)
                        for value in operands[0]
                    )
                elif isinstance(component, Constant):
                    expected = (0,) * len(output)
                else:
                    expected = tuple(value for operand in operands for value in operand)
                if output != expected:
                    return None
        return tuple(steps)

    def decode_characteristic(self, assignment):
        """Compute the decode characteristic for this public typed contract."""

        from claasp.representations.constraints.sat import CNFFormula

        if self._formula is None:
            raise ValueError("build the formula before decoding")
        if not CNFFormula(
            self._formula.variables, self._formula.assertions, self._formula.provenance
        ).is_satisfied(assignment):
            raise ValueError("invalid word differential witness")
        result = WordDifferentialCharacteristic(
            tuple(
                (name, _packed(self._ports[name], assignment))
                for name in self.primitive.graph.input_ports
            ),
            _packed(self._output, assignment),
            self._steps_and_wiring(assignment),
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
        if (
            len(values) != len(trail.semantic_assignment)
            or set(values) != set(self._semantic_names)
            or any(value not in (0, 1) for value in values.values())
        ):
            return False
        steps = self._steps_and_wiring(values)
        inputs = tuple(
            (name, _packed(self._ports[name], values)) for name in self.primitive.graph.input_ports
        )
        output = _packed(self._output, values)
        return (
            steps is not None
            and trail.steps == steps
            and trail.input_differences == inputs
            and trail.output_difference == output
            and (self.maximum_weight is None or trail.total_weight <= self.maximum_weight)
            and (self.fixed_weight is None or trail.total_weight == self.fixed_weight)
            and (self.output_difference is None or output == self.output_difference)
            and (self.nonzero_input is None or dict(inputs)[self.nonzero_input] != 0)
            and all(
                dict(inputs)[name] == value for name, value in self.fixed_input_differences.items()
            )
        )

    def enumerate_trails(self, solver, *, limit=1000):
        """Compute the enumerate trails for this public typed contract."""

        if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
            raise ValueError("limit must be a positive integer")
        formula = self.smt_formula()
        metadata = (
            ("primitive", self.primitive.family_name),
            (
                "realization",
                getattr(getattr(self.primitive, "realization", None), "name", "default"),
            ),
            ("solver", type(solver).__name__),
            ("executable", str(getattr(solver, "executable", "embedded"))),
            (
                "version",
                solver.version() if callable(getattr(solver, "version", None)) else "unreported",
            ),
            ("weight_range", repr((self.fixed_weight, self.maximum_weight))),
            ("fixed_input_differences", repr(tuple(sorted(self.fixed_input_differences.items())))),
            ("output_difference", repr(self.output_difference)),
            (
                "graph_sha256",
                sha256(
                    repr(
                        (
                            self.primitive.graph.input_ports,
                            self.primitive.graph.bindings,
                            tuple(self.primitive.graph.components),
                            self.primitive.graph.output,
                        )
                    ).encode()
                ).hexdigest(),
            ),
            ("formula_sha256", sha256(repr(formula).encode()).hexdigest()),
        )
        indices = {name: index for index, name in enumerate(formula.variables, 1)}
        trails, blocks, runtime = [], [], 0.0
        context = (
            solver.incremental(formula)
            if callable(getattr(solver, "incremental", None))
            else nullcontext(solver)
        )
        with context as execution:
            while True:
                current = SMTFormula(
                    formula.variables,
                    formula.assertions + tuple(blocks),
                    formula.provenance + ("characteristic_block",) * len(blocks),
                )
                result = execution.solve(current)
                runtime += result.runtime_seconds
                if result.status is SatStatus.UNSATISFIABLE:
                    return WordDifferentialEnumeration(tuple(trails), True, runtime, metadata)
                if result.status is not SatStatus.SATISFIABLE or len(trails) == limit:
                    return WordDifferentialEnumeration(tuple(trails), False, runtime, metadata)
                trail = self.decode_characteristic(result.assignment)
                trails.append(trail)
                blocks.append(
                    tuple(
                        -indices[name] if value else indices[name]
                        for name, value in trail.semantic_assignment
                    )
                )
