"""Weighted full-trail SMT representation lowering."""

from claasp.components import (
    BitVectorSBox,
    ModularAdd,
    Permutation,
    Rotate,
)
from claasp.graph import Primitive
from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _direct_model,
)
from claasp.representations.constraints._propagation import (
    component_applications as _component_applications,
)
from claasp.representations.constraints.smt._cardinality import _at_most
from claasp.representations.constraints.smt.components.modular_add import (
    ModularAddLinearSMTModel,
    _xor_equivalence,
)
from claasp.representations.constraints.smt.model import SMTFormula
from claasp.representations.constraints.smt.word_differential import (
    WordDifferentialCharacteristic as WordDifferentialCharacteristic,
)
from claasp.representations.constraints.smt.word_differential import (
    WordDifferentialEnumeration as WordDifferentialEnumeration,
)
from claasp.representations.constraints.smt.word_differential import (
    WordDifferentialSMTModel as WordDifferentialSMTModel,
)
from claasp.representations.constraints.smt.word_linear import (
    WordLinearCharacteristic as WordLinearCharacteristic,
)
from claasp.representations.constraints.smt.word_linear import (
    WordLinearEnumeration as WordLinearEnumeration,
)
from claasp.representations.constraints.smt.word_linear import (
    WordLinearSMTModel as WordLinearSMTModel,
)
from claasp.semantics import XOR_DIFFERENTIAL, XOR_LINEAR
from claasp.semantics.cryptanalysis import (
    PropagationProblem,
    SBoxTransitionSemantics,
    Trail,
    TrailKind,
    TrailStep,
    XorDifference,
    XorMask,
)
from claasp.unit_types import Word


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
        plaintext = primitive.graph.input_arrays.get("plaintext")
        if (
            primitive.family_name != "speck"
            or plaintext is None
            or not isinstance(plaintext.array_type.unit_type, Word)
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
        self.width = plaintext.array_type.unit_type.width
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
