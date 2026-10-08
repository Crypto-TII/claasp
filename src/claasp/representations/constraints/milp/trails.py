"""Exact weighted trail lowering to the portable MILP representation."""

from typing import cast

from claasp.components import BitVectorSBox, Permutation
from claasp.graph import Primitive
from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _direct_model,
    _unaudited_model,
    _verified_model,
)
from claasp.representations.constraints.milp.model import (
    ConstraintSense,
    LinearConstraint,
    LinearExpression,
    LinearVariable,
    MILPModel,
    ObjectiveSense,
    VariableKind,
)
from claasp.representations.constraints.polynomial.boolean import monomial_transition_table
from claasp.representations.constraints.smt.trails import check_present_smt_trail
from claasp.semantics import XOR_DIFFERENTIAL
from claasp.semantics.cryptanalysis import (
    PropagationProblem,
    Trail,
    TrailKind,
    TrailStep,
    XorDifference,
)


class PresentDifferentialMILPModel:
    """Exact two-round PRESENT XOR-differential optimization model.

    EXAMPLES::

        >>> from claasp.primitives import Present
        >>> lowering = PresentDifferentialMILPModel(Present(number_of_rounds=2))
        >>> model = lowering.milp_model()
        >>> (model.objective_sense.value, len(model.constraints))
        ('minimize', 289)
    """

    model_provenance = _direct_model(
        ConstraintBackend.MILP,
        "PresentDifferentialMILPModel",
        "xor_differential",
        "one-hot exhaustive DDT row selection",
        "The S-box support and weights are enumerated directly from the supplied table.",
    )

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
            (
                ConstraintModelApplication(
                    self.model_provenance,
                    tuple(cast(str, component_id) for component_id, _, _ in self._records),
                ),
            ),
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


class PresentActiveSBoxesMILPModel(PresentDifferentialMILPModel):
    """Minimize active S-boxes over the exact two-round PRESENT relation.

    EXAMPLES::

        >>> from claasp.primitives import Present
        >>> formulation = PresentActiveSBoxesMILPModel(
        ...     Present(number_of_rounds=2)
        ... ).milp_model()
        >>> len(formulation.objective.terms) > 0
        True
    """

    model_provenance = _direct_model(
        ConstraintBackend.MILP,
        "PresentActiveSBoxesMILPModel",
        "xor_differential_activity",
        "active-input objective over exact DDT transition selectors",
        "The feasible region is identical to the reviewed exact differential model.",
    )

    def milp_model(self) -> MILPModel:
        """Return exact differential feasibility with an activity objective."""

        weighted = super().milp_model()
        objective = {}
        for variable in weighted.variables:
            if "_choice_" not in variable.name:
                continue
            source = int(variable.name.rsplit("_", 2)[1])
            if source:
                objective[variable.name] = 1
        return MILPModel(
            weighted.variables,
            weighted.constraints,
            LinearExpression.from_terms(objective),
            ObjectiveSense.MINIMIZE,
            (ConstraintModelApplication(self.model_provenance),),
        )


class PresentFixedActiveSBoxesMILPModel(PresentDifferentialMILPModel):
    """Minimize exact weight after fixing the PRESENT active-S-box count.

    EXAMPLES::

        >>> from claasp.primitives import Present
        >>> model = PresentFixedActiveSBoxesMILPModel(
        ...     Present(number_of_rounds=2), active_sboxes=2
        ... ).milp_model()
        >>> model.constraints[-1].rhs
        2
    """

    model_provenance = _direct_model(
        ConstraintBackend.MILP,
        "PresentFixedActiveSBoxesMILPModel",
        "xor_differential_fixed_activity",
        "exact DDT weight optimization at a fixed active-S-box count",
        "This is the second stage of the recovered active-S-box search.",
    )

    def __init__(self, primitive, *, active_sboxes: int) -> None:
        if (
            not isinstance(active_sboxes, int)
            or isinstance(active_sboxes, bool)
            or not 1 <= active_sboxes <= 32
        ):
            raise ValueError("active_sboxes must be an integer from 1 through 32")
        super().__init__(primitive)
        self.active_sboxes = active_sboxes

    def milp_model(self) -> MILPModel:
        """Return exact weight minimization at the selected activity count."""

        weighted = super().milp_model()
        activity = {}
        for variable in weighted.variables:
            if "_choice_" in variable.name and int(variable.name.rsplit("_", 2)[1]):
                activity[variable.name] = 1
        constraint = LinearConstraint(
            LinearExpression.from_terms(activity),
            ConstraintSense.EQUAL,
            self.active_sboxes,
            "fixed_active_sboxes",
        )
        return MILPModel(
            weighted.variables,
            weighted.constraints + (constraint,),
            weighted.objective,
            weighted.objective_sense,
            (ConstraintModelApplication(self.model_provenance),),
        )


def check_present_milp_trail(primitive: Primitive, trail: Trail) -> bool:
    """Independently check a decoded trail using shared semantics and wiring.

    The checker is used after :meth:`PresentDifferentialMILPModel.decode_trail`
    to verify the decoded transitions and PRESENT permutation boundaries
    independently of the MILP constraints.

    EXAMPLES::

        >>> from claasp.primitives import Present
        >>> primitive = Present(number_of_rounds=2)
        >>> problem = PropagationProblem(primitive, XOR_DIFFERENTIAL)
        >>> sboxes = tuple(
        ...     component
        ...     for component in primitive.components
        ...     if isinstance(component, BitVectorSBox)
        ...     and component.component_id.startswith("sbox_")
        ... )
        >>> steps = tuple(
        ...     TrailStep(
        ...         component.component_id,
        ...         problem.provider_for(component).transition((0,), 0),
        ...     )
        ...     for component in sboxes
        ... )
        >>> trail = Trail(
        ...     TrailKind.XOR_DIFFERENTIAL,
        ...     XorDifference(0, 64),
        ...     XorDifference(0, 64),
        ...     steps,
        ... )
        >>> check_present_milp_trail(primitive, trail)
        True
    """

    return check_present_smt_trail(primitive, trail)


class WordDifferentialMILPModel:
    """Assemble exact XOR-differential Word graphs as portable MILP.

    EXAMPLES::

        >>> from claasp.primitives import ToySpeck
        >>> model = WordDifferentialMILPModel(
        ...     ToySpeck(2), fixed_weight=1,
        ...     fixed_input_differences={"key": 0}, nonzero_input="plaintext",
        ... )
        >>> formulation = model.milp_model()
        >>> (len(formulation.variables), len(formulation.constraints))
        (187, 501)
    """

    model_provenance = _direct_model(
        ConstraintBackend.MILP,
        "WordDifferentialMILPModel",
        "xor_differential",
        "exact MILP translation of the reviewed Boolean Word-graph relation",
        "The portable formulation preserves every clause as one linear inequality.",
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
    ) -> None:
        from claasp.representations.constraints.sat.trails import WordDifferentialSATModel

        self._sat_model = WordDifferentialSATModel(
            primitive,
            maximum_weight=maximum_weight,
            fixed_weight=fixed_weight,
            nonzero_input=nonzero_input,
            fixed_input_differences=fixed_input_differences,
            output_difference=output_difference,
        )
        self.primitive = primitive
        self._model: MILPModel | None = None

    def milp_model(self) -> MILPModel:
        """Return the exact portable MILP formulation."""

        from claasp.representations.constraints.milp.lowering import cnf_to_milp

        translated = cnf_to_milp(self._sat_model.cnf_formula())
        objective = LinearExpression.from_terms(
            {
                variable.name: 1
                for variable in translated.variables
                if variable.name.startswith("weight_")
                and not variable.name.startswith(("weight_complement", "weight_counter"))
            }
        )
        self._model = MILPModel(
            translated.variables,
            translated.constraints,
            objective,
            ObjectiveSense.MINIMIZE,
            (ConstraintModelApplication(self.model_provenance),),
        )
        return self._model

    def decode_characteristic(self, assignment):
        """Decode and independently validate a complete MILP assignment."""

        if self._model is None:
            raise ValueError("build the MILP model before decoding")
        return self._sat_model.decode_characteristic(
            {name: int(round(value)) for name, value in assignment.items()}
        )

    def check_characteristic(self, trail) -> bool:
        """Recheck component transitions, wiring, and requested boundaries."""

        if self._model is None:
            raise ValueError("build the MILP model before checking")
        return self._sat_model.check_characteristic(trail)


class WordDeterministicTruncatedMILPModel:
    """Assemble deterministic-truncated Word graphs as portable MILP.

    EXAMPLES::

        >>> from claasp.primitives import ToySpeck
        >>> model = WordDeterministicTruncatedMILPModel(
        ...     ToySpeck(2),
        ...     fixed_input_patterns={"plaintext": "00000001", "key": "0" * 16},
        ...     output_pattern="???0????",
        ... )
        >>> formulation = model.milp_model()
        >>> (len(formulation.variables), len(formulation.constraints))
        (200, 829)
    """

    model_provenance = _direct_model(
        ConstraintBackend.MILP,
        "WordDeterministicTruncatedMILPModel",
        "deterministic_truncated_xor",
        "exact MILP translation of the reviewed ternary Word-graph relation",
        "The portable formulation preserves every clause as one linear inequality.",
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
        self._model: MILPModel | None = None

    def milp_model(self) -> MILPModel:
        """Return the exact portable MILP formulation."""

        from claasp.representations.constraints.milp.lowering import cnf_to_milp

        translated = cnf_to_milp(self._sat_model.cnf_formula())
        self._model = MILPModel(
            translated.variables,
            translated.constraints,
            constraint_models=(ConstraintModelApplication(self.model_provenance),),
        )
        return self._model

    def decode_characteristic(self, assignment):
        """Decode and independently validate a complete MILP assignment."""

        if self._model is None:
            raise ValueError("build the MILP model before decoding")
        return self._sat_model.decode_characteristic(
            {name: int(round(value)) for name, value in assignment.items()}
        )

    def check_characteristic(self, trail) -> bool:
        """Recheck ternary component transitions, wiring, and boundaries."""

        if self._model is None:
            raise ValueError("build the MILP model before checking")
        return self._sat_model.check_characteristic(trail)


class SpeckSemiDeterministicTruncatedMILPModel:
    """Assemble recovered look-ahead-window Speck trails as MILP.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> model = SpeckSemiDeterministicTruncatedMILPModel(
        ...     Speck(number_of_rounds=2),
        ...     "00000000011111001110000000000000",
        ...     "???????????????1???????????????1",
        ... )
        >>> formulation = model.milp_model()
        >>> (len(formulation.variables), len(formulation.constraints))
        (672, 3483)
    """

    model_provenance = _unaudited_model(
        ConstraintBackend.MILP,
        "SpeckSemiDeterministicTruncatedMILPModel",
        "semi_deterministic_truncated_xor",
        "exact MILP translation of the recovered look-ahead-window Speck model",
        "The exact correspondence with a primary-source construction has not been audited.",
    )

    def __init__(
        self, primitive, input_pattern, output_pattern, *, maximum_scaled_weight=None
    ) -> None:
        from claasp.representations.constraints.sat.trails import (
            SpeckSemiDeterministicTruncatedSATModel,
        )

        self._sat_model = SpeckSemiDeterministicTruncatedSATModel(
            primitive,
            input_pattern,
            output_pattern,
            maximum_scaled_weight=maximum_scaled_weight,
        )
        self.primitive = primitive
        self._model: MILPModel | None = None

    def milp_model(self) -> MILPModel:
        """Return the exact formulation minimizing recovered scaled weight."""

        from claasp.representations.constraints.milp.lowering import cnf_to_milp

        translated = cnf_to_milp(self._sat_model.cnf_formula())
        coefficients = {}
        for variable in translated.variables:
            if "__weight_" not in variable.name:
                continue
            selector = variable.name.split("__weight_", 1)[1].split("_")
            if len(selector) == 2 and all(part.isdigit() for part in selector):
                coefficients[variable.name] = int(selector[1])
        self._model = MILPModel(
            translated.variables,
            translated.constraints,
            LinearExpression.from_terms(coefficients),
            ObjectiveSense.MINIMIZE,
            (ConstraintModelApplication(self.model_provenance),),
        )
        return self._model

    def decode_trail(self, assignment):
        """Decode and independently validate the complete Speck trail."""

        if self._model is None:
            raise ValueError("build the MILP model before decoding")
        return self._sat_model.decode_trail(
            {name: int(round(value)) for name, value in assignment.items()}
        )


class WordDeterministicDifferentialLinearMILPModel:
    """Assemble deterministic-middle differential-linear trails as MILP.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> model = WordDeterministicDifferentialLinearMILPModel(
        ...     Speck(number_of_rounds=3), prefix_rounds=1, middle_rounds=1,
        ...     differential_maximum_weight=16, linear_maximum_weight=16,
        ... )
        >>> formulation = model.milp_model()
        >>> (len(formulation.variables), len(formulation.constraints))
        (2543, 7151)
    """

    model_provenance = _direct_model(
        ConstraintBackend.MILP,
        "WordDeterministicDifferentialLinearMILPModel",
        "differential_linear",
        "exact MILP translation of the reviewed deterministic-middle composition",
        "The objective is differential weight plus twice the linear-correlation weight.",
    )

    def __init__(
        self,
        primitive,
        *,
        prefix_rounds,
        middle_rounds,
        differential_maximum_weight,
        linear_maximum_weight,
        input_difference=None,
        output_mask=None,
    ) -> None:
        from claasp.representations.constraints.sat.trails import (
            WordDeterministicDifferentialLinearSATModel,
        )

        self._sat_model = WordDeterministicDifferentialLinearSATModel(
            primitive,
            prefix_rounds=prefix_rounds,
            middle_rounds=middle_rounds,
            differential_maximum_weight=differential_maximum_weight,
            linear_maximum_weight=linear_maximum_weight,
            input_difference=input_difference,
            output_mask=output_mask,
        )
        self.primitive = primitive
        self._model: MILPModel | None = None

    def milp_model(self) -> MILPModel:
        """Return the exact portable MILP formulation and legacy objective."""

        from claasp.representations.constraints.milp.lowering import cnf_to_milp

        translated = cnf_to_milp(self._sat_model.cnf_formula())
        coefficients = {}
        for variable in translated.variables:
            name = variable.name
            if name.startswith("differential_weight_"):
                coefficients[name] = 1
            elif name.startswith("linear_") and "_weight_" in name and not name.startswith(
                "linear___"
            ):
                coefficients[name] = 2
        self._model = MILPModel(
            translated.variables,
            translated.constraints,
            LinearExpression.from_terms(coefficients),
            ObjectiveSense.MINIMIZE,
            (ConstraintModelApplication(self.model_provenance),),
        )
        return self._model

    def decode_trail(self, assignment):
        """Decode and independently validate all three trail sections."""

        if self._model is None:
            raise ValueError("build the MILP model before decoding")
        return self._sat_model.decode_trail(
            {name: int(round(value)) for name, value in assignment.items()}
        )


class WordSemiDeterministicDifferentialLinearMILPModel:
    """Assemble semi-deterministic differential-linear trails as MILP.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> model = WordSemiDeterministicDifferentialLinearMILPModel(
        ...     Speck(number_of_rounds=3), prefix_rounds=1, middle_rounds=1,
        ...     differential_maximum_weight=16,
        ...     middle_maximum_scaled_weight=None,
        ...     linear_maximum_weight=16,
        ... )
        >>> formulation = model.milp_model()
        >>> (len(formulation.variables), len(formulation.constraints))
        (2303, 6599)
    """

    model_provenance = _unaudited_model(
        ConstraintBackend.MILP,
        "WordSemiDeterministicDifferentialLinearMILPModel",
        "differential_linear",
        "exact MILP translation of the recovered semi-deterministic composition",
        "The middle probability and exact literature correspondence remain unaudited.",
    )

    def __init__(
        self,
        primitive,
        *,
        prefix_rounds,
        middle_rounds,
        differential_maximum_weight,
        middle_maximum_scaled_weight,
        linear_maximum_weight,
        input_difference=None,
        output_mask=None,
    ) -> None:
        from claasp.representations.constraints.sat.trails import (
            WordSemiDeterministicDifferentialLinearSATModel,
        )

        self._sat_model = WordSemiDeterministicDifferentialLinearSATModel(
            primitive,
            prefix_rounds=prefix_rounds,
            middle_rounds=middle_rounds,
            differential_maximum_weight=differential_maximum_weight,
            middle_maximum_scaled_weight=middle_maximum_scaled_weight,
            linear_maximum_weight=linear_maximum_weight,
            input_difference=input_difference,
            output_mask=output_mask,
        )
        self.primitive = primitive
        self._model: MILPModel | None = None

    def milp_model(self) -> MILPModel:
        """Return the exact formulation with the historical outer objective."""

        from claasp.representations.constraints.milp.lowering import cnf_to_milp

        translated = cnf_to_milp(self._sat_model.cnf_formula())
        coefficients = {}
        for variable in translated.variables:
            name = variable.name
            if name.startswith("differential_weight_"):
                coefficients[name] = 1
            elif name.startswith("linear_") and "_weight_" in name and not name.startswith(
                "linear___"
            ):
                coefficients[name] = 2
        self._model = MILPModel(
            translated.variables,
            translated.constraints,
            LinearExpression.from_terms(coefficients),
            ObjectiveSense.MINIMIZE,
            (ConstraintModelApplication(self.model_provenance),),
        )
        return self._model

    def decode_trail(self, assignment):
        """Decode all sections and retain the middle estimate separately."""

        if self._model is None:
            raise ValueError("build the MILP model before decoding")
        return self._sat_model.decode_trail(
            {name: int(round(value)) for name, value in assignment.items()}
        )


class WordLinearMILPModel:
    """Assemble exact XOR-linear Word graphs as portable MILP.

    EXAMPLES::

        >>> from claasp.primitives import ToySpeck
        >>> model = WordLinearMILPModel(
        ...     ToySpeck(3), maximum_weight=1,
        ...     fixed_inputs={"key": 0}, nonzero_input="plaintext",
        ... )
        >>> formulation = model.milp_model()
        >>> (len(formulation.variables), len(formulation.constraints))
        (296, 706)
    """

    model_provenance = _direct_model(
        ConstraintBackend.MILP,
        "WordLinearMILPModel",
        "xor_linear",
        "exact MILP translation of the reviewed Boolean Word-graph relation",
        "The portable formulation preserves every clause as one linear inequality.",
    )

    def __init__(
        self,
        primitive,
        *,
        maximum_weight,
        nonzero_input=None,
        fixed_input_masks=None,
        fixed_inputs=None,
    ) -> None:
        from claasp.representations.constraints.sat.trails import WordLinearSATModel

        self._sat_model = WordLinearSATModel(
            primitive,
            maximum_weight=maximum_weight,
            nonzero_input=nonzero_input,
            fixed_input_masks=fixed_input_masks,
            fixed_inputs=fixed_inputs,
        )
        self.primitive = primitive
        self._model: MILPModel | None = None

    def milp_model(self) -> MILPModel:
        """Return the exact portable MILP formulation."""

        from claasp.representations.constraints.milp.lowering import cnf_to_milp

        translated = cnf_to_milp(self._sat_model.cnf_formula())
        objective = LinearExpression.from_terms(
            {
                variable.name: 1
                for variable in translated.variables
                if "_weight_" in variable.name and not variable.name.startswith("__")
            }
        )
        self._model = MILPModel(
            translated.variables,
            translated.constraints,
            objective,
            ObjectiveSense.MINIMIZE,
            (ConstraintModelApplication(self.model_provenance),),
        )
        return self._model

    def decode_characteristic(self, assignment):
        """Decode and independently validate a complete MILP assignment."""

        if self._model is None:
            raise ValueError("build the MILP model before decoding")
        return self._sat_model.decode_characteristic(
            {name: int(round(value)) for name, value in assignment.items()}
        )

    def check_characteristic(self, trail) -> bool:
        """Recheck component masks, signs, wiring, and requested boundaries."""

        if self._model is None:
            raise ValueError("build the MILP model before checking")
        return self._sat_model.check_characteristic(trail)


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


class PresentMonomialTrailMILPModel:
    """Compose exact local monomial transitions over reduced PRESENT rounds.

    EXAMPLES::

        >>> from claasp.primitives import Present
        >>> lowering = PresentMonomialTrailMILPModel(
        ...     Present(number_of_rounds=2), input_mask=1, output_mask=1
        ... )
        >>> model = lowering.milp_model()
        >>> len(model.constraints) > 100
        True
    """

    model_provenance = _verified_model(
        ConstraintBackend.MILP,
        "PresentMonomialTrailMILPModel",
        "division_property",
        "exhaustive monomial-transition row selection",
        "https://eprint.iacr.org/2020/1048",
        "An Algebraic Formulation of the Division Property: Revisiting Degree Evaluations, Cube Attacks, and Key-Independent Sums",
        "section 3, Definition 1; section 4.2",
    )

    def __init__(self, primitive, input_mask: int, output_mask: int) -> None:
        from claasp.components import BitVectorSBox, Permutation

        if primitive.family_name != "present":
            raise ValueError("primitive must be a typed PRESENT graph")
        for name, mask in (("input_mask", input_mask), ("output_mask", output_mask)):
            if not isinstance(mask, int) or isinstance(mask, bool) or not 0 <= mask < 1 << 64:
                raise ValueError(f"{name} must be a 64-bit exponent vector")
        self.primitive = primitive
        self.input_mask = input_mask
        self.output_mask = output_mask
        self.round_count = len(primitive.rounds)
        first_sbox = next(
            component
            for component in primitive.components
            if isinstance(component, BitVectorSBox) and component.component_id == "sbox_1_0"
        )
        table = monomial_transition_table(first_sbox.table)
        self.local_transitions = tuple(
            (input_value, output_value)
            for output_value, input_values in table.items()
            for input_value in sorted(input_values)
        )
        self.permutations = tuple(
            next(
                component
                for component in primitive.components
                if isinstance(component, Permutation)
                and component.component_id == f"p_layer_{round_number}"
            )
            for round_number in range(1, self.round_count + 1)
        )

    def milp_model(self) -> MILPModel:
        """Return the complete fixed-boundary portable MILP query."""

        variables = []
        constraints = []
        for boundary in range(self.round_count + 1):
            variables.extend(
                LinearVariable(f"state_{boundary}_{bit}", VariableKind.BINARY) for bit in range(64)
            )
        for round_index in range(self.round_count):
            variables.extend(
                LinearVariable(f"sub_{round_index}_{bit}", VariableKind.BINARY) for bit in range(64)
            )
            for nibble in range(16):
                selectors = tuple(
                    f"select_{round_index}_{nibble}_{index}"
                    for index in range(len(self.local_transitions))
                )
                variables.extend(LinearVariable(name, VariableKind.BINARY) for name in selectors)
                constraints.append(
                    LinearConstraint(
                        LinearExpression.from_terms({name: 1 for name in selectors}),
                        ConstraintSense.EQUAL,
                        1,
                        f"one_{round_index}_{nibble}",
                    )
                )
                for local_bit in range(4):
                    position = 4 * nibble + local_bit
                    input_terms = {f"state_{round_index}_{position}": 1}
                    output_terms = {f"sub_{round_index}_{position}": 1}
                    for index, (input_value, output_value) in enumerate(self.local_transitions):
                        shift = 3 - local_bit
                        if (input_value >> shift) & 1:
                            input_terms[selectors[index]] = -1
                        if (output_value >> shift) & 1:
                            output_terms[selectors[index]] = -1
                    constraints.extend(
                        (
                            LinearConstraint(
                                LinearExpression.from_terms(input_terms), ConstraintSense.EQUAL, 0
                            ),
                            LinearConstraint(
                                LinearExpression.from_terms(output_terms), ConstraintSense.EQUAL, 0
                            ),
                        )
                    )
            for output_position, input_position in enumerate(
                self.permutations[round_index].mapping
            ):
                constraints.append(
                    LinearConstraint(
                        LinearExpression.from_terms(
                            {
                                f"state_{round_index + 1}_{output_position}": 1,
                                f"sub_{round_index}_{input_position}": -1,
                            }
                        ),
                        ConstraintSense.EQUAL,
                        0,
                        f"permute_{round_index}_{output_position}",
                    )
                )
        for bit in range(64):
            shift = 63 - bit
            constraints.extend(
                (
                    LinearConstraint(
                        LinearExpression.from_terms({f"state_0_{bit}": 1}),
                        ConstraintSense.EQUAL,
                        (self.input_mask >> shift) & 1,
                        f"fix_input_{bit}",
                    ),
                    LinearConstraint(
                        LinearExpression.from_terms({f"state_{self.round_count}_{bit}": 1}),
                        ConstraintSense.EQUAL,
                        (self.output_mask >> shift) & 1,
                        f"fix_output_{bit}",
                    ),
                )
            )
        return MILPModel(
            tuple(variables),
            tuple(constraints),
            constraint_models=(
                ConstraintModelApplication(
                    self.model_provenance,
                    tuple(
                        cast(str, component.component_id)
                        for round_number in range(1, self.round_count + 1)
                        for component in _round_sboxes(self.primitive, round_number)
                    ),
                ),
            ),
        )

    def decode_trail(self, assignment):
        """Decode a solver witness and validate it with independent semantics."""

        from claasp.analysis.monomial import (
            MonomialTrail,
            MonomialTrailStep,
            MultiRoundMonomialTrail,
            PresentMonomialSemantics,
        )

        def mask(prefix):
            value = 0
            for bit in range(64):
                value = (value << 1) | int(round(assignment[f"{prefix}_{bit}"]))
            return value

        rounds = []
        for round_index in range(self.round_count):
            source = mask(f"state_{round_index}")
            substituted = mask(f"sub_{round_index}")
            target = mask(f"state_{round_index + 1}")
            steps = tuple(
                MonomialTrailStep(
                    f"sbox_{round_index + 1}_{nibble}",
                    (source >> (4 * (15 - nibble))) & 0xF,
                    (substituted >> (4 * (15 - nibble))) & 0xF,
                )
                for nibble in range(16)
            ) + (MonomialTrailStep(f"p_layer_{round_index + 1}", substituted, target),)
            rounds.append(
                MonomialTrail(
                    source, target, 64, steps, "plaintext", f"typed PRESENT round {round_index + 1}"
                )
            )
        trail = MultiRoundMonomialTrail(
            self.input_mask,
            self.output_mask,
            tuple(rounds),
            "portable MILP monomial witness through typed PRESENT graph",
        )
        if not PresentMonomialSemantics(self.primitive).check(trail):
            raise ValueError("solver returned an invalid PRESENT monomial trail")
        return trail
