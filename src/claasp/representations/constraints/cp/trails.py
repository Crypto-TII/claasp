"""Native CP lowering of shared cryptanalytic trail semantics."""

import re
from dataclasses import dataclass

from claasp.components import BitVectorSBox, Permutation, Rotate
from claasp.domains import Word
from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _direct_model,
    _unaudited_model,
)
from claasp.representations.constraints.cp.components import (
    ModularAddBoomerangCPModel as _ModularAddBoomerangCPModel,
)
from claasp.representations.constraints.cp.components import (
    ModularAddDeterministicTruncatedCPModel as _ModularAddDeterministicTruncatedCPModel,
)
from claasp.representations.constraints.cp.components import (
    ProbabilisticTruncatedModularAddCPModel as _ProbabilisticTruncatedModularAddCPModel,
)
from claasp.representations.constraints.cp.components import (
    SBoxBoomerangCPModel as _SBoxBoomerangCPModel,
)
from claasp.representations.constraints.cp.components import (
    SBoxDifferenceCPModel as _SBoxDifferenceCPModel,
)
from claasp.representations.constraints.cp.components import (
    SBoxXorDifferentialCPModel as _SBoxXorDifferentialCPModel,
)
from claasp.representations.constraints.cp.lowering import BooleanMiniZincLowerer
from claasp.representations.constraints.cp.model import MiniZincModel
from claasp.representations.constraints.smt.trails import (
    check_present_linear_smt_trail,
    check_present_smt_trail,
)
from claasp.semantics import DETERMINISTIC_TRUNCATED_XOR, XOR_DIFFERENTIAL, XOR_LINEAR
from claasp.semantics.cryptanalysis import (
    ImpossiblePropagationBoundary,
    ModularAddTransitionSemantics,
    ProbabilisticTruncatedModularAddTransition,
    ProbabilisticTruncatedTrail,
    PropagationProblem,
    Trail,
    TrailKind,
    TrailStep,
    TruncatedXorDifference,
    WordwiseDifferenceKind,
    WordwiseXorDifference,
    XorDifference,
    XorMask,
    check_probabilistic_truncated_modular_add,
    propagate_two_word_simon_inverse_round,
    propagate_two_word_simon_round,
    propagate_two_word_speck_round,
)

ModularAddDeterministicTruncatedCPModel = _ModularAddDeterministicTruncatedCPModel
ModularAddBoomerangCPModel = _ModularAddBoomerangCPModel
ProbabilisticTruncatedModularAddCPModel = _ProbabilisticTruncatedModularAddCPModel
SBoxBoomerangCPModel = _SBoxBoomerangCPModel
SBoxDifferenceCPModel = _SBoxDifferenceCPModel
SBoxXorDifferentialCPModel = _SBoxXorDifferentialCPModel


class PresentDifferentialCPModel:
    """Native table-constraint model for two-round PRESENT differences.

    EXAMPLES::

        >>> from claasp.primitives import Present
        >>> problem = PropagationProblem(
        ...     Present(number_of_rounds=2), XOR_DIFFERENTIAL, maximum_weight=4
        ... )
        >>> query = PresentDifferentialCPModel(problem).cp_model()
        >>> (query.includes, query.constraints[-1].endswith("<= 4;"))
        (('include "table.mzn";',), True)
    """

    def __init__(self, problem: PropagationProblem) -> None:
        if not isinstance(problem, PropagationProblem):
            raise TypeError("problem must be a PropagationProblem")
        if problem.semantics != XOR_DIFFERENTIAL:
            raise ValueError("differential CP lowering requires XOR-differential semantics")
        if problem.maximum_weight is None:
            raise ValueError("differential CP lowering requires maximum_weight")
        if problem.primitive.family_name != "present" or len(problem.primitive.rounds) != 2:
            raise NotImplementedError("differential CP lowering currently supports PRESENT-2")
        self.problem = problem
        self.primitive = problem.primitive
        self._records = ()
        self._input_names = ()
        self._last_output_names = ()

    def cp_model(self) -> MiniZincModel:
        """Lower exact DDT support and weights to native table constraints."""

        declarations = []
        constraints = []
        plaintext = tuple(f"plaintext_{bit}" for bit in range(64))
        first_output = tuple(f"round_1_sbox_output_{bit}" for bit in range(64))
        second_output = tuple(f"round_2_sbox_output_{bit}" for bit in range(64))
        for name in (*plaintext, *first_output, *second_output):
            declarations.append(f"var 0..1: {name};")
        permutation = _component(self.primitive, "p_layer_1", Permutation)
        second_input = tuple(first_output[position] for position in permutation.mapping)
        weight_names = []
        records = []
        for round_number, (inputs, outputs) in enumerate(
            ((plaintext, first_output), (second_input, second_output)), start=1
        ):
            for nibble, component in enumerate(_round_sboxes(self.primitive, round_number)):
                start = 4 * nibble
                local_input = inputs[start : start + 4]
                local_output = outputs[start : start + 4]
                weight_name = f"round_{round_number}_sbox_{nibble}_weight"
                weight_names.append(weight_name)
                declarations.append(f"var 0..4: {weight_name};")
                rows = []
                semantics = self.problem.provider_for(component)
                for source in range(16):
                    for target in range(16):
                        transition = semantics.transition((source,), target)
                        if transition.is_possible:
                            rows.append(
                                (*_bits(source, 4), *_bits(target, 4), int(transition.weight))
                            )
                table_name = f"round_{round_number}_sbox_{nibble}_table"
                flattened = ",".join(str(item) for row in rows for item in row)
                declarations.append(
                    f"array[0..{len(rows) - 1}, 1..9] of int: {table_name} = "
                    f"array2d(0..{len(rows) - 1}, 1..9, [{flattened}]);"
                )
                variables = ",".join((*local_input, *local_output, weight_name))
                constraints.append(f"constraint table([{variables}], {table_name});")
                records.append((component.component_id, local_input, local_output))
        constraints.append("constraint " + " + ".join(plaintext) + " >= 1;")
        constraints.append(
            "constraint " + " + ".join(weight_names) + f" <= {self.problem.maximum_weight};"
        )
        self._records = tuple(records)
        self._input_names = plaintext
        self._last_output_names = second_output
        return MiniZincModel(
            tuple(declarations),
            tuple(constraints),
            includes=('include "table.mzn";',),
            provenance=self.problem.provenance,
        )

    def decode_trail(self, assignment) -> Trail:
        """Project a solution to shared transitions and independently check it."""

        if not self._records:
            raise ValueError("build the CP model before decoding a trail")
        components = {component.component_id: component for component in self.primitive.components}
        steps = []
        for component_id, inputs, outputs in self._records:
            semantics = self.problem.provider_for(components[component_id])
            source = _integer(assignment[name] for name in inputs)
            target = _integer(assignment[name] for name in outputs)
            steps.append(TrailStep(component_id, semantics.transition((source,), target)))
        raw_output = _integer(assignment[name] for name in self._last_output_names)
        final = _permute(raw_output, _component(self.primitive, "p_layer_2", Permutation).mapping)
        trail = Trail(
            TrailKind.XOR_DIFFERENTIAL,
            XorDifference(_integer(assignment[name] for name in self._input_names), 64),
            XorDifference(final, 64),
            tuple(steps),
        )
        if not check_present_smt_trail(self.primitive, trail):
            raise ValueError("MiniZinc returned an invalid differential trail")
        return trail


class PresentActiveSBoxesCPModel(PresentDifferentialCPModel):
    """Minimize active S-boxes over the exact two-round PRESENT relation.

    EXAMPLES::

        >>> from claasp.primitives import Present
        >>> query = PresentActiveSBoxesCPModel(
        ...     Present(number_of_rounds=2)
        ... ).cp_model()
        >>> (len(query.declarations), query.solve.startswith("solve minimize"))
        (288, True)
    """

    model_provenance = _direct_model(
        ConstraintBackend.CP,
        "PresentActiveSBoxesCPModel",
        "xor_differential_activity",
        "active-input objective over exact DDT table constraints",
        "The feasible region is identical to the reviewed exact differential model.",
    )

    def __init__(self, primitive) -> None:
        problem = (
            primitive
            if isinstance(primitive, PropagationProblem)
            else PropagationProblem(primitive, XOR_DIFFERENTIAL, maximum_weight=128)
        )
        super().__init__(problem)

    def cp_model(self) -> MiniZincModel:
        """Return exact differential tables with an activity objective."""

        weighted = super().cp_model()
        first_output = tuple(f"round_1_sbox_output_{bit}" for bit in range(64))
        permutation = _component(self.primitive, "p_layer_1", Permutation)
        round_inputs = (
            tuple(f"plaintext_{bit}" for bit in range(64)),
            tuple(first_output[position] for position in permutation.mapping),
        )
        active = tuple(
            f"active_{round_number}_{nibble}"
            for round_number in range(1, 3)
            for nibble in range(16)
        )
        declarations = weighted.declarations + tuple(f"var bool: {name};" for name in active)
        constraints = list(weighted.constraints[:-1])
        for round_number, inputs in enumerate(round_inputs, 1):
            for nibble in range(16):
                names = inputs[4 * nibble : 4 * nibble + 4]
                constraints.append(
                    f"constraint active_{round_number}_{nibble} = (sum([{','.join(names)}]) > 0);"
                )
        solve = "solve minimize sum([" + ",".join(f"bool2int({name})" for name in active) + "]);"
        return MiniZincModel(
            declarations,
            tuple(constraints),
            solve,
            weighted.includes,
            weighted.outputs,
            weighted.provenance,
            weighted.name_mapping,
            (ConstraintModelApplication(self.model_provenance),),
        )


class PresentFixedActiveSBoxesCPModel(PresentActiveSBoxesCPModel):
    """Minimize exact weight after fixing the PRESENT active-S-box count.

    EXAMPLES::

        >>> from claasp.primitives import Present
        >>> query = PresentFixedActiveSBoxesCPModel(
        ...     Present(number_of_rounds=2), active_sboxes=2
        ... ).cp_model()
        >>> (len(query.constraints), query.solve.startswith("solve minimize"))
        (66, True)
    """

    model_provenance = _direct_model(
        ConstraintBackend.CP,
        "PresentFixedActiveSBoxesCPModel",
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

    def cp_model(self) -> MiniZincModel:
        """Return exact weight minimization at the selected activity count."""

        active_model = super().cp_model()
        active = tuple(
            f"active_{round_number}_{nibble}"
            for round_number in range(1, 3)
            for nibble in range(16)
        )
        weights = tuple(
            f"round_{round_number}_sbox_{nibble}_weight"
            for round_number in range(1, 3)
            for nibble in range(16)
        )
        constraint = (
            "constraint sum(["
            + ",".join(f"bool2int({name})" for name in active)
            + f"]) = {self.active_sboxes};"
        )
        solve = "solve minimize " + " + ".join(weights) + ";"
        return MiniZincModel(
            active_model.declarations,
            active_model.constraints + (constraint,),
            solve,
            active_model.includes,
            active_model.outputs,
            active_model.provenance,
            active_model.name_mapping,
            (ConstraintModelApplication(self.model_provenance),),
        )


class PresentLinearCPModel:
    """Native table-constraint model for three-round PRESENT masks.

    EXAMPLES::

        >>> from claasp.primitives import Present
        >>> problem = PropagationProblem(
        ...     Present(number_of_rounds=3), XOR_LINEAR, maximum_weight=4
        ... )
        >>> query = PresentLinearCPModel(problem).cp_model()
        >>> (query.includes, query.constraints[-1].endswith("<= 4;"))
        (('include "table.mzn";',), True)
    """

    def __init__(self, problem: PropagationProblem) -> None:
        if not isinstance(problem, PropagationProblem):
            raise TypeError("problem must be a PropagationProblem")
        if problem.semantics != XOR_LINEAR:
            raise ValueError("linear CP lowering requires XOR-linear semantics")
        if problem.maximum_weight is None:
            raise ValueError("linear CP lowering requires maximum_weight")
        if problem.primitive.family_name != "present" or len(problem.primitive.rounds) != 3:
            raise NotImplementedError("linear CP lowering currently supports PRESENT-3")
        self.problem = problem
        self.primitive = problem.primitive
        self._records = ()
        self._input_names = ()
        self._last_output_names = ()

    def cp_model(self) -> MiniZincModel:
        """Lower exact signed-LAT support and absolute weights to tables."""

        declarations = []
        constraints = []
        input_names = tuple(f"plaintext_mask_{bit}" for bit in range(64))
        for name in input_names:
            declarations.append(f"var 0..1: {name};")
        current_input = input_names
        weight_names = []
        records = []
        last_output = ()
        for round_number in range(1, 4):
            output_names = tuple(f"round_{round_number}_sbox_mask_{bit}" for bit in range(64))
            for name in output_names:
                declarations.append(f"var 0..1: {name};")
            for nibble, component in enumerate(_round_sboxes(self.primitive, round_number)):
                start = 4 * nibble
                local_input = current_input[start : start + 4]
                local_output = output_names[start : start + 4]
                weight_name = f"round_{round_number}_linear_{nibble}_weight"
                weight_names.append(weight_name)
                declarations.append(f"var 0..3: {weight_name};")
                rows = []
                semantics = self.problem.provider_for(component)
                for source in range(16):
                    for target in range(16):
                        transition = semantics.transition((source,), target)
                        if transition.is_possible:
                            rows.append(
                                (*_bits(source, 4), *_bits(target, 4), int(transition.weight))
                            )
                table_name = f"round_{round_number}_linear_{nibble}_table"
                flattened = ",".join(str(item) for row in rows for item in row)
                declarations.append(
                    f"array[0..{len(rows) - 1}, 1..9] of int: {table_name} = "
                    f"array2d(0..{len(rows) - 1}, 1..9, [{flattened}]);"
                )
                variables = ",".join((*local_input, *local_output, weight_name))
                constraints.append(f"constraint table([{variables}], {table_name});")
                records.append((component.component_id, local_input, local_output))
            permutation = _component(self.primitive, f"p_layer_{round_number}", Permutation)
            current_input = tuple(output_names[position] for position in permutation.mapping)
            last_output = output_names
        constraints.append("constraint " + " + ".join(input_names) + " >= 1;")
        constraints.append(
            "constraint " + " + ".join(weight_names) + f" <= {self.problem.maximum_weight};"
        )
        self._records = tuple(records)
        self._input_names = input_names
        self._last_output_names = last_output
        return MiniZincModel(
            tuple(declarations),
            tuple(constraints),
            includes=('include "table.mzn";',),
            provenance=self.problem.provenance,
        )

    def decode_trail(self, assignment) -> Trail:
        """Recover signed transitions and reject a semantically invalid witness."""

        if not self._records:
            raise ValueError("build the CP model before decoding a trail")
        components = {component.component_id: component for component in self.primitive.components}
        steps = []
        for component_id, inputs, outputs in self._records:
            semantics = self.problem.provider_for(components[component_id])
            source = _integer(assignment[name] for name in inputs)
            target = _integer(assignment[name] for name in outputs)
            steps.append(TrailStep(component_id, semantics.transition((source,), target)))
        raw_output = _integer(assignment[name] for name in self._last_output_names)
        final = _permute(raw_output, _component(self.primitive, "p_layer_3", Permutation).mapping)
        trail = Trail(
            TrailKind.XOR_LINEAR,
            XorMask(_integer(assignment[name] for name in self._input_names), 64),
            XorMask(final, 64),
            tuple(steps),
        )
        if not check_present_linear_smt_trail(self.primitive, trail):
            raise ValueError("MiniZinc returned an invalid linear trail")
        return trail


class SpeckDifferentialCPModel:
    """Exact native CP model for Speck XOR-differential trails.

    The reviewed slice is Speck32/64 with zero key difference. Decoded
    transitions are recounted by independent paired-carry semantics.


    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> problem = PropagationProblem(
        ...     Speck(number_of_rounds=3), XOR_DIFFERENTIAL, maximum_weight=6
        ... )
        >>> model = SpeckDifferentialCPModel(
        ...     problem, input_difference=0x02110A04, output_difference=0x80008000
        ... )
        >>> model.cp_model().constraints[-1].endswith("<= 6;")
        True
    """

    def __init__(
        self,
        problem: PropagationProblem,
        *,
        input_difference=None,
        output_difference=None,
        boundary_relation=None,
        round_count=None,
    ) -> None:
        if not isinstance(problem, PropagationProblem):
            raise TypeError("problem must be a PropagationProblem")
        if problem.semantics != XOR_DIFFERENTIAL:
            raise ValueError("Speck CP lowering requires XOR-differential semantics")
        plaintext = problem.primitive.input_ports.get("plaintext")
        if (
            problem.primitive.family_name != "speck"
            or plaintext is None
            or not isinstance(plaintext.value_type.domain, Word)
            or plaintext.value_type.domain.width != 16
        ):
            raise NotImplementedError("the reviewed CP slice supports Speck32/64")
        if problem.maximum_weight is None:
            raise ValueError("Speck CP lowering requires maximum_weight")
        self.problem = problem
        self.primitive = problem.primitive
        self.width = 16
        for value in (input_difference, output_difference):
            if value is not None:
                XorDifference(value, 32)
        self.input_difference = input_difference
        self.output_difference = output_difference
        if boundary_relation not in (None, "equal", "not_equal"):
            raise ValueError("boundary_relation must be equal or not_equal")
        self.boundary_relation = boundary_relation
        self.round_count = len(self.primitive.rounds) if round_count is None else round_count
        if (
            not isinstance(self.round_count, int)
            or isinstance(self.round_count, bool)
            or not 1 <= self.round_count <= len(self.primitive.rounds)
        ):
            raise ValueError("round_count must select a nonempty Speck prefix")

    def cp_model(self) -> MiniZincModel:
        """Compile exact support, weight bits, and deterministic round wiring."""

        rounds = self.round_count
        declarations = [_MODADD_DIFFERENTIAL_PREDICATE]
        constraints = []
        for boundary in range(rounds + 1):
            declarations.extend(
                (
                    f"array[0..15] of var bool: x_{boundary};",
                    f"array[0..15] of var bool: y_{boundary};",
                )
            )
        for round_number in range(rounds):
            declarations.append(f"array[0..14] of var bool: weight_{round_number};")
            alpha = _component(self.primitive, f"round_{round_number}_rotate_right", Rotate).amount
            beta = _component(self.primitive, f"round_{round_number}_rotate_left", Rotate).amount
            constraints.append(
                "constraint modular_addition_xor_difference("
                f"{_array_rotation(f'x_{round_number}', -alpha, self.width)}, "
                f"y_{round_number}, x_{round_number + 1}, weight_{round_number});"
            )
            for index in range(self.width):
                constraints.append(
                    f"constraint y_{round_number + 1}[{index}] = "
                    f"(y_{round_number}[{(index + beta) % self.width}] != "
                    f"x_{round_number + 1}[{index}]);"
                )
        constraints.append(r"constraint exists(i in 0..15)(x_0[i] \/ y_0[i]);")
        for boundary, value in ((0, self.input_difference), (rounds, self.output_difference)):
            if value is None:
                continue
            for bit in range(32):
                name = "x" if bit < 16 else "y"
                encoded = "true" if value & (1 << (31 - bit)) else "false"
                constraints.append(f"constraint {name}_{boundary}[{bit % 16}] = {encoded};")
        if self.boundary_relation == "equal":
            for name in ("x", "y"):
                constraints.append(
                    f"constraint forall(i in 0..15)({name}_0[i] = {name}_{rounds}[i]);"
                )
        elif self.boundary_relation == "not_equal":
            constraints.append(
                f"constraint exists(i in 0..15)(x_0[i] != x_{rounds}[i] \\/ y_0[i] != y_{rounds}[i]);"
            )
        weight_terms = [
            f"bool2int(weight_{round_number}[{bit}])"
            for round_number in range(rounds)
            for bit in range(self.width - 1)
        ]
        constraints.append(
            f"constraint sum([{', '.join(weight_terms)}]) <= {self.problem.maximum_weight};"
        )
        return MiniZincModel(
            tuple(declarations), tuple(constraints), provenance=self.problem.provenance
        )

    def decode_trail(self, assignment) -> Trail:
        """Decode and independently validate a MiniZinc Speck trail."""

        semantics = ModularAddTransitionSemantics(self.width)
        steps = []
        left = _boolean_word(assignment["x_0"])
        right = _boolean_word(assignment["y_0"])
        initial = (left << self.width) | right
        for round_number in range(self.round_count):
            alpha = _component(self.primitive, f"round_{round_number}_rotate_right", Rotate).amount
            beta = _component(self.primitive, f"round_{round_number}_rotate_left", Rotate).amount
            output = _boolean_word(assignment[f"x_{round_number + 1}"])
            transition = semantics.xor_differential(
                _rotate_right_integer(left, alpha, self.width), right, output
            )
            if not transition.is_possible:
                raise ValueError("MiniZinc returned an impossible modular-add transition")
            next_right = _rotate_left_integer(right, beta, self.width) ^ output
            if next_right != _boolean_word(assignment[f"y_{round_number + 1}"]):
                raise ValueError("MiniZinc returned invalid Speck round wiring")
            component_id = self.primitive.round_operations[round_number]["modular_add"].component_id
            steps.append(TrailStep(component_id, transition))
            left, right = output, next_right
        trail = Trail(
            TrailKind.XOR_DIFFERENTIAL,
            XorDifference(initial, 2 * self.width),
            XorDifference((left << self.width) | right, 2 * self.width),
            tuple(steps),
        )
        if (
            not initial
            or trail.total_weight > self.problem.maximum_weight
            or (self.input_difference is not None and initial != self.input_difference)
            or (
                self.output_difference is not None
                and trail.output_pattern.value != self.output_difference
            )
        ):
            raise ValueError("MiniZinc assignment violates requested Speck boundaries or weight")
        equal = initial == trail.output_pattern.value
        if (self.boundary_relation == "equal" and not equal) or (
            self.boundary_relation == "not_equal" and equal
        ):
            raise ValueError("MiniZinc assignment violates requested boundary relation")
        return trail


class SpeckARXWindowDifferentialCPModel(SpeckDifferentialCPModel):
    """Apply the legacy per-round n-window pruning to exact Speck trails.

    The window constraint is a search heuristic over the exact modular-add
    feasible region. It is opt-in and never replaces the unpruned model.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> problem = PropagationProblem(
        ...     Speck(number_of_rounds=3), XOR_DIFFERENTIAL, maximum_weight=45
        ... )
        >>> query = SpeckARXWindowDifferentialCPModel(
        ...     problem, window_sizes=(3, 3, 3)
        ... ).cp_model()
        >>> "arx_window_left_0" in query.constraints[-3]
        True
    """

    model_provenance = _direct_model(
        ConstraintBackend.CP,
        "SpeckARXWindowDifferentialCPModel",
        "xor_differential_window_heuristic",
        "legacy per-round n-window pruning over exact modular-add constraints",
        "The heuristic is explicit and does not change the underlying transition semantics.",
    )

    def __init__(self, problem, *, window_sizes, **options) -> None:
        super().__init__(problem, **options)
        if (
            not isinstance(window_sizes, (tuple, list))
            or len(window_sizes) != self.round_count
            or any(
                not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < self.width
                for value in window_sizes
            )
        ):
            raise ValueError("window_sizes must provide one integer from 0 through 15 per round")
        self.window_sizes = tuple(window_sizes)

    def cp_model(self) -> MiniZincModel:
        """Return exact Speck constraints plus opt-in legacy window pruning."""

        exact = super().cp_model()
        declarations = list(exact.declarations)
        constraints = list(exact.constraints)
        for round_number, window in enumerate(self.window_sizes):
            alpha = _component(self.primitive, f"round_{round_number}_rotate_right", Rotate).amount
            left = f"arx_window_left_{round_number}"
            declarations.append(
                f"array[0..15] of var bool: {left} = "
                f"{_array_rotation(f'x_{round_number}', -alpha, self.width)};"
            )
            constraints.append(
                f"constraint forall(i in 0..{self.width - 1 - window})("
                f"not forall(j in 0..{window})("
                f"xorall([{left}[i+j], y_{round_number}[i+j], "
                f"x_{round_number + 1}[i+j]])));"
            )
        return MiniZincModel(
            tuple(declarations),
            tuple(constraints),
            exact.solve,
            exact.includes,
            exact.outputs,
            exact.provenance,
            exact.name_mapping,
            (ConstraintModelApplication(self.model_provenance),),
        )


class SpeckTruncatedCPModel:
    """Compile one fixed deterministic-truncated Speck round propagation.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> problem = PropagationProblem(
        ...     Speck(number_of_rounds=2), DETERMINISTIC_TRUNCATED_XOR
        ... )
        >>> difference = TruncatedXorDifference.parse(
        ...     "00000000011111001110000000000000"
        ... )
        >>> model = SpeckTruncatedCPModel(problem, difference)
        >>> str(model.expected_output)
        '????100000000000????100000000011'
    """

    def __init__(
        self, problem: PropagationProblem, input_difference: TruncatedXorDifference
    ) -> None:
        if not isinstance(problem, PropagationProblem):
            raise TypeError("problem must be a PropagationProblem")
        if problem.semantics != DETERMINISTIC_TRUNCATED_XOR:
            raise ValueError("truncated CP lowering requires deterministic-truncated semantics")
        if problem.primitive.family_name != "speck":
            raise NotImplementedError("truncated CP lowering currently supports Speck")
        if not isinstance(input_difference, TruncatedXorDifference):
            raise TypeError("input_difference must be a TruncatedXorDifference")
        self.problem = problem
        self.input_difference = input_difference
        self.expected_output = propagate_two_word_speck_round(problem.primitive, input_difference)

    def cp_model(self) -> MiniZincModel:
        """Represent the shared paired-carry result using three-valued CP units."""

        declarations = []
        constraints = []
        for prefix, pattern in (
            ("plaintext_truncated", self.input_difference),
            ("round_0_output_truncated", self.expected_output),
        ):
            for index, bit in enumerate(pattern.bits):
                name = f"{prefix}_{index}"
                declarations.append(f"var 0..2: {name};")
                constraints.append(f"constraint {name} = {bit.encoded};")
        return MiniZincModel(
            tuple(declarations), tuple(constraints), provenance=self.problem.provenance
        )

    def decode_output(self, assignment) -> TruncatedXorDifference:
        """Decode and independently compare the solver's three-valued output."""

        symbols = {0: "0", 1: "1", 2: "?"}
        pattern = TruncatedXorDifference.parse(
            "".join(
                symbols[assignment[f"round_0_output_truncated_{index}"]]
                for index in range(len(self.expected_output.bits))
            )
        )
        if pattern != self.expected_output:
            raise ValueError("MiniZinc returned an invalid truncated propagation")
        return pattern


class SpeckProbabilisticTruncatedCPModel:
    """Compose counter-based probabilistic truncated semantics over Speck.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> from claasp.semantics import PROBABILISTIC_TRUNCATED_XOR
        >>> problem = PropagationProblem(
        ...     Speck(number_of_rounds=2), PROBABILISTIC_TRUNCATED_XOR
        ... )
        >>> model = SpeckProbabilisticTruncatedCPModel(
        ...     problem,
        ...     TruncatedXorDifference.parse("00000000011111001110000000000000"),
        ...     TruncatedXorDifference.parse("???????????????1???????????????1"),
        ... )
        >>> model.cp_model().solve
        'solve minimize scaled_weight;'
    """

    def __init__(
        self,
        problem: PropagationProblem,
        input_pattern: TruncatedXorDifference,
        output_pattern: TruncatedXorDifference,
    ) -> None:
        from claasp.semantics import PROBABILISTIC_TRUNCATED_XOR

        if problem.semantics != PROBABILISTIC_TRUNCATED_XOR:
            raise ValueError("Speck model requires probabilistic-truncated XOR semantics")
        plaintext = problem.primitive.input_ports.get("plaintext")
        if (
            problem.primitive.family_name != "speck"
            or plaintext is None
            or not isinstance(plaintext.value_type.domain, Word)
            or plaintext.value_type.domain.width != 16
        ):
            raise NotImplementedError("the reviewed slice supports Speck32/64")
        if len(input_pattern.bits) != 32 or len(output_pattern.bits) != 32:
            raise ValueError("Speck32 patterns must contain 32 bits")
        self.problem = problem
        self.primitive = problem.primitive
        self.input_pattern = input_pattern
        self.output_pattern = output_pattern
        self.width = 16

    def cp_model(self) -> MiniZincModel:
        """Compile fixed boundaries and minimize the composed scaled weight."""

        rounds = len(self.primitive.rounds)
        declarations = [_PROBABILISTIC_TRUNCATED_MODADD_PREDICATE]
        constraints = []
        for boundary in range(rounds + 1):
            declarations.extend(
                (
                    f"array[0..15] of var 0..2: x_{boundary};",
                    f"array[0..15] of var 0..2: y_{boundary};",
                )
            )
        probabilities = []
        for round_number in range(rounds):
            declarations.extend(
                (
                    f"array[0..15] of var 0..2: carry_{round_number};",
                    f"array[0..15] of var {{0,4,9,19,41,100}}: costs_{round_number};",
                    f"var int: probability_{round_number};",
                )
            )
            probabilities.append(f"probability_{round_number}")
            alpha = _component(self.primitive, f"round_{round_number}_rotate_right", Rotate).amount
            beta = _component(self.primitive, f"round_{round_number}_rotate_left", Rotate).amount
            constraints.extend(
                (
                    "constraint counter_based_probabilistic_truncated_modadd("
                    f"{_array_rotation(f'x_{round_number}', -alpha, self.width)}, "
                    f"y_{round_number}, x_{round_number + 1}, carry_{round_number}, "
                    f"costs_{round_number}, probability_{round_number});",
                    f"constraint costs_{round_number}[15] = 0;",
                )
            )
            for index in range(self.width):
                source = (index + beta) % self.width
                constraints.append(
                    f"constraint y_{round_number + 1}[{index}] = "
                    f"truncated_xor2(y_{round_number}[{source}], "
                    f"x_{round_number + 1}[{index}]);"
                )
        constraints.extend(
            (
                _fixed_array("x_0", TruncatedXorDifference(self.input_pattern.bits[:16])),
                _fixed_array("y_0", TruncatedXorDifference(self.input_pattern.bits[16:])),
                _fixed_array(f"x_{rounds}", TruncatedXorDifference(self.output_pattern.bits[:16])),
                _fixed_array(f"y_{rounds}", TruncatedXorDifference(self.output_pattern.bits[16:])),
            )
        )
        declarations.append("var int: scaled_weight;")
        constraints.append(f"constraint scaled_weight = sum([{', '.join(probabilities)}]);")
        return MiniZincModel(
            tuple(declarations),
            tuple(constraints),
            solve="solve minimize scaled_weight;",
            provenance=self.problem.provenance,
        )

    def decode_trail(self, assignment) -> ProbabilisticTruncatedTrail:
        """Decode all additions and independently check transitions and wiring."""

        transitions = []
        left = TruncatedXorDifference(self.input_pattern.bits[:16])
        right = TruncatedXorDifference(self.input_pattern.bits[16:])
        for round_number in range(len(self.primitive.rounds)):
            alpha = _component(self.primitive, f"round_{round_number}_rotate_right", Rotate).amount
            beta = _component(self.primitive, f"round_{round_number}_rotate_left", Rotate).amount
            output = _decode_truncated(assignment[f"x_{round_number + 1}"])
            transition = ProbabilisticTruncatedModularAddTransition(
                left.rotate_right(alpha),
                right,
                output,
                _decode_truncated(assignment[f"carry_{round_number}"]),
                tuple(int(value) for value in assignment[f"costs_{round_number}"]),
            )
            if not check_probabilistic_truncated_modular_add(transition):
                raise ValueError("invalid probabilistic truncated addition")
            next_right = right.rotate_left(beta).xor(output)
            if next_right != _decode_truncated(assignment[f"y_{round_number + 1}"]):
                raise ValueError("invalid probabilistic truncated Speck wiring")
            transitions.append(transition)
            left, right = output, next_right
        trail = ProbabilisticTruncatedTrail(
            self.input_pattern,
            TruncatedXorDifference(left.bits + right.bits),
            tuple(transitions),
        )
        if trail.output_pattern != self.output_pattern:
            raise ValueError("decoded trail does not meet its output boundary")
        if trail.scaled_weight != int(assignment["scaled_weight"]):
            raise ValueError("inconsistent composed scaled weight")
        return trail


class WordwiseDifferenceCPModel:
    """Expose typed word states as a native MiniZinc enum.

    EXAMPLES::

        >>> words = (
        ...     WordwiseXorDifference(8, WordwiseDifferenceKind.ZERO),
        ...     WordwiseXorDifference.known(8, 0x53),
        ...     WordwiseXorDifference(8, WordwiseDifferenceKind.UNKNOWN),
        ... )
        >>> query = WordwiseDifferenceCPModel(words).cp_model()
        >>> query.declarations[0]
        'enum WordDifferenceState = {ZERO, KNOWN, NONZERO, UNKNOWN};'
    """

    def __init__(self, words: tuple[WordwiseXorDifference, ...]) -> None:
        if not words or any(not isinstance(word, WordwiseXorDifference) for word in words):
            raise ValueError("words must contain wordwise XOR differences")
        if len({word.width for word in words}) != 1:
            raise ValueError("wordwise CP values must have one common width")
        self.words = words
        self.width = words[0].width

    def cp_model(self) -> MiniZincModel:
        """Encode semantic states directly, with no legacy integer sentinels."""

        last = len(self.words) - 1
        maximum = (1 << self.width) - 1
        declarations = (
            "enum WordDifferenceState = {ZERO, KNOWN, NONZERO, UNKNOWN};",
            f"array[0..{last}] of var WordDifferenceState: state;",
            f"array[0..{last}] of var 0..{maximum}: value;",
        )
        constraints = []
        for index, word in enumerate(self.words):
            constraints.append(f"constraint state[{index}] = {word.kind.name};")
            if word.kind is WordwiseDifferenceKind.KNOWN:
                constraints.append(f"constraint value[{index}] = {word.value};")
            else:
                # Canonical don't-care value keeps solver output deterministic;
                # meaning is carried exclusively by the enum state.
                constraints.append(f"constraint value[{index}] = 0;")
        return MiniZincModel(
            declarations,
            tuple(constraints),
            provenance=("typed wordwise XOR-difference states",),
        )

    def decode(self, assignment) -> tuple[WordwiseXorDifference, ...]:
        """Project enum states back to typed values and verify the boundary."""

        decoded = []
        for state, value in zip(assignment["state"], assignment["value"]):
            encoded_state = state.get("e") if isinstance(state, dict) else str(state)
            kind = WordwiseDifferenceKind[encoded_state]
            decoded.append(
                WordwiseXorDifference.known(self.width, int(value))
                if kind is WordwiseDifferenceKind.KNOWN
                else WordwiseXorDifference(self.width, kind)
            )
        result = tuple(decoded)
        if result != self.words:
            raise ValueError("MiniZinc changed a fixed wordwise boundary")
        return result


class SpeckContinuousHeuristicCPModel:
    """Evaluate the recovered continuous Speck approximation in MiniZinc.

    This validates one fixed numerical input and deliberately exposes no proof
    or optimality status.

    EXAMPLES::

        >>> model = SpeckContinuousHeuristicCPModel(
        ...     (-1.0,) * 16, (-1.0,) * 16, rounds=2
        ... )
        >>> query = model.cp_model()
        >>> (len(query.declarations), len(query.constraints), query.solve)
        (10, 160, 'solve satisfy;')
    """

    model_provenance = _unaudited_model(
        ConstraintBackend.CP,
        "SpeckContinuousHeuristicCPModel",
        "continuous_differential_linear_heuristic",
        "recovered nonlinear continuous XOR, carry, and modular-add equations",
        "The numerical formulation is heuristic and cannot establish a cryptanalytic proof.",
    )

    def __init__(self, left, right, *, rounds: int, tolerance: float = 1e-4) -> None:
        from claasp.semantics.cryptanalysis import continuous_speck32

        self.left = tuple(float(value) for value in left)
        self.right = tuple(float(value) for value in right)
        self.rounds = rounds
        self.tolerance = tolerance
        self._expected = continuous_speck32(self.left, self.right, rounds=rounds)
        if tolerance <= 0:
            raise ValueError("tolerance must be positive")
        self._query: MiniZincModel | None = None

    def cp_model(self) -> MiniZincModel:
        """Return a fixed-input nonlinear MiniZinc feasibility query."""

        declarations = []
        for boundary in range(self.rounds + 1):
            declarations.extend(
                (
                    f"array[0..15] of var -1.0..1.0: x_{boundary};",
                    f"array[0..15] of var -1.0..1.0: y_{boundary};",
                )
            )
            if boundary < self.rounds:
                declarations.extend(
                    (
                        f"array[0..15] of var -1.0..1.0: carry_{boundary};",
                        f"array[0..15] of var -1.0..1.0: add_{boundary};",
                    )
                )
        constraints = [
            *(f"constraint x_0[{i}] = {value:.17g};" for i, value in enumerate(self.left)),
            *(f"constraint y_0[{i}] = {value:.17g};" for i, value in enumerate(self.right)),
        ]
        for round_number in range(self.rounds):
            constraints.append(f"constraint carry_{round_number}[15] = -1.0;")
            for index in reversed(range(16)):
                rotated_x = (index - 7) % 16
                constraints.append(
                    f"constraint abs(add_{round_number}[{index}] - ("
                    f"x_{round_number}[{rotated_x}] * y_{round_number}[{index}] * "
                    f"carry_{round_number}[{index}])) <= {self.tolerance:.17g};"
                )
                constraints.append(
                    f"constraint x_{round_number + 1}[{index}] = add_{round_number}[{index}];"
                )
                rotated_y = (index + 2) % 16
                constraints.append(
                    f"constraint abs(y_{round_number + 1}[{index}] - ("
                    f"-y_{round_number}[{rotated_y}] * x_{round_number + 1}[{index}])) "
                    f"<= {self.tolerance:.17g};"
                )
                if index:
                    constraints.append(
                        f"constraint abs(carry_{round_number}[{index - 1}] - (0.25 * ("
                        f"x_{round_number}[{rotated_x}] + y_{round_number}[{index}] + "
                        f"carry_{round_number}[{index}] + x_{round_number}[{rotated_x}] * "
                        f"y_{round_number}[{index}] * carry_{round_number}[{index}]))) "
                        f"<= {self.tolerance:.17g};"
                    )
        self._query = MiniZincModel(
            tuple(declarations),
            tuple(constraints),
            provenance=(
                "recovered legacy continuous Speck equations",
                "heuristic numerical evidence only",
            ),
            constraint_models=(ConstraintModelApplication(self.model_provenance),),
        )
        return self._query

    def decode_result(self, assignment):
        """Check MiniZinc values against independent Python propagation."""

        from claasp.semantics.cryptanalysis import ContinuousHeuristicResult

        if self._query is None:
            raise ValueError("build the CP model before decoding")
        values = tuple(float(value) for value in assignment[f"x_{self.rounds}"]) + tuple(
            float(value) for value in assignment[f"y_{self.rounds}"]
        )
        accumulated_tolerance = self.tolerance * self.rounds * 16
        if any(
            abs(actual - expected) > accumulated_tolerance
            for actual, expected in zip(values, self._expected.values)
        ):
            raise ValueError("MiniZinc continuous result differs from independent propagation")
        return ContinuousHeuristicResult(
            values,
            accumulated_tolerance,
            "recovered MiniZinc continuous Speck model; independently rechecked in Python",
        )


class ImpossibleBoundaryCPModel:
    """Prove that forward and backward partial patterns contradict.

    EXAMPLES::

        >>> boundary = ImpossiblePropagationBoundary(
        ...     TruncatedXorDifference.parse("01??0"),
        ...     TruncatedXorDifference.parse("00?11"),
        ... )
        >>> boundary.contradictory_positions
        (1, 4)
        >>> ImpossibleBoundaryCPModel(boundary).cp_model().constraints[-1]
        'constraint exists(i in 0..4)(contradiction[i]);'
    """

    def __init__(self, boundary: ImpossiblePropagationBoundary) -> None:
        if not isinstance(boundary, ImpossiblePropagationBoundary):
            raise TypeError("boundary must be an ImpossiblePropagationBoundary")
        self.boundary = boundary

    def cp_model(self) -> MiniZincModel:
        """Compile an existential fixed-bit contradiction at the boundary."""

        width = len(self.boundary.forward.bits)
        declarations = (
            f"array[0..{width - 1}] of var 0..2: forward;",
            f"array[0..{width - 1}] of var 0..2: backward;",
            f"array[0..{width - 1}] of var bool: contradiction;",
        )
        constraints = [
            _fixed_array("forward", self.boundary.forward),
            _fixed_array("backward", self.boundary.backward),
        ]
        constraints.extend(
            rf"constraint contradiction[{index}] = "
            rf"(forward[{index}] < 2 /\ backward[{index}] < 2 /\ "
            rf"forward[{index}] != backward[{index}]);"
            for index in range(width)
        )
        constraints.append(f"constraint exists(i in 0..{width - 1})(contradiction[i]);")
        return MiniZincModel(
            declarations,
            tuple(constraints),
            provenance=("forward/backward impossible propagation boundary",),
        )

    def decode_boundary(self, assignment) -> ImpossiblePropagationBoundary:
        """Decode and independently confirm the contradiction positions."""

        decoded = ImpossiblePropagationBoundary(
            _decode_truncated(assignment["forward"]),
            _decode_truncated(assignment["backward"]),
        )
        solver_positions = tuple(
            index for index, value in enumerate(assignment["contradiction"]) if bool(value)
        )
        if decoded != self.boundary or solver_positions != decoded.contradictory_positions:
            raise ValueError("MiniZinc returned an invalid impossible boundary")
        if not decoded.is_impossible:
            raise ValueError("decoded boundary is compatible")
        return decoded


class SpeckImpossibleCPModel:
    """Search a zero-key Speck impossible differential across a round split.

    This preserves the legacy bitwise deterministic-truncated search: both
    external differences are nonzero and the forward and backward segments
    must contain opposite known bits at their shared boundary.


    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> model = SpeckImpossibleCPModel(Speck(number_of_rounds=7), middle_round=3)
        >>> model.cp_model().provenance[-1]
        '7 rounds, split after round 3, zero key difference'
    """

    def __init__(self, primitive, middle_round: int) -> None:
        plaintext = primitive.input_ports.get("plaintext")
        if (
            primitive.family_name != "speck"
            or plaintext is None
            or not isinstance(plaintext.value_type.domain, Word)
            or plaintext.value_type.domain.width != 16
        ):
            raise NotImplementedError("the reviewed impossible slice supports Speck32/64")
        if not 1 <= middle_round < len(primitive.rounds):
            raise ValueError("middle_round must be inside the primitive")
        self.primitive = primitive
        self.middle_round = middle_round
        self.width = 16

    def cp_model(self) -> MiniZincModel:
        """Compile independent forward/backward segments meeting in conflict."""

        rounds = len(self.primitive.rounds)
        declarations = [_DETERMINISTIC_TRUNCATED_MODADD_PREDICATE]
        constraints = []
        for prefix, boundaries in (
            ("forward", range(self.middle_round + 1)),
            ("backward", range(self.middle_round, rounds + 1)),
        ):
            for boundary in boundaries:
                declarations.extend(
                    (
                        f"array[0..15] of var 0..2: {prefix}_x_{boundary};",
                        f"array[0..15] of var 0..2: {prefix}_y_{boundary};",
                    )
                )
        for round_number in range(self.middle_round):
            prefix = "forward"
            alpha = _component(self.primitive, f"round_{round_number}_rotate_right", Rotate).amount
            beta = _component(self.primitive, f"round_{round_number}_rotate_left", Rotate).amount
            constraints.append(
                "constraint deterministic_truncated_modadd("
                f"{_array_rotation(f'{prefix}_x_{round_number}', -alpha, self.width)}, "
                f"{prefix}_y_{round_number}, {prefix}_x_{round_number + 1});"
            )
            for index in range(self.width):
                source = (index + beta) % self.width
                constraints.append(
                    f"constraint {prefix}_y_{round_number + 1}[{index}] = "
                    f"truncated_xor2({prefix}_y_{round_number}[{source}], "
                    f"{prefix}_x_{round_number + 1}[{index}]);"
                )
        for round_number in reversed(range(self.middle_round, rounds)):
            alpha = _component(self.primitive, f"round_{round_number}_rotate_right", Rotate).amount
            beta = _component(self.primitive, f"round_{round_number}_rotate_left", Rotate).amount
            for index in range(self.width):
                # old_y = ROR(new_y XOR new_x, beta)
                source = (index - beta) % self.width
                constraints.append(
                    f"constraint backward_y_{round_number}[{index}] = "
                    f"truncated_xor2(backward_y_{round_number + 1}[{source}], "
                    f"backward_x_{round_number + 1}[{source}]);"
                )
            # old_x = ROL(new_x - old_y, alpha).  The legacy modular
            # subtraction abstraction uses the same directional predicate.
            constraints.append(
                "constraint deterministic_truncated_modadd("
                f"backward_x_{round_number + 1}, backward_y_{round_number}, "
                f"{_array_rotation(f'backward_x_{round_number}', alpha, self.width)});"
            )
        constraints.extend(
            (
                r"constraint exists(i in 0..15)(forward_x_0[i] != 0 \/ forward_y_0[i] != 0);",
                rf"constraint exists(i in 0..15)(backward_x_{rounds}[i] != 0 \/ backward_y_{rounds}[i] != 0);",
                "constraint exists(i in 0..15)("
                + rf"(forward_x_{self.middle_round}[i] + backward_x_{self.middle_round}[i] = 1) \/ "
                + f"(forward_y_{self.middle_round}[i] + backward_y_{self.middle_round}[i] = 1));",
            )
        )
        return MiniZincModel(
            tuple(declarations),
            tuple(constraints),
            provenance=(
                "legacy MznImpossibleXorDifferentialModel Speck32/64 fixture",
                "7 rounds, split after round 3, zero key difference",
            ),
        )


class SimonImpossibleCPModel:
    """Compose the legacy fully-automatic Simon impossible fixture.

    EXAMPLES::

        >>> from claasp.primitives import Simon
        >>> model = SimonImpossibleCPModel(
        ...     Simon(number_of_rounds=11),
        ...     TruncatedXorDifference.parse("00000000000000000000000000000001"),
        ...     TruncatedXorDifference.parse("000000?0?00000000000000000000000"),
        ...     middle_round=6,
        ... )
        >>> model.cp_model().provenance[-1]
        'legacy Simon32/64 11-round fully-automatic impossible fixture'
    """

    def __init__(self, primitive, input_pattern, output_pattern, middle_round: int) -> None:
        if primitive.family_name != "simon" or len(input_pattern.bits) != 32:
            raise NotImplementedError("the reviewed impossible slice supports Simon32/64")
        if len(output_pattern.bits) != 32:
            raise ValueError("Simon32 output patterns must contain 32 bits")
        if not 1 <= middle_round < len(primitive.rounds):
            raise ValueError("middle_round must be inside the primitive")
        self.primitive, self.input_pattern = primitive, input_pattern
        self.output_pattern, self.middle_round = output_pattern, middle_round

    def cp_model(self) -> MiniZincModel:
        """Compile directional Simon propagation and a middle contradiction."""

        rounds = len(self.primitive.rounds)
        declarations, constraints = [_SIMON_TRUNCATED_FUNCTIONS], []
        for prefix, boundaries in (
            ("forward", range(self.middle_round + 1)),
            ("backward", range(self.middle_round, rounds + 1)),
        ):
            for boundary in boundaries:
                declarations.extend(
                    (
                        f"array[0..15] of var 0..2: {prefix}_x_{boundary};",
                        f"array[0..15] of var 0..2: {prefix}_y_{boundary};",
                    )
                )
        for round_number in range(self.middle_round):
            for index in range(16):
                constraints.extend(
                    (
                        f"constraint forward_x_{round_number + 1}[{index}] = truncated_xor2("
                        f"truncated_xor2(forward_y_{round_number}[{index}], truncated_and2("
                        f"forward_x_{round_number}[{(index + 1) % 16}], forward_x_{round_number}[{(index + 8) % 16}])), "
                        f"forward_x_{round_number}[{(index + 2) % 16}]);",
                        f"constraint forward_y_{round_number + 1}[{index}] = forward_x_{round_number}[{index}];",
                    )
                )
        for round_number in reversed(range(self.middle_round, rounds)):
            for index in range(16):
                constraints.extend(
                    (
                        f"constraint backward_x_{round_number}[{index}] = backward_y_{round_number + 1}[{index}];",
                        f"constraint backward_y_{round_number}[{index}] = truncated_xor2("
                        f"truncated_xor2(backward_x_{round_number + 1}[{index}], truncated_and2("
                        f"backward_y_{round_number + 1}[{(index + 1) % 16}], backward_y_{round_number + 1}[{(index + 8) % 16}])), "
                        f"backward_y_{round_number + 1}[{(index + 2) % 16}]);",
                    )
                )
        constraints.extend(
            (
                _fixed_array("forward_x_0", TruncatedXorDifference(self.input_pattern.bits[:16])),
                _fixed_array("forward_y_0", TruncatedXorDifference(self.input_pattern.bits[16:])),
                _fixed_array(
                    f"backward_x_{rounds}", TruncatedXorDifference(self.output_pattern.bits[:16])
                ),
                _fixed_array(
                    f"backward_y_{rounds}", TruncatedXorDifference(self.output_pattern.bits[16:])
                ),
                "constraint exists(i in 0..15)("
                + rf"(forward_x_{self.middle_round}[i] + backward_x_{self.middle_round}[i] = 1) \/ "
                + f"(forward_y_{self.middle_round}[i] + backward_y_{self.middle_round}[i] = 1));",
            )
        )
        return MiniZincModel(
            tuple(declarations),
            tuple(constraints),
            provenance=("legacy Simon32/64 11-round fully-automatic impossible fixture",),
        )

    def decode_boundary(self, assignment) -> ImpossiblePropagationBoundary:
        """Decode both middle patterns and check them independently in Python."""

        forward = self.input_pattern
        for _ in range(self.middle_round):
            forward = propagate_two_word_simon_round(forward)
        backward = self.output_pattern
        for _ in range(len(self.primitive.rounds) - self.middle_round):
            backward = propagate_two_word_simon_inverse_round(backward)
        decoded = ImpossiblePropagationBoundary(
            TruncatedXorDifference(
                _decode_truncated(assignment[f"forward_x_{self.middle_round}"]).bits
                + _decode_truncated(assignment[f"forward_y_{self.middle_round}"]).bits
            ),
            TruncatedXorDifference(
                _decode_truncated(assignment[f"backward_x_{self.middle_round}"]).bits
                + _decode_truncated(assignment[f"backward_y_{self.middle_round}"]).bits
            ),
        )
        if decoded != ImpossiblePropagationBoundary(forward, backward) or not decoded.is_impossible:
            raise ValueError("MiniZinc returned an invalid Simon impossible boundary")
        return decoded


def _bits(value, width):
    return tuple((value >> (width - 1 - bit)) & 1 for bit in range(width))


def _integer(bits):
    value = 0
    for bit in bits:
        value = (value << 1) | int(bit)
    return value


def _permute(value, mapping):
    bits = _bits(value, len(mapping))
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
    if component is None and primitive.family_name == "speck":
        parts = component_id.split("_")
        if len(parts) >= 4 and parts[0] == "round" and parts[1].isdigit():
            operation = "_".join(parts[2:])
            component = primitive.round_operations[int(parts[1])].get(operation)
    if not isinstance(component, expected_type):
        raise ValueError(f"primitive is missing {component_id!r}")
    return component


def _array_rotation(name, offset, width):
    values = ",".join(f"{name}[{(index + offset) % width}]" for index in range(width))
    return f"array1d(0..{width - 1}, [{values}])"


def _boolean_word(bits):
    return _integer(int(bit) for bit in bits)


def _rotate_left_integer(value, amount, width):
    mask = (1 << width) - 1
    return ((value << amount) | (value >> (width - amount))) & mask


def _rotate_right_integer(value, amount, width):
    mask = (1 << width) - 1
    return ((value >> amount) | (value << (width - amount))) & mask


def _fixed_array(name, pattern):
    values = ",".join(str(bit.encoded) for bit in pattern.bits)
    return f"constraint {name} = array1d(0..{len(pattern.bits) - 1}, [{values}]);"


def _decode_truncated(values):
    symbols = {0: "0", 1: "1", 2: "?"}
    return TruncatedXorDifference.parse("".join(symbols[int(value)] for value in values))


_MODADD_DIFFERENTIAL_PREDICATE = r"""
predicate modular_addition_xor_difference(
    array[int] of var bool: a,
    array[int] of var bool: b,
    array[int] of var bool: c,
    array[int] of var bool: weight
) =
    forall(j in 0..length(a)-2)(
        (a[j] \/ b[j] \/ not c[j] \/ a[j+1] \/ b[j+1] \/ c[j+1]) /\
        (a[j] \/ not b[j] \/ c[j] \/ a[j+1] \/ b[j+1] \/ c[j+1]) /\
        (not a[j] \/ b[j] \/ c[j] \/ a[j+1] \/ b[j+1] \/ c[j+1]) /\
        (not a[j] \/ not b[j] \/ not c[j] \/ a[j+1] \/ b[j+1] \/ c[j+1]) /\
        (a[j] \/ b[j] \/ c[j] \/ not a[j+1] \/ not b[j+1] \/ not c[j+1]) /\
        (a[j] \/ not b[j] \/ not c[j] \/ not a[j+1] \/ not b[j+1] \/ not c[j+1]) /\
        (not a[j] \/ b[j] \/ not c[j] \/ not a[j+1] \/ not b[j+1] \/ not c[j+1]) /\
        (not a[j] \/ not b[j] \/ c[j] \/ not a[j+1] \/ not b[j+1] \/ not c[j+1]) /\
        (not a[j+1] \/ c[j+1] \/ weight[j]) /\
        (b[j+1] \/ not c[j+1] \/ weight[j]) /\
        (a[j+1] \/ not b[j+1] \/ weight[j]) /\
        (a[j+1] \/ b[j+1] \/ c[j+1] \/ not weight[j]) /\
        (not a[j+1] \/ not b[j+1] \/ not c[j+1] \/ not weight[j])
    ) /\
    ((a[length(a)-1] != b[length(a)-1]) = c[length(a)-1]);
""".strip()


class WordDeterministicTruncatedCPModel:
    """Assemble deterministic-truncated Word graphs as MiniZinc CP.

    EXAMPLES::

        >>> from claasp.primitives import ToySpeck
        >>> model = WordDeterministicTruncatedCPModel(
        ...     ToySpeck(2),
        ...     fixed_input_patterns={"key": "0" * 16},
        ...     nonzero_input="plaintext",
        ... )
        >>> query = model.cp_model()
        >>> (len(query.declarations) > 0, query.constraint_models[0].model.backend.value)
        (True, 'cp')
    """

    model_provenance = _direct_model(
        ConstraintBackend.CP,
        "WordDeterministicTruncatedCPModel",
        "deterministic_truncated_xor",
        "MiniZinc translation of deterministic-truncated Word graph clauses",
        "Graph wiring and recovered paired-carry clauses are translated exactly.",
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
        self._query: MiniZincModel | None = None

    def cp_model(self) -> MiniZincModel:
        """Return the complete deterministic-truncated graph query."""

        lowered = BooleanMiniZincLowerer().lower(self._sat_model.cnf_formula())
        self._query = MiniZincModel(
            lowered.declarations,
            lowered.constraints,
            lowered.solve,
            lowered.includes,
            lowered.outputs,
            lowered.provenance,
            lowered.name_mapping,
            (ConstraintModelApplication(self.model_provenance),),
        )
        return self._query

    def decode_characteristic(self, assignment):
        """Decode and independently validate a complete CP assignment."""

        if self._query is None:
            raise ValueError("build the CP model before decoding")
        return self._sat_model.decode_characteristic(assignment)

    def check_characteristic(self, trail) -> bool:
        """Recheck graph propagation and requested boundary restrictions."""

        if self._query is None:
            raise ValueError("build the CP model before checking")
        return self._sat_model.check_characteristic(trail)


class WordwiseDeterministicTruncatedCPModel:
    """Assemble four-state wordwise propagation as native MiniZinc Boolean CP.

    EXAMPLES::

        >>> from claasp.primitives import ToyAES
        >>> model = WordwiseDeterministicTruncatedCPModel(
        ...     ToyAES(number_of_rounds=1, word_size=4, state_size=2),
        ...     zero_difference_inputs=("key",), nonzero_input="plaintext",
        ... )
        >>> query = model.cp_model()
        >>> (len(query.declarations), query.constraint_models[0].model.backend.value)
        (324, 'cp')
    """

    model_provenance = _direct_model(
        ConstraintBackend.CP,
        "WordwiseDeterministicTruncatedCPModel",
        "wordwise_deterministic_truncated_xor",
        "MiniZinc translation of the exact four-state word-graph formula",
        "Known values, abstract activity, wiring, and dense layers retain typed decoding.",
    )

    def __init__(
        self,
        primitive,
        *,
        fixed_input_differences=None,
        output_differences=None,
        zero_difference_inputs=(),
        nonzero_input=None,
    ) -> None:
        from claasp.representations.constraints.sat.trails import (
            WordwiseDeterministicTruncatedSATModel,
        )

        self._sat_model = WordwiseDeterministicTruncatedSATModel(
            primitive,
            fixed_input_differences=fixed_input_differences,
            output_differences=output_differences,
            zero_difference_inputs=zero_difference_inputs,
            nonzero_input=nonzero_input,
        )
        self.primitive = primitive
        self._query: MiniZincModel | None = None

    def cp_model(self) -> MiniZincModel:
        """Return the complete MiniZinc feasibility query."""

        lowered = BooleanMiniZincLowerer().lower(self._sat_model.cnf_formula())
        self._query = MiniZincModel(
            lowered.declarations,
            lowered.constraints,
            lowered.solve,
            lowered.includes,
            lowered.outputs,
            lowered.provenance,
            lowered.name_mapping,
            (ConstraintModelApplication(self.model_provenance),),
        )
        return self._query

    def decode_characteristic(self, assignment):
        """Decode and independently validate a complete MiniZinc witness."""

        if self._query is None:
            raise ValueError("build the CP model before decoding")
        return self._sat_model.decode_characteristic(assignment)

    def check_characteristic(self, trail) -> bool:
        """Recheck component propagation, wiring, and boundaries."""

        if self._query is None:
            raise ValueError("build the CP model before checking")
        return self._sat_model.check_characteristic(trail)


class WordDifferentialCPModel:
    """Assemble exact XOR-differential Word graphs as portable MiniZinc.

    The complete reviewed Boolean relation is translated exactly to MiniZinc;
    decoding delegates to the independently checked Word-graph semantics.

    EXAMPLES::

        >>> from claasp.primitives import ToySpeck
        >>> model = WordDifferentialCPModel(
        ...     ToySpeck(2), fixed_weight=1,
        ...     fixed_input_differences={"key": 0}, nonzero_input="plaintext",
        ... )
        >>> query = model.cp_model()
        >>> (len(query.declarations), query.constraint_models[0].model.backend.value)
        (187, 'cp')
    """

    model_provenance = _direct_model(
        ConstraintBackend.CP,
        "WordDifferentialCPModel",
        "xor_differential",
        "exact MiniZinc translation of the reviewed Boolean Word-graph relation",
        "The portable CP formulation preserves the complete Boolean relation without a literature claim.",
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
        self._query: MiniZincModel | None = None

    def cp_model(self) -> MiniZincModel:
        """Return the exact portable MiniZinc query."""

        lowered = BooleanMiniZincLowerer().lower(self._sat_model.cnf_formula())
        self._query = MiniZincModel(
            lowered.declarations,
            lowered.constraints,
            lowered.solve,
            lowered.includes,
            lowered.outputs,
            lowered.provenance,
            lowered.name_mapping,
            (ConstraintModelApplication(self.model_provenance),),
        )
        return self._query

    def decode_characteristic(self, assignment):
        """Decode and independently validate a complete CP assignment."""

        if self._query is None:
            raise ValueError("build the CP model before decoding")
        return self._sat_model.decode_characteristic(assignment)

    def check_characteristic(self, trail) -> bool:
        """Recheck component transitions, wiring, and requested boundaries."""

        if self._query is None:
            raise ValueError("build the CP model before checking")
        return self._sat_model.check_characteristic(trail)


@dataclass(frozen=True, slots=True)
class ModularAddBoomerangTrailResult:
    """Two exact differential characteristics joined by one add switch.

    EXAMPLES::

        >>> from types import SimpleNamespace
        >>> result = ModularAddBoomerangTrailResult(
        ...     SimpleNamespace(total_weight=2), SimpleNamespace(weight=1),
        ...     SimpleNamespace(total_weight=3),
        ... )
        >>> (result.search_weight, result.total_weight)
        (5, 6)
    """

    upper: object
    switch: object
    lower: object

    @property
    def search_weight(self):
        """Return the upper-plus-lower objective optimized by the CP model."""

        return self.upper.total_weight + self.lower.total_weight

    @property
    def total_weight(self):
        """Return the decoded characteristic weight including the switch."""

        return self.search_weight + self.switch.weight


class ModularAddBoomerangTrailCPModel:
    """Compose top and bottom Word trails through an exact modular-add switch.

    The supplied top graph must expose the switch word as its output. The
    selected bottom input is connected to the lower side of the switch. The
    CP objective minimizes the two characteristic weights; the exact switch
    count and weight are decoded and reported separately because the recovered
    legacy ARX objective did not charge the switch relation.

    EXAMPLES::

        >>> from claasp import Primitive, ValueType, Word
        >>> from claasp.components import ModularAdd
        >>> def add_graph(name):
        ...     graph = Primitive(name, {"left": ValueType(Word(4), (1,)),
        ...         "right": ValueType(Word(4), (1,))})
        ...     graph.add_round()
        ...     graph.set_output(graph.add_component(
        ...         ModularAdd((graph.input("left"), graph.input("right")))))
        ...     return graph
        >>> options = dict(maximum_weight=3, nonzero_input="left",
        ...     fixed_input_differences={"right": 0})
        >>> model = ModularAddBoomerangTrailCPModel(
        ...     WordDifferentialCPModel(add_graph("top"), **options),
        ...     WordDifferentialCPModel(add_graph("bottom"), **options),
        ...     ModularAddBoomerangCPModel(4), lower_input="left")
        >>> "switch_delta_left" in model.cp_model().source()
        True
    """

    model_provenance = _unaudited_model(
        ConstraintBackend.CP,
        "ModularAddBoomerangTrailCPModel",
        "boomerang",
        "complete top/switch/bottom MiniZinc composition",
        "The switch is exact; the search objective preserves the legacy upper-plus-lower cost.",
    )

    def __init__(
        self,
        upper,
        lower,
        switch,
        *,
        lower_input=None,
        lower_output_input=None,
        lower_right_input=None,
    ) -> None:
        if not isinstance(upper, WordDifferentialCPModel) or not isinstance(
            lower, WordDifferentialCPModel
        ):
            raise TypeError("upper and lower must be WordDifferentialCPModel instances")
        if not isinstance(switch, ModularAddBoomerangCPModel):
            raise TypeError("switch must be a ModularAddBoomerangCPModel")
        full_switch = lower_output_input is not None or lower_right_input is not None
        if full_switch == (lower_input is not None):
            raise ValueError("choose lower_input or both lower_output_input and lower_right_input")
        if full_switch and (
            lower_output_input not in lower.primitive.input_ports
            or lower_right_input not in lower.primitive.input_ports
        ):
            raise ValueError("full switch inputs must name bottom-graph inputs")
        if not full_switch and lower_input not in lower.primitive.input_ports:
            raise ValueError("lower_input must name a bottom-graph input")
        upper_size = upper.primitive.output.value_type.encoded_bit_size
        expected_upper_size = 2 * switch.width if full_switch else switch.width
        if upper_size != expected_upper_size:
            raise ValueError(f"top output must contain exactly {expected_upper_size} bits")
        lower_names = (lower_output_input, lower_right_input) if full_switch else (lower_input,)
        if any(
            lower.primitive.input_ports[name].value_type.encoded_bit_size != switch.width
            for name in lower_names
        ):
            raise ValueError("each selected bottom input must contain exactly one switch word")
        self.upper = upper
        self.lower = lower
        self.switch = switch
        self.lower_input = lower_input
        self.lower_output_input = lower_output_input
        self.lower_right_input = lower_right_input
        self.full_switch = full_switch
        self._query: MiniZincModel | None = None

    @staticmethod
    def _rewrite(lines, replacements):
        if not replacements:
            return tuple(lines)
        pattern = re.compile(r"\b(" + "|".join(map(re.escape, replacements)) + r")\b")
        return tuple(
            pattern.sub(lambda match: replacements[match.group(0)], line) for line in lines
        )

    @classmethod
    def _boolean_namespace(cls, query, prefix):
        replacements = {encoded: prefix + encoded for encoded, _ in query.name_mapping}
        return (
            cls._rewrite(query.declarations, replacements),
            cls._rewrite(query.constraints, replacements),
            {logical: replacements[encoded] for encoded, logical in query.name_mapping},
            tuple(
                (replacements[encoded], f"{prefix[:-1]}::{logical}")
                for encoded, logical in query.name_mapping
            ),
        )

    def cp_model(self) -> MiniZincModel:
        """Return one solver query containing both trails and their switch."""

        upper_query = self.upper.cp_model()
        lower_query = self.lower.cp_model()
        switch_query = self.switch.cp_model()
        upper_declarations, upper_constraints, upper_names, upper_mapping = self._boolean_namespace(
            upper_query, "upper_"
        )
        lower_declarations, lower_constraints, lower_names, lower_mapping = self._boolean_namespace(
            lower_query, "lower_"
        )
        switch_names = {
            name: "switch_" + name
            for name in (
                "delta_left",
                "delta_right",
                "nabla_output",
                "nabla_right",
                "state",
                "transitions",
                "switch_possible",
            )
        }
        switch_declarations = self._rewrite(switch_query.declarations, switch_names)
        switch_constraints = self._rewrite(switch_query.constraints, switch_names)
        upper_output = self.upper._sat_model._shared._output
        lower_inputs = (
            (
                self.lower._sat_model._shared._ports[self.lower_output_input],
                self.lower._sat_model._shared._ports[self.lower_right_input],
            )
            if self.full_switch
            else (self.lower._sat_model._shared._ports[self.lower_input],)
        )
        links = []
        for bit in range(self.switch.width):
            links.append(
                f"constraint switch_delta_left[{bit}] = bool2int("
                f"{upper_names[upper_output[self.switch.width - bit - 1]]});"
            )
            if self.full_switch:
                links.extend(
                    (
                        f"constraint switch_delta_right[{bit}] = bool2int("
                        f"{upper_names[upper_output[2 * self.switch.width - bit - 1]]});",
                        f"constraint switch_nabla_output[{bit}] = bool2int("
                        f"{lower_names[lower_inputs[0][self.switch.width - bit - 1]]});",
                        f"constraint switch_nabla_right[{bit}] = bool2int("
                        f"{lower_names[lower_inputs[1][self.switch.width - bit - 1]]});",
                    )
                )
            else:
                links.append(
                    f"constraint switch_nabla_right[{bit}] = bool2int("
                    f"{lower_names[lower_inputs[0][self.switch.width - bit - 1]]});"
                )
        if self.full_switch:
            links.append("constraint sum(switch_nabla_output) + sum(switch_nabla_right) >= 1;")
        upper_weights = tuple(
            upper_names[name]
            for name in self.upper._sat_model._shared._formula.variables
            if name.startswith("weight_") and not name.startswith("weight_complement_")
        )
        lower_weights = tuple(
            lower_names[name]
            for name in self.lower._sat_model._shared._formula.variables
            if name.startswith("weight_") and not name.startswith("weight_complement_")
        )
        objective = upper_weights + lower_weights
        solve = (
            "solve minimize " + " + ".join(f"bool2int({name})" for name in objective) + ";"
            if objective
            else "solve satisfy;"
        )
        self._query = MiniZincModel(
            upper_declarations + lower_declarations + switch_declarations,
            upper_constraints + lower_constraints + switch_constraints + tuple(links),
            solve,
            tuple(
                dict.fromkeys(
                    (*upper_query.includes, *lower_query.includes, *switch_query.includes)
                )
            ),
            provenance=(
                "exact top and bottom Word differential relations",
                "exact modular-add boomerang feasibility switch",
                "legacy objective excludes switch weight",
            ),
            name_mapping=upper_mapping + lower_mapping,
            constraint_models=(ConstraintModelApplication(self.model_provenance),),
        )
        return self._query

    def decode_trail(self, assignment):
        """Decode and independently recheck both trails and the exact switch."""

        if self._query is None:
            raise ValueError("build the CP model before decoding")
        upper_assignment = {
            name.removeprefix("upper::"): int(value)
            for name, value in assignment.items()
            if name.startswith("upper::")
        }
        lower_assignment = {
            name.removeprefix("lower::"): int(value)
            for name, value in assignment.items()
            if name.startswith("lower::")
        }
        switch_assignment = {
            name.removeprefix("switch_"): value
            for name, value in assignment.items()
            if name.startswith("switch_")
        }
        upper = self.upper.decode_characteristic(upper_assignment)
        lower = self.lower.decode_characteristic(lower_assignment)
        switch = self.switch.decode_connectivity(switch_assignment)
        if self.full_switch:
            mask = (1 << self.switch.width) - 1
            if upper.output_difference >> self.switch.width != switch.delta_left.value:
                raise ValueError("top trail left operand does not meet the modular-add switch")
            if upper.output_difference & mask != switch.delta_right.value:
                raise ValueError("top trail right operand does not meet the modular-add switch")
            lower_inputs = dict(lower.input_differences)
            if lower_inputs[self.lower_output_input] != switch.nabla_output.value:
                raise ValueError("bottom trail output branch does not meet the switch")
            if lower_inputs[self.lower_right_input] != switch.nabla_right.value:
                raise ValueError("bottom trail right branch does not meet the switch")
        else:
            if upper.output_difference != switch.delta_left.value:
                raise ValueError("top trail does not meet the modular-add switch")
            if dict(lower.input_differences)[self.lower_input] != switch.nabla_right.value:
                raise ValueError("bottom trail does not leave the modular-add switch")
        return ModularAddBoomerangTrailResult(upper, switch, lower)


class SpeckBoomerangCPModel:
    """Automatically partition Speck around one modular-add boomerang switch.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> model = SpeckBoomerangCPModel(
        ...     Speck(number_of_rounds=3), switch_round=1,
        ...     upper_maximum_weight=20, lower_maximum_weight=20,
        ... )
        >>> "switch_delta_right" in model.cp_model().source()
        True
    """

    model_provenance = _direct_model(
        ConstraintBackend.CP,
        "SpeckBoomerangCPModel",
        "boomerang",
        "automatic immutable Speck graph partition around an exact modular-add switch",
        "All four switch differences are linked to validated graph slices.",
    )

    def __init__(
        self,
        primitive,
        *,
        switch_round,
        upper_maximum_weight,
        lower_maximum_weight,
    ) -> None:
        from claasp.transformations import slice_primitive

        if primitive.family_name != "speck":
            raise NotImplementedError("automatic boomerang partitioning currently supports Speck")
        if (
            not isinstance(switch_round, int)
            or isinstance(switch_round, bool)
            or not 0 <= switch_round < len(primitive.rounds)
        ):
            raise ValueError("switch_round must select a Speck round")
        component = primitive.round_operations[switch_round]["modular_add"]
        upper_graph = slice_primitive(
            primitive,
            component.inputs,
            family_name=f"{primitive.family_name}_boomerang_upper_{switch_round}",
        ).primitive
        lower_graph = slice_primitive(
            primitive,
            primitive.output,
            inputs={"switch_output": component.output, "switch_right": component.inputs[1]},
            family_name=f"{primitive.family_name}_boomerang_lower_{switch_round}",
        ).primitive
        upper_fixed = {"key": 0} if "key" in upper_graph.input_ports else {}
        lower_fixed = {"key": 0} if "key" in lower_graph.input_ports else {}
        upper = WordDifferentialCPModel(
            upper_graph,
            maximum_weight=upper_maximum_weight,
            nonzero_input="plaintext",
            fixed_input_differences=upper_fixed,
        )
        lower = WordDifferentialCPModel(
            lower_graph,
            maximum_weight=lower_maximum_weight,
            fixed_input_differences=lower_fixed,
        )
        self.primitive = primitive
        self.switch_round = switch_round
        self.upper_graph = upper_graph
        self.lower_graph = lower_graph
        self._composition = ModularAddBoomerangTrailCPModel(
            upper,
            lower,
            ModularAddBoomerangCPModel(component.output_type.domain.width),
            lower_output_input="switch_output",
            lower_right_input="switch_right",
        )

    def cp_model(self) -> MiniZincModel:
        """Return the automatically partitioned complete composition."""

        query = self._composition.cp_model()
        return MiniZincModel(
            query.declarations,
            query.constraints,
            query.solve,
            query.includes,
            query.outputs,
            query.provenance + (f"automatic Speck switch round {self.switch_round}",),
            query.name_mapping,
            query.constraint_models + (ConstraintModelApplication(self.model_provenance),),
        )

    def decode_trail(self, assignment):
        """Decode the automatically partitioned upper, switch, and lower trail."""

        return self._composition.decode_trail(assignment)


@dataclass(frozen=True, slots=True)
class SBoxBoomerangTrailResult:
    """Two exact PRESENT characteristics joined by one S-box BCT entry.

    EXAMPLES::

        >>> from types import SimpleNamespace
        >>> result = SBoxBoomerangTrailResult(
        ...     SimpleNamespace(total_weight=2), SimpleNamespace(weight=1),
        ...     SimpleNamespace(total_weight=3), 0,
        ... )
        >>> (result.search_weight, result.total_weight)
        (5, 6)
    """

    upper: object
    switch: object
    lower: object
    nibble: int

    @property
    def search_weight(self):
        """Return the bounded upper-plus-lower characteristic weight."""

        return self.upper.total_weight + self.lower.total_weight

    @property
    def total_weight(self):
        """Return upper, switch, and lower weights together."""

        return self.search_weight + self.switch.weight


class SBoxBoomerangTrailCPModel:
    """Join two exact PRESENT-2 trails through one exact S-box BCT switch.

    The upper output is the input difference of the next PRESENT S-box layer;
    the lower input is that S-box's output difference. Both complete
    characteristics retain their requested weight bounds, while the solver
    maximizes the exact quartet count of the selected switch.

    EXAMPLES::

        >>> from claasp.primitives import Present
        >>> upper = PresentDifferentialCPModel(PropagationProblem(
        ...     Present(number_of_rounds=2), XOR_DIFFERENTIAL, maximum_weight=8))
        >>> lower = PresentDifferentialCPModel(PropagationProblem(
        ...     Present(number_of_rounds=2), XOR_DIFFERENTIAL, maximum_weight=8))
        >>> sbox = _round_sboxes(upper.primitive, 1)[0]
        >>> model = SBoxBoomerangTrailCPModel(
        ...     upper, lower, SBoxBoomerangCPModel(sbox), nibble=0)
        >>> "switch_quartet_count" in model.cp_model().source()
        True
    """

    model_provenance = _direct_model(
        ConstraintBackend.CP,
        "SBoxBoomerangTrailCPModel",
        "boomerang",
        "complete bounded PRESENT trails joined by an exact S-box BCT switch",
        "The selected BCT entry is exact and decoded independently.",
    )

    def __init__(self, upper, lower, switch, *, nibble) -> None:
        if not isinstance(upper, PresentDifferentialCPModel) or not isinstance(
            lower, PresentDifferentialCPModel
        ):
            raise TypeError("upper and lower must be PresentDifferentialCPModel instances")
        if not isinstance(switch, SBoxBoomerangCPModel):
            raise TypeError("switch must be an SBoxBoomerangCPModel")
        if not isinstance(nibble, int) or isinstance(nibble, bool) or not 0 <= nibble < 16:
            raise ValueError("nibble must be an integer from 0 through 15")
        upper_sbox = _round_sboxes(upper.primitive, 1)[nibble]
        lower_sbox = _round_sboxes(lower.primitive, 1)[nibble]
        if upper_sbox.table != switch.component.table or lower_sbox.table != switch.component.table:
            raise ValueError("both trail graphs and the switch must use the same S-box table")
        self.upper = upper
        self.lower = lower
        self.switch = switch
        self.nibble = nibble
        self._query: MiniZincModel | None = None

    @staticmethod
    def _rewrite(lines, replacements):
        pattern = re.compile(r"\b(" + "|".join(map(re.escape, replacements)) + r")\b")
        return tuple(
            pattern.sub(lambda match: replacements[match.group(0)], line) for line in lines
        )

    @classmethod
    def _namespace(cls, query, prefix):
        reserved = {"array", "array2d", "bool", "constraint", "int", "of", "sum", "table", "var"}
        identifiers = {
            name
            for name in re.findall(r"\b[A-Za-z_]\w*\b", "\n".join(query.declarations))
            if name not in reserved
        }
        replacements = {name: prefix + name for name in identifiers}
        scalar_names = tuple(
            match.group(1)
            for line in query.declarations
            if (match := re.search(r":\s*(\w+)\s*;\s*$", line))
        )
        mapping = tuple((replacements[name], f"{prefix[:-1]}::{name}") for name in scalar_names)
        return (
            cls._rewrite(query.declarations, replacements),
            cls._rewrite(query.constraints, replacements),
            replacements,
            mapping,
        )

    @staticmethod
    def _packed_expression(names):
        width = len(names)
        return " + ".join(f"{1 << (width - bit - 1)} * {name}" for bit, name in enumerate(names))

    def cp_model(self) -> MiniZincModel:
        """Return both bounded characteristics and the selected BCT switch."""

        upper_query = self.upper.cp_model()
        lower_query = self.lower.cp_model()
        switch_query = self.switch.cp_model()
        upper_declarations, upper_constraints, upper_names, upper_mapping = self._namespace(
            upper_query, "upper_"
        )
        lower_declarations, lower_constraints, lower_names, lower_mapping = self._namespace(
            lower_query, "lower_"
        )
        switch_names = {
            name: "switch_" + name
            for name in ("bct", "input_difference", "output_difference", "quartet_count")
        }
        switch_declarations = self._rewrite(switch_query.declarations, switch_names)
        switch_constraints = self._rewrite(switch_query.constraints, switch_names)
        final_permutation = _component(self.upper.primitive, "p_layer_2", Permutation)
        start = 4 * self.nibble
        upper_bits = tuple(
            upper_names[f"round_2_sbox_output_{final_permutation.mapping[bit]}"]
            for bit in range(start, start + 4)
        )
        lower_bits = tuple(lower_names[f"plaintext_{bit}"] for bit in range(start, start + 4))
        links = (
            f"constraint switch_input_difference = {self._packed_expression(upper_bits)};",
            f"constraint switch_output_difference = {self._packed_expression(lower_bits)};",
        )
        switch_mapping = tuple(
            (encoded, encoded)
            for encoded in (
                "switch_input_difference",
                "switch_output_difference",
                "switch_quartet_count",
            )
        )
        self._query = MiniZincModel(
            upper_declarations + lower_declarations + switch_declarations,
            upper_constraints + lower_constraints + switch_constraints + links,
            "solve maximize switch_quartet_count;",
            tuple(
                dict.fromkeys(
                    (*upper_query.includes, *lower_query.includes, *switch_query.includes)
                )
            ),
            provenance=(
                "exact bounded upper and lower PRESENT differential characteristics",
                "exact selected S-box boomerang connectivity table",
            ),
            name_mapping=upper_mapping + lower_mapping + switch_mapping,
            constraint_models=(ConstraintModelApplication(self.model_provenance),),
        )
        return self._query

    def decode_trail(self, assignment):
        """Decode and independently validate both trails and their BCT entry."""

        if self._query is None:
            raise ValueError("build the CP model before decoding")
        upper_assignment = {
            name.removeprefix("upper::"): value
            for name, value in assignment.items()
            if name.startswith("upper::")
        }
        lower_assignment = {
            name.removeprefix("lower::"): value
            for name, value in assignment.items()
            if name.startswith("lower::")
        }
        upper = self.upper.decode_trail(upper_assignment)
        lower = self.lower.decode_trail(lower_assignment)
        switch = self.switch.decode(
            {
                "input_difference": assignment["switch_input_difference"],
                "output_difference": assignment["switch_output_difference"],
                "quartet_count": assignment["switch_quartet_count"],
            }
        )
        shift = 64 - 4 * (self.nibble + 1)
        if (upper.output_pattern.value >> shift) & 0xF != switch.input_difference.value:
            raise ValueError("upper trail does not enter the selected S-box switch")
        if (lower.input_pattern.value >> shift) & 0xF != switch.output_difference.value:
            raise ValueError("lower trail does not leave the selected S-box switch")
        return SBoxBoomerangTrailResult(upper, switch, lower, self.nibble)


class WordLinearCPModel:
    """Assemble exact XOR-linear Word graphs as portable MiniZinc.

    EXAMPLES::

        >>> from claasp.primitives import ToySpeck
        >>> model = WordLinearCPModel(
        ...     ToySpeck(3), maximum_weight=1,
        ...     fixed_inputs={"key": 0}, nonzero_input="plaintext",
        ... )
        >>> query = model.cp_model()
        >>> (len(query.declarations) > 0, query.constraint_models[0].model.backend.value)
        (True, 'cp')
    """

    model_provenance = _direct_model(
        ConstraintBackend.CP,
        "WordLinearCPModel",
        "xor_linear",
        "exact MiniZinc translation of the reviewed Boolean Word-graph relation",
        "The portable CP formulation preserves the complete Boolean relation without a literature claim.",
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
        self._query: MiniZincModel | None = None

    def cp_model(self) -> MiniZincModel:
        """Return the exact portable MiniZinc query."""

        lowered = BooleanMiniZincLowerer().lower(self._sat_model.cnf_formula())
        self._query = MiniZincModel(
            lowered.declarations,
            lowered.constraints,
            lowered.solve,
            lowered.includes,
            lowered.outputs,
            lowered.provenance,
            lowered.name_mapping,
            (ConstraintModelApplication(self.model_provenance),),
        )
        return self._query

    def decode_characteristic(self, assignment):
        """Decode and independently validate a complete CP assignment."""

        if self._query is None:
            raise ValueError("build the CP model before decoding")
        return self._sat_model.decode_characteristic(assignment)

    def check_characteristic(self, trail) -> bool:
        """Recheck component masks, signs, wiring, and requested boundaries."""

        if self._query is None:
            raise ValueError("build the CP model before checking")
        return self._sat_model.check_characteristic(trail)


class WordDeterministicDifferentialLinearCPModel:
    """Assemble deterministic-middle differential-linear trails as MiniZinc.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> model = WordDeterministicDifferentialLinearCPModel(
        ...     Speck(number_of_rounds=3), prefix_rounds=1, middle_rounds=1,
        ...     differential_maximum_weight=16, linear_maximum_weight=16,
        ... )
        >>> query = model.cp_model()
        >>> (len(query.declarations), len(query.constraints))
        (2543, 7151)
    """

    model_provenance = _direct_model(
        ConstraintBackend.CP,
        "WordDeterministicDifferentialLinearCPModel",
        "differential_linear",
        "exact MiniZinc translation of the reviewed deterministic-middle composition",
        "The portable CP formulation preserves the reviewed Boolean composition exactly.",
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
        self._query: MiniZincModel | None = None

    def cp_model(self) -> MiniZincModel:
        """Return the exact portable MiniZinc query."""

        lowered = BooleanMiniZincLowerer().lower(self._sat_model.cnf_formula())
        self._query = MiniZincModel(
            lowered.declarations,
            lowered.constraints,
            lowered.solve,
            lowered.includes,
            lowered.outputs,
            lowered.provenance,
            lowered.name_mapping,
            (ConstraintModelApplication(self.model_provenance),),
        )
        return self._query

    def decode_trail(self, assignment):
        """Decode and independently validate all three trail sections."""

        if self._query is None:
            raise ValueError("build the CP model before decoding")
        return self._sat_model.decode_trail(assignment)


class WordImpossibleCPModel:
    """Search generic reversible Word graphs for a split-round contradiction.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> model = WordImpossibleCPModel(
        ...     Speck(number_of_rounds=3), middle_round=1,
        ...     active_input="plaintext", zero_difference_inputs=("key",),
        ... )
        >>> query = model.cp_model()
        >>> (len(query.declarations), len(query.constraints))
        (1568, 5674)
    """

    model_provenance = _direct_model(
        ConstraintBackend.CP,
        "WordImpossibleCPModel",
        "impossible_xor_differential",
        "exact MiniZinc translation of generic Word-graph impossible composition",
        "The CP formulation preserves every reviewed Boolean clause.",
    )

    def __init__(
        self,
        primitive,
        middle_round,
        *,
        active_input,
        zero_difference_inputs=(),
        input_pattern=None,
        output_pattern=None,
    ) -> None:
        from claasp.representations.constraints.sat.trails import WordImpossibleSATModel

        self._sat_model = WordImpossibleSATModel(
            primitive,
            middle_round,
            active_input=active_input,
            zero_difference_inputs=zero_difference_inputs,
            input_pattern=input_pattern,
            output_pattern=output_pattern,
        )
        self.primitive = primitive
        self._query: MiniZincModel | None = None

    def cp_model(self) -> MiniZincModel:
        """Return the exact portable MiniZinc query."""

        lowered = BooleanMiniZincLowerer().lower(self._sat_model.cnf_formula())
        self._query = MiniZincModel(
            lowered.declarations,
            lowered.constraints,
            lowered.solve,
            lowered.includes,
            lowered.outputs,
            lowered.provenance,
            lowered.name_mapping,
            (ConstraintModelApplication(self.model_provenance),),
        )
        return self._query

    def decode_trail(self, assignment):
        """Decode and independently validate both directions and contradiction."""

        if self._query is None:
            raise ValueError("build the CP model before decoding")
        return self._sat_model.decode_trail(assignment)


class WordwiseImpossibleCPModel:
    """Search a split-round four-state wordwise contradiction in MiniZinc.

    EXAMPLES::

        >>> from claasp.primitives import ToyAES
        >>> model = WordwiseImpossibleCPModel(
        ...     ToyAES(number_of_rounds=2, word_size=4, state_size=2), 1,
        ...     active_input="plaintext", zero_difference_inputs=("key",),
        ... )
        >>> query = model.cp_model()
        >>> (len(query.declarations), "wordwise_contradiction_exists" in query.provenance)
        (736, True)
    """

    model_provenance = _direct_model(
        ConstraintBackend.CP,
        "WordwiseImpossibleCPModel",
        "wordwise_impossible_xor_differential",
        "MiniZinc translation of composed four-state forward/backward graphs",
        "The selected abstract incompatibility is decoded independently.",
    )

    def __init__(
        self,
        primitive,
        middle_round,
        *,
        active_input,
        zero_difference_inputs=(),
        input_differences=None,
        output_differences=None,
    ) -> None:
        from claasp.representations.constraints.sat.trails import (
            WordwiseImpossibleSATModel,
        )

        self._sat_model = WordwiseImpossibleSATModel(
            primitive,
            middle_round,
            active_input=active_input,
            zero_difference_inputs=zero_difference_inputs,
            input_differences=input_differences,
            output_differences=output_differences,
        )
        self.primitive = primitive
        self._query: MiniZincModel | None = None

    def cp_model(self) -> MiniZincModel:
        """Return the complete MiniZinc feasibility query."""

        lowered = BooleanMiniZincLowerer().lower(self._sat_model.cnf_formula())
        self._query = MiniZincModel(
            lowered.declarations,
            lowered.constraints,
            lowered.solve,
            lowered.includes,
            lowered.outputs,
            lowered.provenance,
            lowered.name_mapping,
            (ConstraintModelApplication(self.model_provenance),),
        )
        return self._query

    def decode_trail(self, assignment):
        """Decode both directions and independently verify the contradiction."""

        if self._query is None:
            raise ValueError("build the CP model before decoding")
        return self._sat_model.decode_trail(assignment)


class SpeckSemiDeterministicTruncatedCPModel:
    """Assemble recovered look-ahead-window Speck trails as MiniZinc.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> model = SpeckSemiDeterministicTruncatedCPModel(
        ...     Speck(number_of_rounds=2),
        ...     "00000000011111001110000000000000",
        ...     "???????????????1???????????????1",
        ... )
        >>> query = model.cp_model()
        >>> (len(query.declarations), len(query.constraints))
        (672, 3483)
    """

    model_provenance = _unaudited_model(
        ConstraintBackend.CP,
        "SpeckSemiDeterministicTruncatedCPModel",
        "semi_deterministic_truncated_xor",
        "exact MiniZinc translation of the recovered look-ahead-window Speck model",
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
        self._query: MiniZincModel | None = None

    def cp_model(self) -> MiniZincModel:
        """Return the exact portable MiniZinc query."""

        lowered = BooleanMiniZincLowerer().lower(self._sat_model.cnf_formula())
        self._query = MiniZincModel(
            lowered.declarations,
            lowered.constraints,
            lowered.solve,
            lowered.includes,
            lowered.outputs,
            lowered.provenance,
            lowered.name_mapping,
            (ConstraintModelApplication(self.model_provenance),),
        )
        return self._query

    def decode_trail(self, assignment):
        """Decode and independently validate the complete Speck trail."""

        if self._query is None:
            raise ValueError("build the CP model before decoding")
        return self._sat_model.decode_trail(assignment)


class WordSemiDeterministicDifferentialLinearCPModel:
    """Assemble semi-deterministic differential-linear trails as MiniZinc.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> model = WordSemiDeterministicDifferentialLinearCPModel(
        ...     Speck(number_of_rounds=3), prefix_rounds=1, middle_rounds=1,
        ...     differential_maximum_weight=16,
        ...     middle_maximum_scaled_weight=None,
        ...     linear_maximum_weight=16,
        ... )
        >>> query = model.cp_model()
        >>> (len(query.declarations), len(query.constraints))
        (2303, 6599)
    """

    model_provenance = _unaudited_model(
        ConstraintBackend.CP,
        "WordSemiDeterministicDifferentialLinearCPModel",
        "differential_linear",
        "exact MiniZinc translation of the recovered semi-deterministic composition",
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
        self._query: MiniZincModel | None = None

    def cp_model(self) -> MiniZincModel:
        """Return the exact portable MiniZinc query."""

        lowered = BooleanMiniZincLowerer().lower(self._sat_model.cnf_formula())
        self._query = MiniZincModel(
            lowered.declarations,
            lowered.constraints,
            lowered.solve,
            lowered.includes,
            lowered.outputs,
            lowered.provenance,
            lowered.name_mapping,
            (ConstraintModelApplication(self.model_provenance),),
        )
        return self._query

    def decode_trail(self, assignment):
        """Decode and independently validate all three trail sections."""

        if self._query is None:
            raise ValueError("build the CP model before decoding")
        return self._sat_model.decode_trail(assignment)


_DETERMINISTIC_TRUNCATED_MODADD_PREDICATE = r"""
function var 0..2: truncated_xor2(var 0..2: a, var 0..2: b) =
    if a < 2 /\ b < 2 then (a + b) mod 2 else 2 endif;

function array[int] of var 0..2: truncated_left_shift(
    array[int] of var 0..2: values, int: amount
) = array1d(index_set(values), [
    if j < length(values) - amount then values[j + amount] else 0 endif
    | j in index_set(values)
]);

predicate deterministic_truncated_modadd(
    array[int] of var 0..2: a,
    array[int] of var 0..2: b,
    array[int] of var 0..2: c
) = let {
    int: n = length(a),
    array[0..n-1] of var 0..2: shifted_a = truncated_left_shift(a, 1),
    array[0..n-1] of var 0..2: shifted_b = truncated_left_shift(b, 1),
    array[0..n-1] of var 0..2: shifted_c = truncated_left_shift(c, 1),
    var 0..n-1: pivot
} in
    forall(i in 0..n-1)(
        if i < pivot then c[i] = 2
        else shifted_a[i] = 0 /\ shifted_b[i] = 0 /\ shifted_c[i] = 0
        endif
    ) /\
    (if a[pivot] < 2 /\ b[pivot] < 2
     then c[pivot] = (a[pivot] + b[pivot]) mod 2 else c[pivot] = 2 endif) /\
    (if pivot > 0 then a[pivot] + b[pivot] > 0 else true endif);
""".strip()


_SIMON_TRUNCATED_FUNCTIONS = r"""
function var 0..2: truncated_xor2(var 0..2: a, var 0..2: b) =
    if a < 2 /\ b < 2 then (a + b) mod 2 else 2 endif;

function var 0..2: truncated_and2(var 0..2: a, var 0..2: b) =
    if a = 0 /\ b = 0 then 0 else 2 endif;
""".strip()


_PROBABILISTIC_TRUNCATED_MODADD_PREDICATE = r"""
function var 0..2: truncated_xor2(var 0..2: a, var 0..2: b) =
    if a < 2 /\ b < 2 then (a + b) mod 2 else 2 endif;

function array[int] of var 0..2: truncated_xor3(
    array[int] of var 0..2: a,
    array[int] of var 0..2: b,
    array[int] of var 0..2: carry
) = array1d(index_set(a), [
    if a[j] < 2 /\ b[j] < 2 /\ carry[j] < 2
    then (a[j] + b[j] + carry[j]) mod 2 else 2 endif
    | j in index_set(a)
]);

predicate counter_based_probabilistic_truncated_modadd(
    array[int] of var 0..2: a,
    array[int] of var 0..2: b,
    array[int] of var 0..2: c,
    array[int] of var 0..2: carry,
    array[int] of var {0,4,9,19,41,100}: costs,
    var int: probability
) = let {
    int: n = length(a),
    array[0..n-1] of var 0..n: run_length
} in
    c = truncated_xor3(a, b, carry) /\
    carry[n-1] = 0 /\ run_length[n-1] = 0 /\
    forall(i in 0..n-2)(
        run_length[i] = if a[i+1] + b[i+1] = 0 /\ carry[i+1] = 2
                        then run_length[i+1] + 1 else 0 endif
    ) /\
    forall(i in 0..n-2)(
        if a[i+1] = 0 /\ b[i+1] = 0 /\ c[i+1] = 0 then
            carry[i] = 0 /\ costs[i] = 0
        elseif a[i+1] = 1 /\ b[i+1] = 1 /\ c[i+1] = 1 then
            carry[i] = 1 /\ costs[i] = 0
        else
            (carry[i] = 2 /\ costs[i] = 0) \/
            (run_length[i] = 0 /\ costs[i] = 100 /\ (carry[i] = 0 \/ carry[i] = 1)) \/
            (run_length[i] = 1 /\ costs[i] = 41 /\ carry[i] = 0) \/
            (run_length[i] = 2 /\ costs[i] = 19 /\ carry[i] = 0) \/
            (run_length[i] = 3 /\ costs[i] = 9 /\ carry[i] = 0) \/
            (run_length[i] = 4 /\ costs[i] = 4 /\ carry[i] = 0) \/
            (run_length[i] > 4 /\ costs[i] = 0 /\ carry[i] = 0)
        endif
    ) /\ probability = sum(costs);
""".strip()
