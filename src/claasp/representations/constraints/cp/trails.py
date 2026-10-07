"""Native CP lowering of shared cryptanalytic trail semantics."""

from claasp.components import BitVectorSBox, Permutation, Rotate
from claasp.domains import Word
from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _direct_model,
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
