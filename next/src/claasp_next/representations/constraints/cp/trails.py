"""Native CP lowering of shared cryptanalytic trail semantics."""

from claasp_next.components import BitVectorSBox, Permutation, Rotate
from claasp_next.domains import Word
from claasp_next.semantics import XOR_DIFFERENTIAL, XOR_LINEAR
from claasp_next.semantics.cryptanalysis import (
    ImpossiblePropagationBoundary, ModularAddTransitionSemantics, PropagationProblem,
    ProbabilisticTruncatedModularAddTransition, ProbabilisticTruncatedTrail,
    Trail, TrailKind, TrailStep,
    TruncatedXorDifference, XorDifference, XorMask,
    check_probabilistic_truncated_modular_add, propagate_two_word_speck_round,
    WordwiseDifferenceKind, WordwiseXorDifference,
)
from claasp_next.semantics import DETERMINISTIC_TRUNCATED_XOR
from claasp_next.representations.constraints.cp.model import MiniZincModel
from claasp_next.representations.constraints.smt.trails import (
    check_present_linear_smt_trail,
    check_present_smt_trail,
)


class PresentDifferentialCPModel:
    """Native table-constraint model for two-round PRESENT differences."""

    def __init__(self, problem: PropagationProblem) -> None:
        if not isinstance(problem, PropagationProblem):
            raise TypeError("problem must be a PropagationProblem")
        if problem.semantics != XOR_DIFFERENTIAL:
            raise ValueError("differential CP lowering requires XOR-differential semantics")
        if problem.maximum_weight is None:
            raise ValueError("differential CP lowering requires maximum_weight")
        if problem.cipher.family_name != "present" or len(problem.cipher.rounds) != 2:
            raise NotImplementedError("differential CP lowering currently supports PRESENT-2")
        self.problem = problem
        self.cipher = problem.cipher
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
        permutation = _component(self.cipher, "p_layer_1", Permutation)
        second_input = tuple(first_output[position] for position in permutation.mapping)
        weight_names = []
        records = []
        for round_number, (inputs, outputs) in enumerate(
            ((plaintext, first_output), (second_input, second_output)), start=1
        ):
            for nibble, component in enumerate(_round_sboxes(self.cipher, round_number)):
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
                            rows.append((*_bits(source, 4), *_bits(target, 4), int(transition.weight)))
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
            tuple(declarations), tuple(constraints),
            includes=('include "table.mzn";',), provenance=self.problem.provenance,
        )

    def decode_trail(self, assignment) -> Trail:
        """Project a solution to shared transitions and independently check it."""

        if not self._records:
            raise ValueError("build the CP model before decoding a trail")
        components = {component.component_id: component for component in self.cipher.components}
        steps = []
        for component_id, inputs, outputs in self._records:
            semantics = self.problem.provider_for(components[component_id])
            source = _integer(assignment[name] for name in inputs)
            target = _integer(assignment[name] for name in outputs)
            steps.append(TrailStep(component_id, semantics.transition((source,), target)))
        raw_output = _integer(assignment[name] for name in self._last_output_names)
        final = _permute(raw_output, _component(self.cipher, "p_layer_2", Permutation).mapping)
        trail = Trail(
            TrailKind.XOR_DIFFERENTIAL,
            XorDifference(_integer(assignment[name] for name in self._input_names), 64),
            XorDifference(final, 64), tuple(steps),
        )
        if not check_present_smt_trail(self.cipher, trail):
            raise ValueError("MiniZinc returned an invalid differential trail")
        return trail


class PresentLinearCPModel:
    """Native table-constraint model for three-round PRESENT masks."""

    def __init__(self, problem: PropagationProblem) -> None:
        if not isinstance(problem, PropagationProblem):
            raise TypeError("problem must be a PropagationProblem")
        if problem.semantics != XOR_LINEAR:
            raise ValueError("linear CP lowering requires XOR-linear semantics")
        if problem.maximum_weight is None:
            raise ValueError("linear CP lowering requires maximum_weight")
        if problem.cipher.family_name != "present" or len(problem.cipher.rounds) != 3:
            raise NotImplementedError("linear CP lowering currently supports PRESENT-3")
        self.problem = problem
        self.cipher = problem.cipher
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
            for nibble, component in enumerate(_round_sboxes(self.cipher, round_number)):
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
                            rows.append((*_bits(source, 4), *_bits(target, 4), int(transition.weight)))
                table_name = f"round_{round_number}_linear_{nibble}_table"
                flattened = ",".join(str(item) for row in rows for item in row)
                declarations.append(
                    f"array[0..{len(rows) - 1}, 1..9] of int: {table_name} = "
                    f"array2d(0..{len(rows) - 1}, 1..9, [{flattened}]);"
                )
                variables = ",".join((*local_input, *local_output, weight_name))
                constraints.append(f"constraint table([{variables}], {table_name});")
                records.append((component.component_id, local_input, local_output))
            permutation = _component(self.cipher, f"p_layer_{round_number}", Permutation)
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
            tuple(declarations), tuple(constraints),
            includes=('include "table.mzn";',), provenance=self.problem.provenance,
        )

    def decode_trail(self, assignment) -> Trail:
        """Recover signed transitions and reject a semantically invalid witness."""

        if not self._records:
            raise ValueError("build the CP model before decoding a trail")
        components = {component.component_id: component for component in self.cipher.components}
        steps = []
        for component_id, inputs, outputs in self._records:
            semantics = self.problem.provider_for(components[component_id])
            source = _integer(assignment[name] for name in inputs)
            target = _integer(assignment[name] for name in outputs)
            steps.append(TrailStep(component_id, semantics.transition((source,), target)))
        raw_output = _integer(assignment[name] for name in self._last_output_names)
        final = _permute(raw_output, _component(self.cipher, "p_layer_3", Permutation).mapping)
        trail = Trail(
            TrailKind.XOR_LINEAR,
            XorMask(_integer(assignment[name] for name in self._input_names), 64),
            XorMask(final, 64), tuple(steps),
        )
        if not check_present_linear_smt_trail(self.cipher, trail):
            raise ValueError("MiniZinc returned an invalid linear trail")
        return trail


class SpeckDifferentialCPModel:
    """Exact native CP model for Speck XOR-differential trails.

    The reviewed slice is Speck32/64 with zero key difference. Decoded
    transitions are recounted by independent paired-carry semantics.
    """

    def __init__(self, problem: PropagationProblem) -> None:
        if not isinstance(problem, PropagationProblem):
            raise TypeError("problem must be a PropagationProblem")
        if problem.semantics != XOR_DIFFERENTIAL:
            raise ValueError("Speck CP lowering requires XOR-differential semantics")
        plaintext = problem.cipher.inputs.get("plaintext")
        if (
            problem.cipher.family_name != "speck"
            or plaintext is None
            or not isinstance(plaintext.value_type.domain, Word)
            or plaintext.value_type.domain.width != 16
        ):
            raise NotImplementedError("the reviewed CP slice supports Speck32/64")
        if problem.maximum_weight is None:
            raise ValueError("Speck CP lowering requires maximum_weight")
        self.problem = problem
        self.cipher = problem.cipher
        self.width = 16

    def cp_model(self) -> MiniZincModel:
        """Compile exact support, weight bits, and deterministic round wiring."""

        rounds = len(self.cipher.rounds)
        declarations = [_MODADD_DIFFERENTIAL_PREDICATE]
        constraints = []
        for boundary in range(rounds + 1):
            declarations.extend((
                f"array[0..15] of var bool: x_{boundary};",
                f"array[0..15] of var bool: y_{boundary};",
            ))
        for round_number in range(rounds):
            declarations.append(f"array[0..14] of var bool: weight_{round_number};")
            alpha = _component(
                self.cipher, f"round_{round_number}_rotate_right", Rotate
            ).amount
            beta = _component(
                self.cipher, f"round_{round_number}_rotate_left", Rotate
            ).amount
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
        for round_number in range(len(self.cipher.rounds)):
            alpha = _component(
                self.cipher, f"round_{round_number}_rotate_right", Rotate
            ).amount
            beta = _component(
                self.cipher, f"round_{round_number}_rotate_left", Rotate
            ).amount
            output = _boolean_word(assignment[f"x_{round_number + 1}"])
            transition = semantics.xor_differential(
                _rotate_right_integer(left, alpha, self.width), right, output
            )
            if not transition.is_possible:
                raise ValueError("MiniZinc returned an impossible modular-add transition")
            next_right = _rotate_left_integer(right, beta, self.width) ^ output
            if next_right != _boolean_word(assignment[f"y_{round_number + 1}"]):
                raise ValueError("MiniZinc returned invalid Speck round wiring")
            steps.append(TrailStep(f"round_{round_number}_modular_add", transition))
            left, right = output, next_right
        return Trail(
            TrailKind.XOR_DIFFERENTIAL,
            XorDifference(initial, 2 * self.width),
            XorDifference((left << self.width) | right, 2 * self.width),
            tuple(steps),
        )


class SpeckTruncatedCPModel:
    """Compile one fixed deterministic-truncated Speck round propagation."""

    def __init__(
        self, problem: PropagationProblem, input_difference: TruncatedXorDifference
    ) -> None:
        if not isinstance(problem, PropagationProblem):
            raise TypeError("problem must be a PropagationProblem")
        if problem.semantics != DETERMINISTIC_TRUNCATED_XOR:
            raise ValueError("truncated CP lowering requires deterministic-truncated semantics")
        if problem.cipher.family_name != "speck":
            raise NotImplementedError("truncated CP lowering currently supports Speck")
        if not isinstance(input_difference, TruncatedXorDifference):
            raise TypeError("input_difference must be a TruncatedXorDifference")
        self.problem = problem
        self.input_difference = input_difference
        self.expected_output = propagate_two_word_speck_round(problem.cipher, input_difference)

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
        pattern = TruncatedXorDifference.parse("".join(
            symbols[assignment[f"round_0_output_truncated_{index}"]]
            for index in range(len(self.expected_output.bits))
        ))
        if pattern != self.expected_output:
            raise ValueError("MiniZinc returned an invalid truncated propagation")
        return pattern


class ProbabilisticTruncatedModularAddCPModel:
    """Native CP representation of one counter-based partial addition."""

    def __init__(
        self,
        left: TruncatedXorDifference,
        right: TruncatedXorDifference,
        output: TruncatedXorDifference,
        carry_difference: TruncatedXorDifference | None = None,
    ) -> None:
        if not all(isinstance(item, TruncatedXorDifference) for item in (left, right, output)):
            raise TypeError("left, right, and output must be truncated differences")
        width = len(left.bits)
        if len(right.bits) != width or len(output.bits) != width:
            raise ValueError("probabilistic truncated operands must have equal widths")
        if carry_difference is not None and len(carry_difference.bits) != width:
            raise ValueError("carry difference must have the operand width")
        self.left = left
        self.right = right
        self.output = output
        self.carry_difference = carry_difference
        self.width = width

    def cp_model(self) -> MiniZincModel:
        """Fix the boundary patterns and minimize the legacy scaled cost."""

        last = self.width - 1
        declarations = (
            _PROBABILISTIC_TRUNCATED_MODADD_PREDICATE,
            f"array[0..{last}] of var 0..2: left;",
            f"array[0..{last}] of var 0..2: right;",
            f"array[0..{last}] of var 0..2: output_difference;",
            f"array[0..{last}] of var 0..2: carry_difference;",
            f"array[0..{last}] of var {{0,4,9,19,41,100}}: costs;",
            "var int: scaled_weight;",
        )
        constraints = [
            _fixed_array("left", self.left),
            _fixed_array("right", self.right),
            _fixed_array("output_difference", self.output),
        ]
        if self.carry_difference is not None:
            constraints.append(_fixed_array("carry_difference", self.carry_difference))
        constraints.extend((
            "constraint counter_based_probabilistic_truncated_modadd(left, right, "
            "output_difference, carry_difference, costs, scaled_weight);",
            "constraint costs[" + str(last) + "] = 0;",
        ))
        return MiniZincModel(
            declarations, tuple(constraints), solve="solve minimize scaled_weight;",
            provenance=("legacy counter_based_modadd_semideterministic fixture",),
        )

    def decode_transition(self, assignment) -> ProbabilisticTruncatedModularAddTransition:
        """Project and independently check the optimized partial transition."""

        transition = ProbabilisticTruncatedModularAddTransition(
            self.left,
            self.right,
            self.output,
            _decode_truncated(assignment["carry_difference"]),
            tuple(int(value) for value in assignment["costs"]),
        )
        if transition.scaled_weight != int(assignment["scaled_weight"]):
            raise ValueError("MiniZinc returned an inconsistent scaled weight")
        if not check_probabilistic_truncated_modular_add(transition):
            raise ValueError("MiniZinc returned an invalid probabilistic truncated transition")
        return transition


class SpeckProbabilisticTruncatedCPModel:
    """Compose counter-based probabilistic truncated semantics over Speck."""

    def __init__(
        self,
        problem: PropagationProblem,
        input_pattern: TruncatedXorDifference,
        output_pattern: TruncatedXorDifference,
    ) -> None:
        from claasp_next.semantics import PROBABILISTIC_TRUNCATED_XOR

        if problem.semantics != PROBABILISTIC_TRUNCATED_XOR:
            raise ValueError("Speck model requires probabilistic-truncated XOR semantics")
        plaintext = problem.cipher.inputs.get("plaintext")
        if (
            problem.cipher.family_name != "speck" or plaintext is None
            or not isinstance(plaintext.value_type.domain, Word)
            or plaintext.value_type.domain.width != 16
        ):
            raise NotImplementedError("the reviewed slice supports Speck32/64")
        if len(input_pattern.bits) != 32 or len(output_pattern.bits) != 32:
            raise ValueError("Speck32 patterns must contain 32 bits")
        self.problem = problem
        self.cipher = problem.cipher
        self.input_pattern = input_pattern
        self.output_pattern = output_pattern
        self.width = 16

    def cp_model(self) -> MiniZincModel:
        """Compile fixed boundaries and minimize the composed scaled weight."""

        rounds = len(self.cipher.rounds)
        declarations = [_PROBABILISTIC_TRUNCATED_MODADD_PREDICATE]
        constraints = []
        for boundary in range(rounds + 1):
            declarations.extend((
                f"array[0..15] of var 0..2: x_{boundary};",
                f"array[0..15] of var 0..2: y_{boundary};",
            ))
        probabilities = []
        for round_number in range(rounds):
            declarations.extend((
                f"array[0..15] of var 0..2: carry_{round_number};",
                f"array[0..15] of var {{0,4,9,19,41,100}}: costs_{round_number};",
                f"var int: probability_{round_number};",
            ))
            probabilities.append(f"probability_{round_number}")
            alpha = _component(
                self.cipher, f"round_{round_number}_rotate_right", Rotate
            ).amount
            beta = _component(
                self.cipher, f"round_{round_number}_rotate_left", Rotate
            ).amount
            constraints.extend((
                "constraint counter_based_probabilistic_truncated_modadd("
                f"{_array_rotation(f'x_{round_number}', -alpha, self.width)}, "
                f"y_{round_number}, x_{round_number + 1}, carry_{round_number}, "
                f"costs_{round_number}, probability_{round_number});",
                f"constraint costs_{round_number}[15] = 0;",
            ))
            for index in range(self.width):
                source = (index + beta) % self.width
                constraints.append(
                    f"constraint y_{round_number + 1}[{index}] = "
                    f"truncated_xor2(y_{round_number}[{source}], "
                    f"x_{round_number + 1}[{index}]);"
                )
        constraints.extend((
            _fixed_array("x_0", TruncatedXorDifference(self.input_pattern.bits[:16])),
            _fixed_array("y_0", TruncatedXorDifference(self.input_pattern.bits[16:])),
            _fixed_array(f"x_{rounds}", TruncatedXorDifference(self.output_pattern.bits[:16])),
            _fixed_array(f"y_{rounds}", TruncatedXorDifference(self.output_pattern.bits[16:])),
        ))
        declarations.append("var int: scaled_weight;")
        constraints.append(f"constraint scaled_weight = sum([{', '.join(probabilities)}]);")
        return MiniZincModel(
            tuple(declarations), tuple(constraints), solve="solve minimize scaled_weight;",
            provenance=self.problem.provenance,
        )

    def decode_trail(self, assignment) -> ProbabilisticTruncatedTrail:
        """Decode all additions and independently check transitions and wiring."""

        transitions = []
        left = TruncatedXorDifference(self.input_pattern.bits[:16])
        right = TruncatedXorDifference(self.input_pattern.bits[16:])
        for round_number in range(len(self.cipher.rounds)):
            alpha = _component(
                self.cipher, f"round_{round_number}_rotate_right", Rotate
            ).amount
            beta = _component(
                self.cipher, f"round_{round_number}_rotate_left", Rotate
            ).amount
            output = _decode_truncated(assignment[f"x_{round_number + 1}"])
            transition = ProbabilisticTruncatedModularAddTransition(
                left.rotate_right(alpha), right, output,
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
            self.input_pattern, TruncatedXorDifference(left.bits + right.bits),
            tuple(transitions),
        )
        if trail.output_pattern != self.output_pattern:
            raise ValueError("decoded trail does not meet its output boundary")
        if trail.scaled_weight != int(assignment["scaled_weight"]):
            raise ValueError("inconsistent composed scaled weight")
        return trail


class WordwiseDifferenceCPModel:
    """Expose typed word states as a native MiniZinc enum."""

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
            declarations, tuple(constraints),
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
    """Prove that forward and backward partial patterns contradict."""

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
        constraints.append(
            f"constraint exists(i in 0..{width - 1})(contradiction[i]);"
        )
        return MiniZincModel(
            declarations, tuple(constraints),
            provenance=("forward/backward impossible propagation boundary",),
        )

    def decode_boundary(self, assignment) -> ImpossiblePropagationBoundary:
        """Decode and independently confirm the contradiction positions."""

        decoded = ImpossiblePropagationBoundary(
            _decode_truncated(assignment["forward"]),
            _decode_truncated(assignment["backward"]),
        )
        solver_positions = tuple(
            index for index, value in enumerate(assignment["contradiction"])
            if bool(value)
        )
        if decoded != self.boundary or solver_positions != decoded.contradictory_positions:
            raise ValueError("MiniZinc returned an invalid impossible boundary")
        if not decoded.is_impossible:
            raise ValueError("decoded boundary is compatible")
        return decoded


class SBoxDifferenceCPModel:
    """Exact local feasibility model for possible and impossible differences."""

    def __init__(
        self,
        problem: PropagationProblem,
        component_id: str,
        input_difference: int,
        output_difference: int,
    ) -> None:
        if problem.semantics != XOR_DIFFERENTIAL:
            raise ValueError("impossible-pair CP lowering requires XOR-differential semantics")
        component = next(
            (item for item in problem.components if item.component_id == component_id), None
        )
        if not isinstance(component, BitVectorSBox):
            raise ValueError("component_id must select a scoped bit-vector S-box")
        width = component.output_type.unit_count
        limit = 1 << width
        if not 0 <= input_difference < limit or not 0 <= output_difference < limit:
            raise ValueError("difference is outside the S-box width")
        self.problem = problem
        self.component = component
        self.input_difference = input_difference
        self.output_difference = output_difference

    def cp_model(self) -> MiniZincModel:
        """Return a table whose absence of a fixed pair proves impossibility."""

        semantics = self.problem.provider_for(self.component)
        width = self.component.output_type.unit_count
        feasible = [
            (source, target)
            for source in range(1 << width)
            for target in range(1 << width)
            if semantics.transition((source,), target).is_possible
        ]
        values = ",".join(str(item) for row in feasible for item in row)
        declarations = (
            f"array[0..{len(feasible) - 1}, 1..2] of int: transitions = "
            f"array2d(0..{len(feasible) - 1}, 1..2, [{values}]);",
            f"var 0..{(1 << width) - 1}: input_difference;",
            f"var 0..{(1 << width) - 1}: output_difference;",
        )
        constraints = (
            "constraint table([input_difference,output_difference], transitions);",
            f"constraint input_difference = {self.input_difference};",
            f"constraint output_difference = {self.output_difference};",
        )
        return MiniZincModel(
            declarations, constraints, includes=('include "table.mzn";',),
            provenance=self.problem.provenance,
        )


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


def _round_sboxes(cipher, round_number):
    prefix = f"sbox_{round_number}_"
    result = tuple(
        component for component in cipher.components
        if isinstance(component, BitVectorSBox) and component.component_id.startswith(prefix)
    )
    if len(result) != 16:
        raise ValueError(f"PRESENT round {round_number} must contain 16 state S-boxes")
    return result


def _component(cipher, component_id, expected_type):
    component = next(
        (item for item in cipher.components if item.component_id == component_id), None
    )
    if not isinstance(component, expected_type):
        raise ValueError(f"cipher is missing {component_id!r}")
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
