"""Native CP lowering of shared cryptanalytic trail semantics."""

from claasp_next.components import BitVectorSBox, Permutation
from claasp_next.semantics import XOR_DIFFERENTIAL, XOR_LINEAR
from claasp_next.semantics.cryptanalysis import (
    PropagationProblem, Trail, TrailKind, TrailStep, XorDifference, XorMask,
    TruncatedXorDifference, propagate_two_word_speck_round,
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
