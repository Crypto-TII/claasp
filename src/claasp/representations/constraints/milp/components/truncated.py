"""MILP encodings for local truncated-difference relations."""

import json
from dataclasses import dataclass
from functools import cache
from importlib.resources import files
from itertools import product

from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _unaudited_model,
)
from claasp.representations.constraints.milp.components.relations import (
    FiniteBinaryRelationMILPModel,
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
from claasp.representations.constraints.sat.model import CNFFormula
from claasp.semantics.cryptanalysis import (
    WordwiseDifferenceKind,
    WordwiseXorDifference,
    propagate_dense_wordwise_activity,
)


def _wordwise_values(width):
    return (
        WordwiseXorDifference(width, WordwiseDifferenceKind.ZERO),
        *(WordwiseXorDifference.known(width, value) for value in range(1, 1 << width)),
        WordwiseXorDifference(width, WordwiseDifferenceKind.NONZERO),
        WordwiseXorDifference(width, WordwiseDifferenceKind.UNKNOWN),
    )


def _encoded_word(value, *, include_value):
    encoded = (value.kind.value >> 1, value.kind.value & 1)
    if not include_value:
        return encoded
    concrete = value.value if value.kind is WordwiseDifferenceKind.KNOWN else 0
    return (*encoded, *(concrete >> bit & 1 for bit in reversed(range(value.width))))


def _kind_value(width, kind):
    return (
        WordwiseXorDifference.known(width, 1)
        if kind is WordwiseDifferenceKind.KNOWN
        else WordwiseXorDifference(width, kind)
    )


def _word_columns(prefix, width, *, include_value):
    columns = (f"{prefix}_kind_msb", f"{prefix}_kind_lsb")
    return columns + tuple(f"{prefix}_value_{bit}" for bit in range(width)) if include_value else columns


def _decode_word(assignment, prefix, width, *, include_value):
    kind = WordwiseDifferenceKind(
        2 * round(assignment[f"{prefix}_kind_msb"]) + round(assignment[f"{prefix}_kind_lsb"])
    )
    if kind is WordwiseDifferenceKind.KNOWN:
        if not include_value:
            return WordwiseXorDifference.known(width, 1)
        value = sum(
            round(assignment[f"{prefix}_value_{bit}"]) << (width - bit - 1)
            for bit in range(width)
        )
        return WordwiseXorDifference.known(width, value)
    return WordwiseXorDifference(width, kind)


def _fix_word(prefix, value, *, include_value):
    return tuple(
        LinearConstraint(
            LinearExpression.from_terms({name: 1}),
            ConstraintSense.EQUAL,
            bit,
            f"fixed_{name}",
        )
        for name, bit in zip(
            _word_columns(prefix, value.width, include_value=include_value),
            _encoded_word(value, include_value=include_value),
        )
    )


@cache
def load_bundled_wordwise_espresso(name="wordwise_4bit_xor2_mds4x4"):
    """Load a validated offline-generated wordwise Espresso bundle.

    EXAMPLES::

        >>> bundle = load_bundled_wordwise_espresso()
        >>> (bundle["word_width"], bundle["xor"]["row_count"], bundle["mds"]["row_count"])
        (4, 324, 256)
    """

    if not isinstance(name, str) or not name or not name.replace("_", "a").isalnum():
        raise ValueError("name must contain only letters, digits, and underscores")
    resource = files("claasp.representations.constraints.milp").joinpath(
        "data", f"{name}_inequalities.json"
    )
    try:
        payload = json.loads(resource.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ValueError(f"no bundled wordwise system named {name!r}") from error
    if payload.get("schema_version") != 1 or set(payload) != {
        "schema_version", "legacy_source", "generator", "word_width", "xor", "mds"
    }:
        raise ValueError("unsupported wordwise Espresso bundle")
    return payload


class WordwiseXorMILPModel:
    """Portable exact one-hot relation for wordwise XOR.

    EXAMPLES::

        >>> known = WordwiseXorDifference.known(4, 5)
        >>> relation = WordwiseXorMILPModel(4)
        >>> model = relation.milp_model(inputs=(known, known))
        >>> witness = relation.relation.witness(relation.rows[5 * 18 + 5])
        >>> model.is_feasible(witness)
        True
    """

    model_provenance = _unaudited_model(
        ConstraintBackend.MILP,
        "WordwiseXorMILPModel",
        "wordwise_deterministic_truncated_xor",
        "portable exhaustive wordwise XOR relation",
        "The relation directly evaluates the typed four-state wordwise XOR semantics.",
    )

    def __init__(self, word_width: int, operands: int = 2) -> None:
        if not isinstance(word_width, int) or isinstance(word_width, bool) or word_width < 1:
            raise ValueError("word_width must be a positive integer")
        if not isinstance(operands, int) or isinstance(operands, bool) or operands < 2:
            raise ValueError("operands must be an integer of at least two")
        self.word_width, self.operands = word_width, operands
        self.columns = tuple(
            name
            for operand in range(operands)
            for name in _word_columns(f"input_{operand}", word_width, include_value=True)
        ) + _word_columns("output", word_width, include_value=True)
        values = _wordwise_values(word_width)
        self.rows = tuple(
            tuple(bit for value in inputs for bit in _encoded_word(value, include_value=True))
            + _encoded_word(WordwiseXorDifference.xor_many(inputs), include_value=True)
            for inputs in product(values, repeat=operands)
        )
        self.relation = FiniteBinaryRelationMILPModel(self.columns, self.rows)
        self._model: MILPModel | None = None

    def _fixed(self, inputs, output):
        constraints = []
        if inputs is not None:
            if len(inputs) != self.operands:
                raise ValueError("fixed inputs must match the operand count")
            for position, value in enumerate(inputs):
                constraints.extend(_fix_word(f"input_{position}", value, include_value=True))
        if output is not None:
            constraints.extend(_fix_word("output", output, include_value=True))
        return tuple(constraints)

    def milp_model(self, *, inputs=None, output=None):
        """Return the exact row formulation with optional typed boundaries."""

        base = self.relation.milp_model()
        self._model = MILPModel(
            base.variables,
            (*base.constraints, *self._fixed(inputs, output)),
            constraint_models=(ConstraintModelApplication(self.model_provenance),),
        )
        return self._model

    def decode_transition(self, assignment):
        """Decode and independently re-evaluate a feasible wordwise XOR."""

        if self._model is None or not self._model.is_feasible(assignment):
            raise ValueError("invalid wordwise XOR witness")
        inputs = tuple(
            _decode_word(assignment, f"input_{position}", self.word_width, include_value=True)
            for position in range(self.operands)
        )
        output = _decode_word(assignment, "output", self.word_width, include_value=True)
        if WordwiseXorDifference.xor_many(inputs) != output:
            raise ValueError("wordwise XOR output disagrees with typed semantics")
        return inputs, output


class WordwiseXorEspressoMILPModel(WordwiseXorMILPModel):
    """Recovered compact Espresso wordwise-XOR relation.

    EXAMPLES::

        >>> relation = WordwiseXorEspressoMILPModel()
        >>> model = relation.milp_model()
        >>> (len(model.variables), len(model.constraints))
        (18, 51)
    """

    model_provenance = _unaudited_model(
        ConstraintBackend.MILP,
        "WordwiseXorEspressoMILPModel",
        "wordwise_deterministic_truncated_xor",
        "legacy Espresso product-of-sums wordwise XOR formulation",
        "The legacy relation is recovered exactly; literature correspondence remains unaudited.",
    )

    def __init__(self, bundle_name="wordwise_4bit_xor2_mds4x4") -> None:
        self.bundle = load_bundled_wordwise_espresso(bundle_name)
        super().__init__(self.bundle["word_width"], self.bundle["xor"]["operands"])

    def milp_model(self, *, inputs=None, output=None):
        """Return the compact generated formulation without runtime Espresso."""

        indices = {name: position for position, name in enumerate(self.columns, 1)}
        clauses = tuple(
            tuple(
                indices[name] if symbol == "0" else -indices[name]
                for name, symbol in zip(self.columns, pattern)
                if symbol != "-"
            )
            for pattern in self.bundle["xor"]["clauses"]
        )
        from claasp.representations.constraints.milp.lowering import cnf_to_milp

        translated = cnf_to_milp(
            CNFFormula(self.columns, clauses, ("wordwise_xor_espresso",) * len(clauses))
        )
        self._model = MILPModel(
            translated.variables,
            (*translated.constraints, *self._fixed(inputs, output)),
            constraint_models=(ConstraintModelApplication(self.model_provenance),),
        )
        return self._model


class WordwiseTruncatedMDSMILPModel:
    """Portable exact row model for the recovered dense-MDS abstraction.

    EXAMPLES::

        >>> relation = WordwiseTruncatedMDSMILPModel(4, (4, 4))
        >>> model = relation.milp_model()
        >>> (len(relation.rows), len(model.variables))
        (256, 272)
    """

    model_provenance = _unaudited_model(
        ConstraintBackend.MILP,
        "WordwiseTruncatedMDSMILPModel",
        "wordwise_deterministic_truncated_xor",
        "portable exhaustive dense-MDS four-state abstraction",
        "The relation directly evaluates the reviewed dense wordwise activity semantics.",
    )

    def __init__(self, word_width: int, dimensions=(4, 4)) -> None:
        rows, columns = dimensions
        if word_width < 1 or rows < 1 or columns < 1:
            raise ValueError("word width and matrix dimensions must be positive")
        self.word_width, self.dimensions = word_width, (rows, columns)
        self.columns = tuple(
            name
            for side, count in (("input", columns), ("output", rows))
            for position in range(count)
            for name in _word_columns(f"{side}_{position}", word_width, include_value=False)
        )
        kinds = tuple(WordwiseDifferenceKind)
        self.rows = tuple(
            tuple(
                bit
                for kind in input_kinds
                for bit in _encoded_word(_kind_value(word_width, kind), include_value=False)
            )
            + tuple(
                bit
                for value in propagate_dense_wordwise_activity(
                    tuple(_kind_value(word_width, kind) for kind in input_kinds), rows
                )
                for bit in _encoded_word(value, include_value=False)
            )
            for input_kinds in product(kinds, repeat=columns)
        )
        self.relation = FiniteBinaryRelationMILPModel(self.columns, self.rows)
        self._model: MILPModel | None = None

    def _fixed(self, inputs, outputs):
        constraints = []
        for side, values, count in (("input", inputs, self.dimensions[1]), ("output", outputs, self.dimensions[0])):
            if values is None:
                continue
            if len(values) != count:
                raise ValueError(f"fixed {side}s must match the matrix dimensions")
            for position, value in enumerate(values):
                constraints.extend(_fix_word(f"{side}_{position}", value, include_value=False))
        return tuple(constraints)

    def milp_model(self, *, inputs=None, outputs=None):
        """Return the exact row formulation with optional typed boundaries."""

        base = self.relation.milp_model()
        self._model = MILPModel(
            base.variables,
            (*base.constraints, *self._fixed(inputs, outputs)),
            constraint_models=(ConstraintModelApplication(self.model_provenance),),
        )
        return self._model

    def decode_transition(self, assignment):
        """Decode and independently re-evaluate a feasible dense-MDS abstraction."""

        if self._model is None or not self._model.is_feasible(assignment):
            raise ValueError("invalid wordwise MDS witness")
        inputs = tuple(
            _decode_word(assignment, f"input_{position}", self.word_width, include_value=False)
            for position in range(self.dimensions[1])
        )
        outputs = tuple(
            _decode_word(assignment, f"output_{position}", self.word_width, include_value=False)
            for position in range(self.dimensions[0])
        )
        if propagate_dense_wordwise_activity(inputs, self.dimensions[0]) != outputs:
            raise ValueError("wordwise MDS output disagrees with typed semantics")
        return inputs, outputs


class WordwiseTruncatedMDSEspressoMILPModel(WordwiseTruncatedMDSMILPModel):
    """Recovered compact Espresso dense-MDS abstraction.

    EXAMPLES::

        >>> relation = WordwiseTruncatedMDSEspressoMILPModel()
        >>> model = relation.milp_model()
        >>> (len(model.variables), len(model.constraints))
        (16, 52)
    """

    model_provenance = _unaudited_model(
        ConstraintBackend.MILP,
        "WordwiseTruncatedMDSEspressoMILPModel",
        "wordwise_deterministic_truncated_xor",
        "legacy Espresso product-of-sums truncated-MDS formulation",
        "The legacy relation is recovered exactly; literature correspondence remains unaudited.",
    )

    def __init__(self, bundle_name="wordwise_4bit_xor2_mds4x4") -> None:
        self.bundle = load_bundled_wordwise_espresso(bundle_name)
        super().__init__(self.bundle["word_width"], tuple(self.bundle["mds"]["dimensions"]))

    def milp_model(self, *, inputs=None, outputs=None):
        """Return the compact generated formulation without runtime Espresso."""

        indices = {name: position for position, name in enumerate(self.columns, 1)}
        clauses = tuple(
            tuple(
                indices[name] if symbol == "0" else -indices[name]
                for name, symbol in zip(self.columns, pattern)
                if symbol != "-"
            )
            for pattern in self.bundle["mds"]["clauses"]
        )
        from claasp.representations.constraints.milp.lowering import cnf_to_milp

        translated = cnf_to_milp(
            CNFFormula(self.columns, clauses, ("wordwise_mds_espresso",) * len(clauses))
        )
        self._model = MILPModel(
            translated.variables,
            (*translated.constraints, *self._fixed(inputs, outputs)),
            constraint_models=(ConstraintModelApplication(self.model_provenance),),
        )
        return self._model


@dataclass(frozen=True, slots=True)
class WordwiseImpossibleBoundaryResult:
    """Decoded four-state word boundaries and selected contradictions.

    EXAMPLES::

        >>> result = WordwiseImpossibleBoundaryResult((0, 2), (2, 0), (1,))
        >>> result.contradictory_positions
        (1,)
    """

    forward: tuple[int, ...]
    backward: tuple[int, ...]
    contradictory_positions: tuple[int, ...]


class WordwiseImpossibleBoundaryMILPModel:
    """Select legacy four-state wordwise incompatibilities exactly.

    The recovered relation recognizes only ``(0,1)``, ``(0,2)``, ``(1,0)``,
    and ``(2,0)`` as contradictory. State 3 is unrestricted/unknown and does
    not prove impossibility. ``?`` leaves a boundary word solver-selected.

    EXAMPLES::

        >>> model = WordwiseImpossibleBoundaryMILPModel("20", "00")
        >>> formulation = model.milp_model()
        >>> (len(formulation.variables), formulation.constraints[-1].name)
        (26, 'wordwise_contradiction_exists')
    """

    model_provenance = _unaudited_model(
        ConstraintBackend.MILP,
        "WordwiseImpossibleBoundaryMILPModel",
        "wordwise_impossible_xor_differential",
        "legacy four-state middle incompatibility selector",
        "The local relation is exact; complete graph composition is exposed by the trail model.",
    )

    _INCOMPATIBLE = ((0, 1), (0, 2), (1, 0), (2, 0))

    def __init__(self, forward_pattern: str, backward_pattern: str, *, exactly_one=True):
        if (
            not isinstance(forward_pattern, str)
            or not isinstance(backward_pattern, str)
            or not forward_pattern
            or len(forward_pattern) != len(backward_pattern)
            or set(forward_pattern + backward_pattern) - set("0123?")
        ):
            raise ValueError("wordwise patterns must be equal-length strings over 0,1,2,3,?")
        if not isinstance(exactly_one, bool):
            raise TypeError("exactly_one must be a boolean")
        self.forward_pattern = forward_pattern
        self.backward_pattern = backward_pattern
        self.exactly_one = exactly_one
        self._model: MILPModel | None = None

    @staticmethod
    def _state_name(side, position, state):
        return f"{side}_{position}_state_{state}"

    def milp_model(self) -> MILPModel:
        """Return the complete one-hot boundary and incompatibility model."""

        variables = []
        constraints = []
        for position in range(len(self.forward_pattern)):
            for side in ("forward", "backward"):
                names = tuple(self._state_name(side, position, state) for state in range(4))
                variables.extend(LinearVariable(name, VariableKind.BINARY) for name in names)
                constraints.append(
                    LinearConstraint(
                        LinearExpression.from_terms(dict.fromkeys(names, 1)),
                        ConstraintSense.EQUAL,
                        1,
                        f"{side}_{position}_one_hot",
                    )
                )
            indicator = f"inconsistent_{position}"
            variables.append(LinearVariable(indicator, VariableKind.BINARY))
            pair_names = []
            for forward_state, backward_state in self._INCOMPATIBLE:
                pair = f"pair_{position}_{forward_state}_{backward_state}"
                pair_names.append(pair)
                variables.append(LinearVariable(pair, VariableKind.BINARY))
                forward = self._state_name("forward", position, forward_state)
                backward = self._state_name("backward", position, backward_state)
                constraints.extend(
                    (
                        LinearConstraint(
                            LinearExpression.from_terms({pair: 1, forward: -1}),
                            ConstraintSense.LESS_EQUAL,
                            0,
                            f"{pair}_forward",
                        ),
                        LinearConstraint(
                            LinearExpression.from_terms({pair: 1, backward: -1}),
                            ConstraintSense.LESS_EQUAL,
                            0,
                            f"{pair}_backward",
                        ),
                    )
                )
            constraints.append(
                LinearConstraint(
                    LinearExpression.from_terms(
                        {indicator: 1, **{name: -1 for name in pair_names}}
                    ),
                    ConstraintSense.EQUAL,
                    0,
                    f"inconsistent_{position}_definition",
                )
            )
        for side, pattern in (
            ("forward", self.forward_pattern),
            ("backward", self.backward_pattern),
        ):
            for position, symbol in enumerate(pattern):
                if symbol != "?":
                    constraints.append(
                        LinearConstraint(
                            LinearExpression.from_terms(
                                {self._state_name(side, position, int(symbol)): 1}
                            ),
                            ConstraintSense.EQUAL,
                            1,
                            f"fix_{side}_{position}",
                        )
                    )
        indicators = {
            f"inconsistent_{position}": 1 for position in range(len(self.forward_pattern))
        }
        constraints.append(
            LinearConstraint(
                LinearExpression.from_terms(indicators),
                ConstraintSense.EQUAL if self.exactly_one else ConstraintSense.GREATER_EQUAL,
                1,
                "wordwise_contradiction_exists",
            )
        )
        unknowns = {
            self._state_name("forward", position, WordwiseDifferenceKind.UNKNOWN.value): 1
            for position in range(len(self.forward_pattern))
        }
        self._model = MILPModel(
            tuple(variables),
            tuple(constraints),
            LinearExpression.from_terms(unknowns),
            ObjectiveSense.MINIMIZE,
            (ConstraintModelApplication(self.model_provenance),),
        )
        return self._model

    def decode_boundary(self, assignment) -> WordwiseImpossibleBoundaryResult:
        """Decode a feasible assignment and independently verify each selector."""

        if self._model is None:
            raise ValueError("build the MILP model before decoding")
        values = {name: int(round(value)) for name, value in assignment.items()}
        if not self._model.is_feasible(values):
            raise ValueError("invalid wordwise impossible-boundary assignment")

        def states(side):
            return tuple(
                next(state for state in range(4) if values[self._state_name(side, position, state)])
                for position in range(len(self.forward_pattern))
            )

        forward, backward = states("forward"), states("backward")
        selected = tuple(
            position for position in range(len(forward)) if values[f"inconsistent_{position}"]
        )
        if any(
            (forward[position], backward[position]) not in self._INCOMPATIBLE
            for position in selected
        ):
            raise ValueError("wordwise incompatibility selector chose a compatible state pair")
        return WordwiseImpossibleBoundaryResult(forward, backward, selected)


def wordwise_pattern(differences) -> str:
    """Encode typed wordwise differences as legacy four-state digits.

    EXAMPLES::

        >>> zero = WordwiseXorDifference(4, WordwiseDifferenceKind.ZERO)
        >>> nonzero = WordwiseXorDifference(4, WordwiseDifferenceKind.NONZERO)
        >>> wordwise_pattern((zero, nonzero))
        '02'
    """

    values = tuple(differences)
    if not values or any(not isinstance(item, WordwiseXorDifference) for item in values):
        raise TypeError("differences must contain typed wordwise XOR differences")
    return "".join(str(item.kind.value) for item in values)
