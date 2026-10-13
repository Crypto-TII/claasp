"""Exact probability-bearing and truncated S-box component relations for MILP."""

import json
from functools import cache
from importlib.resources import files
from itertools import product
from math import log2
from typing import ClassVar

from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _direct_model,
)
from claasp.representations.constraints.milp.components.relations import (
    FiniteBinaryRelationMILPModel,
)
from claasp.representations.constraints.milp.model import (
    ConstraintSense,
    LinearConstraint,
    LinearExpression,
    MILPModel,
)
from claasp.representations.constraints.sat.model import CNFFormula
from claasp.semantics.cryptanalysis import (
    SBoxTransitionSemantics,
    TrailKind,
    TruncatedBit,
    TruncatedXorDifference,
)


class SBoxTransitionMILPModel:
    """One selector per supported DDT or signed-LAT transition.

    Solver objective coefficients approximate logarithmic weights, while
    decoded transitions retain exact integer counts and correlation signs.


    EXAMPLES::

        >>> relation = SBoxTransitionMILPModel((0, 1), TrailKind.XOR_DIFFERENTIAL)
        >>> model = relation.milp_model(input_pattern=1, output_pattern=1)
        >>> tuple(variable.name for variable in model.variables[:2])
        ('input_0', 'output_0')
        >>> len(relation.relation.rows)
        2
    """

    model_provenance_by_kind: ClassVar = {
        TrailKind.XOR_DIFFERENTIAL: _direct_model(
            ConstraintBackend.MILP,
            "SBoxXorDifferentialMILPModel",
            "xor_differential",
            "one-hot exhaustive DDT row selection",
            "The finite relation is enumerated directly from the supplied S-box table.",
        ),
        TrailKind.XOR_LINEAR: _direct_model(
            ConstraintBackend.MILP,
            "SBoxXorLinearMILPModel",
            "xor_linear",
            "one-hot exhaustive LAT row selection",
            "The finite relation is enumerated directly from the supplied S-box table.",
        ),
    }

    def __init__(self, table, kind, output_width=None):
        if kind not in (TrailKind.XOR_DIFFERENTIAL, TrailKind.XOR_LINEAR):
            raise ValueError("S-box MILP requires differential or linear semantics")
        self.semantics = SBoxTransitionSemantics(table, output_width)
        self.kind = kind
        self.model_provenance = self.model_provenance_by_kind[kind]
        self.columns = tuple(f"input_{bit}" for bit in range(self.semantics.width)) + tuple(
            f"output_{bit}" for bit in range(self.semantics.output_width)
        )
        rows, costs = [], []
        counts = (
            self.semantics.difference_distribution_table()
            if kind is TrailKind.XOR_DIFFERENTIAL
            else self.semantics.walsh_correlation_table()
        )
        for source in range(len(self.semantics.table)):
            for target in range(self.semantics.output_size):
                count = counts[source][target]
                if count:
                    rows.append(
                        tuple((source >> bit) & 1 for bit in reversed(range(self.semantics.width)))
                        + tuple(
                            (target >> bit) & 1
                            for bit in reversed(range(self.semantics.output_width))
                        )
                    )
                    costs.append(log2(len(self.semantics.table) / abs(count)))
        self.relation = FiniteBinaryRelationMILPModel(self.columns, rows, row_costs=costs)
        self._model = None

    def _transition(self, source, target):
        return (
            self.semantics.xor_differential(source, target)
            if self.kind is TrailKind.XOR_DIFFERENTIAL
            else self.semantics.xor_linear(source, target)
        )

    def milp_model(self, *, input_pattern=None, output_pattern=None):
        """Compute the milp model for this public typed contract."""

        model = self.relation.milp_model()
        constraints = list(model.constraints)
        for prefix, value in (("input", input_pattern), ("output", output_pattern)):
            if value is not None:
                width = self.semantics.width if prefix == "input" else self.semantics.output_width
                if prefix == "input":
                    self.semantics._validate_input_pattern(value)
                else:
                    self.semantics._validate_output_pattern(value)
                for bit in range(width):
                    constraints.append(
                        LinearConstraint(
                            LinearExpression.from_terms({f"{prefix}_{bit}": 1}),
                            ConstraintSense.EQUAL,
                            (value >> (width - 1 - bit)) & 1,
                            f"fixed_{prefix}_{bit}",
                        )
                    )
        self._model = MILPModel(
            model.variables,
            tuple(constraints),
            model.objective,
            constraint_models=(ConstraintModelApplication(self.model_provenance),),
        )
        return self._model

    def decode_transition(self, assignment):
        """Compute the decode transition for this public typed contract."""

        if self._model is None:
            raise ValueError("build the MILP model before decoding")
        if not self._model.is_feasible(assignment):
            raise ValueError("invalid S-box MILP witness")
        values = []
        for prefix in ("input", "output"):
            value = 0
            width = self.semantics.width if prefix == "input" else self.semantics.output_width
            for bit in range(width):
                value = (value << 1) | round(assignment[f"{prefix}_{bit}"])
            values.append(value)
        transition = self._transition(*values)
        if (
            not transition.is_possible
            or abs(self._model.objective_value(assignment) - transition.weight) > 1e-7
        ):
            raise ValueError("S-box MILP objective disagrees with exact transition")
        return transition


class SBoxXorDifferentialMILPModel(SBoxTransitionMILPModel):
    """Encode one exact S-box XOR-differential relation as MILP.

    EXAMPLES::

        >>> relation = SBoxXorDifferentialMILPModel((0, 1))
        >>> relation.kind is TrailKind.XOR_DIFFERENTIAL
        True
        >>> len(relation.relation.rows)
        2
    """

    model_provenance = SBoxTransitionMILPModel.model_provenance_by_kind[TrailKind.XOR_DIFFERENTIAL]

    def __init__(self, table) -> None:
        super().__init__(table, TrailKind.XOR_DIFFERENTIAL)
        self.model_provenance = type(self).model_provenance


class SBoxXorLinearMILPModel(SBoxTransitionMILPModel):
    """Encode one exact S-box XOR-linear relation as MILP.

    EXAMPLES::

        >>> relation = SBoxXorLinearMILPModel((0, 1))
        >>> relation.kind is TrailKind.XOR_LINEAR
        True
        >>> len(relation.relation.rows)
        2
    """

    model_provenance = SBoxTransitionMILPModel.model_provenance_by_kind[TrailKind.XOR_LINEAR]

    def __init__(self, table) -> None:
        super().__init__(table, TrailKind.XOR_LINEAR)
        self.model_provenance = type(self).model_provenance


def _truncated_rows(table):
    semantics = SBoxTransitionSemantics(table)
    symbols = (TruncatedBit.ZERO, TruncatedBit.ONE, TruncatedBit.UNKNOWN)
    rows = []
    for inputs in product(symbols, repeat=semantics.width):
        source = TruncatedXorDifference(inputs)
        output = semantics.truncated_xor_differential(source)
        rows.append(
            tuple(
                bit
                for value in (*source.bits, *output.bits)
                for bit in (value.encoded >> 1, value.encoded & 1)
            )
        )
    return tuple(rows)


class SBoxUndisturbedBitsMILPModel:
    """Portable one-hot baseline for exact undisturbed-bit propagation.

    EXAMPLES::

        >>> from claasp.primitives.block_ciphers.present import PRESENT_SBOX
        >>> relation = SBoxUndisturbedBitsMILPModel(PRESENT_SBOX)
        >>> model = relation.milp_model(input_pattern="0001")
        >>> (len(model.variables), len(model.constraints))
        (97, 25)
    """

    model_provenance = _direct_model(
        ConstraintBackend.MILP,
        "SBoxUndisturbedBitsMILPModel",
        "bitwise_deterministic_truncated_xor",
        "one-hot exhaustive undisturbed-bit relation",
        "The relation is derived directly from every compatible concrete S-box derivative.",
    )

    def __init__(self, table) -> None:
        self.semantics = SBoxTransitionSemantics(table)
        self.columns = tuple(
            f"{side}_{position}_{field}"
            for side in ("input", "output")
            for position in range(self.semantics.width)
            for field in ("unknown", "value")
        )
        self.relation = FiniteBinaryRelationMILPModel(self.columns, _truncated_rows(table))
        self._model: MILPModel | None = None

    def _coerce(self, pattern):
        if isinstance(pattern, str):
            pattern = TruncatedXorDifference.parse(pattern)
        if (
            not isinstance(pattern, TruncatedXorDifference)
            or len(pattern.bits) != self.semantics.width
        ):
            raise ValueError("truncated pattern must match the S-box width")
        return pattern

    def _fixed_constraints(self, input_pattern, output_pattern):
        constraints = []
        for side, pattern in (("input", input_pattern), ("output", output_pattern)):
            if pattern is None:
                continue
            pattern = self._coerce(pattern)
            for position, value in enumerate(pattern.bits):
                for field, bit in zip(("unknown", "value"), divmod(value.encoded, 2)):
                    constraints.append(
                        LinearConstraint(
                            LinearExpression.from_terms({f"{side}_{position}_{field}": 1}),
                            ConstraintSense.EQUAL,
                            bit,
                            f"fixed_{side}_{position}_{field}",
                        )
                    )
        return constraints

    def milp_model(self, *, input_pattern=None, output_pattern=None):
        """Return the exact one-hot formulation with optional typed boundaries."""

        base = self.relation.milp_model()
        self._model = MILPModel(
            base.variables,
            (*base.constraints, *self._fixed_constraints(input_pattern, output_pattern)),
            constraint_models=(ConstraintModelApplication(self.model_provenance),),
        )
        return self._model

    def decode_transition(self, assignment):
        """Decode and independently recompute the strongest output pattern."""

        if self._model is None or not self._model.is_feasible(assignment):
            raise ValueError("invalid undisturbed-bit S-box witness")
        patterns = []
        for side in ("input", "output"):
            bits = []
            for position in range(self.semantics.width):
                encoded = 2 * round(assignment[f"{side}_{position}_unknown"]) + round(
                    assignment[f"{side}_{position}_value"]
                )
                if encoded == 3:
                    raise ValueError("invalid truncated-bit encoding")
                bits.append(TruncatedBit.UNKNOWN if encoded == 2 else TruncatedBit(str(encoded)))
            patterns.append(TruncatedXorDifference(tuple(bits)))
        if self.semantics.truncated_xor_differential(patterns[0]) != patterns[1]:
            raise ValueError("undisturbed-bit output disagrees with exact DDT join")
        return tuple(patterns)


@cache
def load_bundled_undisturbed_sbox_espresso(name: str):
    """Load and validate one offline-generated Espresso clause bundle.

    EXAMPLES::

        >>> payload = load_bundled_undisturbed_sbox_espresso("present")
        >>> (payload["name"], len(payload["systems"]))
        ('present', 8)
    """

    if not isinstance(name, str) or not name or not name.replace("_", "a").isalnum():
        raise ValueError("name must contain only letters, digits, and underscores")
    resource = files("claasp.representations.constraints.milp").joinpath(
        "data", f"{name}_sbox_undisturbed_inequalities.json"
    )
    try:
        payload = json.loads(resource.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ValueError(f"no bundled undisturbed-bit system named {name!r}") from error
    if payload.get("schema_version") != 1 or payload.get("name") != name:
        raise ValueError("unsupported undisturbed-bit bundle")
    semantics = SBoxTransitionSemantics(tuple(payload["table"]))
    expected = {(position, bit) for position in range(semantics.width) for bit in range(2)}
    observed = {(item["output_position"], item["encoding_bit"]) for item in payload["systems"]}
    if observed != expected:
        raise ValueError("undisturbed-bit bundle does not cover every output encoding bit")
    return payload


class SBoxUndisturbedBitsEspressoMILPModel(SBoxUndisturbedBitsMILPModel):
    """Recovered compact Espresso formulation for undisturbed S-box bits.

    EXAMPLES::

        >>> from claasp.primitives.block_ciphers.present import PRESENT_SBOX
        >>> relation = SBoxUndisturbedBitsEspressoMILPModel(PRESENT_SBOX, "present")
        >>> model = relation.milp_model(input_pattern="0001")
        >>> (len(model.variables), len(model.constraints))
        (16, 87)
    """

    model_provenance = _direct_model(
        ConstraintBackend.MILP,
        "SBoxUndisturbedBitsEspressoMILPModel",
        "bitwise_deterministic_truncated_xor",
        "legacy per-output-bit Espresso product-of-sums formulation",
        "Espresso only compresses Boolean projections of the directly enumerated finite relation.",
    )

    def __init__(self, table, bundle_name: str) -> None:
        super().__init__(table)
        self.bundle = load_bundled_undisturbed_sbox_espresso(bundle_name)
        if tuple(self.bundle["table"]) != self.semantics.table:
            raise ValueError("Espresso bundle table does not match the supplied S-box")

    def milp_model(self, *, input_pattern=None, output_pattern=None):
        """Return the compact generated formulation without runtime Espresso."""

        variables = self.columns
        indices = {name: position for position, name in enumerate(variables, 1)}
        clauses = []
        provenance = []
        input_names = tuple(name for name in variables if name.startswith("input_"))
        for system in self.bundle["systems"]:
            target = (
                f"output_{system['output_position']}_{('unknown', 'value')[system['encoding_bit']]}"
            )
            names = (*input_names, target)
            for pattern in system["clauses"]:
                clause = tuple(
                    indices[name] if symbol == "0" else -indices[name]
                    for name, symbol in zip(names, pattern)
                    if symbol != "-"
                )
                clauses.append(clause)
                provenance.append("undisturbed_sbox_espresso")
        formula = CNFFormula(tuple(variables), tuple(clauses), tuple(provenance))
        from claasp.representations.constraints.milp.lowering import cnf_to_milp

        translated = cnf_to_milp(formula)
        self._model = MILPModel(
            translated.variables,
            (*translated.constraints, *self._fixed_constraints(input_pattern, output_pattern)),
            constraint_models=(ConstraintModelApplication(self.model_provenance),),
        )
        return self._model
