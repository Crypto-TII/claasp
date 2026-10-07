"""Deterministic-truncated CP component encodings."""

from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _direct_model,
)
from claasp.representations.constraints.cp.lowering import BooleanMiniZincLowerer
from claasp.representations.constraints.cp.model import MiniZincModel


class ModularAddDeterministicTruncatedCPModel:
    """Expose the recovered paired-carry modular-add relation in MiniZinc.

    EXAMPLES::

        >>> model = ModularAddDeterministicTruncatedCPModel(4)
        >>> query = model.cp_model(
        ...     left_pattern="0001", right_pattern="0001", output_pattern="???0"
        ... )
        >>> (len(query.declarations), len(query.constraints))
        (32, 71)
    """

    model_provenance = _direct_model(
        ConstraintBackend.CP,
        "ModularAddDeterministicTruncatedCPModel",
        "deterministic_truncated_xor",
        "MiniZinc translation of legacy two-bit paired-carry clauses",
        "The recovered Boolean clauses are translated exactly to MiniZinc.",
    )

    def __init__(self, width: int) -> None:
        from claasp.representations.constraints.sat.components.modular_add import (
            ModularAddDeterministicTruncatedSATModel,
        )

        self._sat_model = ModularAddDeterministicTruncatedSATModel(width)
        self.width = self._sat_model.width
        self._query: MiniZincModel | None = None

    def cp_model(self, *, left_pattern=None, right_pattern=None, output_pattern=None):
        """Return paired-carry constraints with optional fixed ternary patterns."""

        from claasp.representations.constraints.sat.model import CNFFormula

        formula = self._sat_model.cnf_formula()
        indices = {name: index for index, name in enumerate(formula.variables, 1)}
        clauses = list(formula.clauses)
        provenance = list(formula.provenance)
        for prefix, pattern in (
            ("left", left_pattern),
            ("right", right_pattern),
            ("output", output_pattern),
        ):
            if pattern is None:
                continue
            encoded = self._sat_model.encode_pattern(pattern)
            if len(encoded) != self.width:
                raise ValueError(f"patterns must contain {self.width} bits")
            for bit, pair in enumerate(encoded):
                for field, value in zip(("unknown", "value"), pair):
                    index = indices[f"{prefix}_{bit}_{field}"]
                    clauses.append(((index if value else -index),))
                    provenance.append(f"fixed_{prefix}")
        lowered = BooleanMiniZincLowerer().lower(
            CNFFormula(formula.variables, tuple(clauses), tuple(provenance))
        )
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

    def decode_transition(self, assignment):
        """Decode and independently validate one CP assignment."""

        if self._query is None:
            raise ValueError("build the CP model before decoding")
        return self._sat_model.decode_transition(assignment)


__all__ = ["ModularAddDeterministicTruncatedCPModel"]
