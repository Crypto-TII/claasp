"""Deterministic-truncated SMT component encodings."""

from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _direct_model,
)
from claasp.representations.constraints.smt.model import SMTFormula


class ModularAddDeterministicTruncatedSMTModel:
    """Expose the recovered paired-carry modular-add relation through SMT.

    The Boolean assertions are logically identical to the exhaustively checked
    SAT relation, but carry explicit SMT provenance and support fixed ternary
    operands directly.

    EXAMPLES::

        >>> model = ModularAddDeterministicTruncatedSMTModel(4)
        >>> formula = model.smt_formula(
        ...     left_pattern="0001", right_pattern="0001", output_pattern="???0"
        ... )
        >>> (len(formula.variables), formula.assertion_count)
        (32, 71)
    """

    model_provenance = _direct_model(
        ConstraintBackend.SMT,
        "ModularAddDeterministicTruncatedSMTModel",
        "deterministic_truncated_xor",
        "Boolean SMT translation of legacy two-bit paired-carry clauses",
        "The recovered clauses are translated without changing their logical semantics.",
    )

    def __init__(self, width: int) -> None:
        from claasp.representations.constraints.sat.components.modular_add import (
            ModularAddDeterministicTruncatedSATModel,
        )

        self._sat_model = ModularAddDeterministicTruncatedSATModel(width)
        self.width = self._sat_model.width
        self._formula: SMTFormula | None = None

    def smt_formula(
        self, *, left_pattern=None, right_pattern=None, output_pattern=None
    ) -> SMTFormula:
        """Return paired-carry assertions with optional fixed ternary patterns."""

        cnf = self._sat_model.cnf_formula()
        indices = {name: index for index, name in enumerate(cnf.variables, 1)}
        clauses = list(cnf.clauses)
        provenance = list(cnf.provenance)
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
        self._formula = SMTFormula(
            cnf.variables,
            tuple(clauses),
            tuple(provenance),
            (ConstraintModelApplication(self.model_provenance),),
        )
        return self._formula

    def decode_transition(self, assignment):
        """Decode and independently validate one SMT assignment."""

        from claasp.representations.constraints.sat.model import CNFFormula

        if self._formula is None:
            raise ValueError("build the SMT formula before decoding")
        if not CNFFormula(
            self._formula.variables, self._formula.assertions, self._formula.provenance
        ).is_satisfied(assignment):
            raise ValueError("invalid deterministic-truncated SMT witness")
        return self._sat_model.decode_transition(assignment)


__all__ = ["ModularAddDeterministicTruncatedSMTModel"]
