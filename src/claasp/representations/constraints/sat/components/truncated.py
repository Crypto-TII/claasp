"""SAT relations for truncated and impossible propagation boundaries."""

from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _direct_model,
)
from claasp.representations.constraints.sat.model import CNFFormula
from claasp.semantics.cryptanalysis import (
    ImpossiblePropagationBoundary,
    TruncatedBit,
    TruncatedXorDifference,
)


class ImpossibleBoundarySATModel:
    """Encode fixed-bit contradictions between two truncated boundaries.

    One indicator is true exactly when both directional bits are known and
    opposite. By default the formula requires at least one such indicator.
    Unknown trits retain the legacy redundant value bit, which is ignored by
    decoding and by the incompatibility relation.

    EXAMPLES::

        >>> model = ImpossibleBoundarySATModel(
        ...     3, forward_pattern="01?", backward_pattern="00?"
        ... )
        >>> formula = model.cnf_formula()
        >>> (formula.variable_count, formula.clause_count)
        (15, 31)
        >>> formula.variables[-3:]
        ('incompatibility_0', 'incompatibility_1', 'incompatibility_2')
    """

    model_provenance = _direct_model(
        ConstraintBackend.SAT,
        "ImpossibleBoundarySATModel",
        "impossible_xor_differential",
        "legacy six-clause fixed-bit incompatibility indicators",
        "Each indicator is equivalent to two known, opposite truncated bits.",
    )

    def __init__(
        self,
        width: int,
        *,
        forward_pattern=None,
        backward_pattern=None,
        require_incompatibility: bool = True,
    ) -> None:
        if not isinstance(width, int) or isinstance(width, bool) or width <= 0:
            raise ValueError("width must be a positive integer")
        if not isinstance(require_incompatibility, bool):
            raise TypeError("require_incompatibility must be Boolean")
        self.width = width
        self.forward_pattern = self._coerce(forward_pattern)
        self.backward_pattern = self._coerce(backward_pattern)
        self.require_incompatibility = require_incompatibility

    def _coerce(self, pattern):
        if pattern is None:
            return None
        if isinstance(pattern, str):
            pattern = TruncatedXorDifference.parse(pattern)
        if not isinstance(pattern, TruncatedXorDifference):
            raise TypeError("boundary patterns must be strings or TruncatedXorDifference values")
        if len(pattern.bits) != self.width:
            raise ValueError(f"boundary patterns must contain {self.width} bits")
        return pattern

    @staticmethod
    def _encoded(bit):
        return (1, 0) if bit is TruncatedBit.UNKNOWN else (0, int(bit.value))

    def cnf_formula(self) -> CNFFormula:
        """Return the exact legacy incompatibility clauses and boundary units."""

        boundary_variables = tuple(
            f"{direction}_{bit}_{field}"
            for direction in ("forward", "backward")
            for bit in range(self.width)
            for field in ("unknown", "value")
        )
        indicators = tuple(f"incompatibility_{bit}" for bit in range(self.width))
        variables = boundary_variables + indicators
        indices = {name: index for index, name in enumerate(variables, 1)}
        clauses = []
        provenance = []

        def add(literals, label):
            clauses.append(tuple(literals))
            provenance.append(label)

        for bit, indicator in enumerate(indicators):
            forward_unknown = indices[f"forward_{bit}_unknown"]
            forward_value = indices[f"forward_{bit}_value"]
            backward_unknown = indices[f"backward_{bit}_unknown"]
            backward_value = indices[f"backward_{bit}_value"]
            incompatible = indices[indicator]
            for clause in (
                (-forward_unknown, -incompatible),
                (-backward_unknown, -incompatible),
                (forward_value, backward_value, -incompatible),
                (-forward_value, -backward_value, -incompatible),
                (
                    forward_unknown,
                    forward_value,
                    backward_unknown,
                    incompatible,
                    -backward_value,
                ),
                (
                    forward_unknown,
                    backward_unknown,
                    backward_value,
                    incompatible,
                    -forward_value,
                ),
            ):
                add(clause, "truncated_incompatibility_indicator")
        if self.require_incompatibility:
            add((indices[name] for name in indicators), "truncated_incompatibility_exists")

        for direction, pattern in (
            ("forward", self.forward_pattern),
            ("backward", self.backward_pattern),
        ):
            if pattern is None:
                continue
            for bit, trit in enumerate(pattern.bits):
                for field, value in zip(("unknown", "value"), self._encoded(trit)):
                    name = f"{direction}_{bit}_{field}"
                    add(((indices[name] if value else -indices[name]),), f"fixed_{direction}")

        return CNFFormula(
            variables,
            tuple(clauses),
            tuple(provenance),
            (ConstraintModelApplication(self.model_provenance),),
        )

    def decode_boundary(self, assignment) -> ImpossiblePropagationBoundary:
        """Decode and independently validate all incompatibility indicators."""

        formula = self.cnf_formula()
        if not formula.is_satisfied(assignment):
            raise ValueError("invalid impossible-boundary SAT witness")

        def pattern(direction):
            return TruncatedXorDifference(
                tuple(
                    TruncatedBit.UNKNOWN
                    if assignment[f"{direction}_{bit}_unknown"]
                    else TruncatedBit.ONE
                    if assignment[f"{direction}_{bit}_value"]
                    else TruncatedBit.ZERO
                    for bit in range(self.width)
                )
            )

        boundary = ImpossiblePropagationBoundary(pattern("forward"), pattern("backward"))
        encoded_positions = tuple(
            bit for bit in range(self.width) if assignment[f"incompatibility_{bit}"]
        )
        if encoded_positions != boundary.contradictory_positions:
            raise ValueError("SAT indicators disagree with the typed impossible boundary")
        if self.require_incompatibility and not boundary.is_impossible:
            raise ValueError("decoded boundary is compatible")
        if self.forward_pattern is not None and boundary.forward != self.forward_pattern:
            raise ValueError("SAT witness changed the fixed forward boundary")
        if self.backward_pattern is not None and boundary.backward != self.backward_pattern:
            raise ValueError("SAT witness changed the fixed backward boundary")
        return boundary


__all__ = ["ImpossibleBoundarySATModel"]
