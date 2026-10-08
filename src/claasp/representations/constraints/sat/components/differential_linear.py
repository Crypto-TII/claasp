"""SAT boundary relations used by differential-linear trail composition."""

from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _direct_model,
)
from claasp.representations.constraints.sat.model import CNFFormula
from claasp.semantics.cryptanalysis import (
    TruncatedBit,
    TruncatedXorDifference,
    XorDifference,
    XorMask,
)


def _validate_width(width: int) -> None:
    if not isinstance(width, int) or isinstance(width, bool) or width <= 0:
        raise ValueError("width must be a positive integer")


def _coerce_truncated(pattern, width: int):
    if pattern is None:
        return None
    if isinstance(pattern, str):
        pattern = TruncatedXorDifference.parse(pattern)
    if not isinstance(pattern, TruncatedXorDifference):
        raise TypeError("truncated patterns must be strings or TruncatedXorDifference values")
    if len(pattern.bits) != width:
        raise ValueError(f"truncated patterns must contain {width} bits")
    return pattern


def _coerce_binary(pattern, width: int, pattern_type):
    if pattern is None:
        return None
    if isinstance(pattern, int) and not isinstance(pattern, bool):
        pattern = pattern_type(pattern, width)
    if not isinstance(pattern, pattern_type):
        raise TypeError(f"binary patterns must be integers or {pattern_type.__name__} values")
    if pattern.width != width:
        raise ValueError(f"binary patterns must contain {width} bits")
    return pattern


def _binary_bits(pattern, width: int):
    return tuple((pattern.value >> (width - bit - 1)) & 1 for bit in range(width))


def _encoded(bit):
    return (1, 0) if bit is TruncatedBit.UNKNOWN else (0, int(bit.value))


class DifferentialToTruncatedSATModel:
    """Connect an exact XOR difference to the truncated middle boundary.

    The recovered legacy clauses force every boundary bit to remain exact:
    the truncated unknown flag is false and its value equals the incoming
    difference. This is the upper connector used before a differential-linear
    distinguisher's middle part.

    EXAMPLES::

        >>> model = DifferentialToTruncatedSATModel(
        ...     2, difference=XorDifference(2, 2), truncated_pattern="10"
        ... )
        >>> formula = model.cnf_formula()
        >>> (formula.variable_count, formula.clause_count)
        (6, 12)
        >>> assignment = {
        ...     "difference_0": 1, "difference_1": 0,
        ...     "truncated_0_unknown": 0, "truncated_0_value": 1,
        ...     "truncated_1_unknown": 0, "truncated_1_value": 0,
        ... }
        >>> difference, middle = model.decode_boundary(assignment)
        >>> (difference.value, str(middle))
        (2, '10')
    """

    model_provenance = _direct_model(
        ConstraintBackend.SAT,
        "DifferentialToTruncatedSATModel",
        "differential_linear",
        "legacy exact-difference to truncated-boundary clauses",
        "Direct per-bit equality between an exact difference and a canonical non-unknown ternary value.",
    )

    def __init__(self, width: int, *, difference=None, truncated_pattern=None) -> None:
        _validate_width(width)
        self.width = width
        self.difference = _coerce_binary(difference, width, XorDifference)
        self.truncated_pattern = _coerce_truncated(truncated_pattern, width)
        self._formula: CNFFormula | None = None

    def cnf_formula(self) -> CNFFormula:
        """Return the legacy three-clause connector for each bit."""

        variables = tuple(
            name
            for bit in range(self.width)
            for name in (
                f"difference_{bit}",
                f"truncated_{bit}_unknown",
                f"truncated_{bit}_value",
            )
        )
        indices = {name: index + 1 for index, name in enumerate(variables)}
        clauses: list[tuple[int, ...]] = []
        provenance: list[str] = []

        def add(clause, label):
            clauses.append(tuple(clause))
            provenance.append(label)

        for bit in range(self.width):
            difference = indices[f"difference_{bit}"]
            unknown = indices[f"truncated_{bit}_unknown"]
            value = indices[f"truncated_{bit}_value"]
            add((-unknown,), "differential_to_truncated_exact")
            add((value, -difference), "differential_to_truncated_exact")
            add((difference, -value), "differential_to_truncated_exact")

        if self.difference is not None:
            for bit, value in enumerate(_binary_bits(self.difference, self.width)):
                variable = indices[f"difference_{bit}"]
                add(((variable if value else -variable),), "fixed_difference")
        if self.truncated_pattern is not None:
            for bit, value in enumerate(self.truncated_pattern.bits):
                for field, encoded in zip(("unknown", "value"), _encoded(value)):
                    variable = indices[f"truncated_{bit}_{field}"]
                    add(((variable if encoded else -variable),), "fixed_truncated")

        self._formula = CNFFormula(
            variables,
            tuple(clauses),
            tuple(provenance),
            (ConstraintModelApplication(self.model_provenance),),
        )
        return self._formula

    def decode_boundary(self, assignment):
        """Decode and independently validate the connected boundary."""

        if self._formula is None:
            raise ValueError("build the formula before decoding")
        if not self._formula.is_satisfied(assignment):
            raise ValueError("invalid differential-to-truncated SAT witness")
        difference = XorDifference(
            sum(
                int(bool(assignment[f"difference_{bit}"])) << (self.width - bit - 1)
                for bit in range(self.width)
            ),
            self.width,
        )
        middle = TruncatedXorDifference(
            tuple(
                TruncatedBit.UNKNOWN
                if assignment[f"truncated_{bit}_unknown"]
                else TruncatedBit.ONE
                if assignment[f"truncated_{bit}_value"]
                else TruncatedBit.ZERO
                for bit in range(self.width)
            )
        )
        if any(bit is TruncatedBit.UNKNOWN for bit in middle.bits):
            raise ValueError("upper differential-linear boundary must remain exact")
        if difference.value != int(str(middle), 2):
            raise ValueError("upper differential-linear boundary values disagree")
        return difference, middle


class TruncatedToLinearSATModel:
    """Connect the truncated middle boundary to an XOR-linear mask.

    The recovered legacy relation uses the canonical truncated pair and
    forbids an active linear mask wherever the middle difference is unknown.
    Exact-zero and exact-one middle bits may both carry either mask value.

    EXAMPLES::

        >>> model = TruncatedToLinearSATModel(
        ...     2, truncated_pattern="?0", mask=XorMask(0, 2)
        ... )
        >>> formula = model.cnf_formula()
        >>> (formula.variable_count, formula.clause_count)
        (6, 10)
        >>> assignment = {
        ...     "truncated_0_unknown": 1, "truncated_0_value": 0, "mask_0": 0,
        ...     "truncated_1_unknown": 0, "truncated_1_value": 0, "mask_1": 0,
        ... }
        >>> middle, mask = model.decode_boundary(assignment)
        >>> (str(middle), mask.value)
        ('?0', 0)
    """

    model_provenance = _direct_model(
        ConstraintBackend.SAT,
        "TruncatedToLinearSATModel",
        "differential_linear",
        "legacy truncated-boundary to XOR-linear clauses",
        "Direct per-bit compatibility relation forbidding an active mask at an unknown middle bit.",
    )

    def __init__(self, width: int, *, truncated_pattern=None, mask=None) -> None:
        _validate_width(width)
        self.width = width
        self.truncated_pattern = _coerce_truncated(truncated_pattern, width)
        self.mask = _coerce_binary(mask, width, XorMask)
        self._formula: CNFFormula | None = None

    def cnf_formula(self) -> CNFFormula:
        """Return the legacy two-clause connector for each bit."""

        variables = tuple(
            name
            for bit in range(self.width)
            for name in (
                f"truncated_{bit}_unknown",
                f"truncated_{bit}_value",
                f"mask_{bit}",
            )
        )
        indices = {name: index + 1 for index, name in enumerate(variables)}
        clauses: list[tuple[int, ...]] = []
        provenance: list[str] = []

        def add(clause, label):
            clauses.append(tuple(clause))
            provenance.append(label)

        for bit in range(self.width):
            unknown = indices[f"truncated_{bit}_unknown"]
            value = indices[f"truncated_{bit}_value"]
            mask = indices[f"mask_{bit}"]
            add((-unknown, -value), "truncated_canonical_unknown")
            add((-mask, -unknown), "truncated_to_linear_compatibility")

        if self.truncated_pattern is not None:
            for bit, value in enumerate(self.truncated_pattern.bits):
                for field, encoded in zip(("unknown", "value"), _encoded(value)):
                    variable = indices[f"truncated_{bit}_{field}"]
                    add(((variable if encoded else -variable),), "fixed_truncated")
        if self.mask is not None:
            for bit, value in enumerate(_binary_bits(self.mask, self.width)):
                variable = indices[f"mask_{bit}"]
                add(((variable if value else -variable),), "fixed_mask")

        self._formula = CNFFormula(
            variables,
            tuple(clauses),
            tuple(provenance),
            (ConstraintModelApplication(self.model_provenance),),
        )
        return self._formula

    def decode_boundary(self, assignment):
        """Decode and independently validate the connected boundary."""

        if self._formula is None:
            raise ValueError("build the formula before decoding")
        if not self._formula.is_satisfied(assignment):
            raise ValueError("invalid truncated-to-linear SAT witness")
        middle = TruncatedXorDifference(
            tuple(
                TruncatedBit.UNKNOWN
                if assignment[f"truncated_{bit}_unknown"]
                else TruncatedBit.ONE
                if assignment[f"truncated_{bit}_value"]
                else TruncatedBit.ZERO
                for bit in range(self.width)
            )
        )
        mask = XorMask(
            sum(
                int(bool(assignment[f"mask_{bit}"])) << (self.width - bit - 1)
                for bit in range(self.width)
            ),
            self.width,
        )
        if any(
            bit is TruncatedBit.UNKNOWN and mask_bit
            for bit, mask_bit in zip(middle.bits, _binary_bits(mask, self.width))
        ):
            raise ValueError("linear masks must be zero at unknown middle bits")
        return middle, mask


__all__ = ["DifferentialToTruncatedSATModel", "TruncatedToLinearSATModel"]
