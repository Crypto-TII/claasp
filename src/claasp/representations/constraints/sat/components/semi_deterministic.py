"""Recovered semi-deterministic truncated SAT component encodings."""

from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _unaudited_model,
)
from claasp.representations.constraints.sat.components._semi_deterministic_templates import (
    WINDOW_TEMPLATES,
)
from claasp.representations.constraints.sat.model import CNFFormula
from claasp.semantics.cryptanalysis import TruncatedBit, TruncatedXorDifference

_WEIGHTS = {0: 0, 1: 4, 2: 9, 3: 19, 4: 41, 5: 100}


class ModularAddSemiDeterministicTruncatedSATModel:
    """Recover the legacy look-ahead-window modular-add CNF.

    The clauses inspect up to five adjacent truncated positions and expose a
    three-bit probability code per output position. Unknown trits retain the
    legacy redundant value bit because that bit participates in the recovered
    formulation. Decoding projects both encodings of unknown to ``?``.

    EXAMPLES::

        >>> model = ModularAddSemiDeterministicTruncatedSATModel(
        ...     4, left_pattern="0001", right_pattern="0000"
        ... )
        >>> formula = model.cnf_formula()
        >>> (formula.variable_count, formula.clause_count)
        (36, 309)
        >>> formula.constraint_models[0].model.reference_status.value
        'TBD'
    """

    model_provenance = _unaudited_model(
        ConstraintBackend.SAT,
        "ModularAddSemiDeterministicTruncatedSATModel",
        "semi_deterministic_truncated_xor",
        "legacy look-ahead windows 0 through 3",
        "Legacy source, documentation, bibliography, tests, and commits introducing the pinned "
        "templates contain no primary-source attribution or derivation.",
    )

    def __init__(
        self,
        width: int,
        *,
        left_pattern=None,
        right_pattern=None,
        output_pattern=None,
    ) -> None:
        if not isinstance(width, int) or isinstance(width, bool) or width < 2:
            raise ValueError("width must be an integer of at least two")
        self.width = width
        self.left_pattern = self._coerce(left_pattern)
        self.right_pattern = self._coerce(right_pattern)
        self.output_pattern = self._coerce(output_pattern)
        self._formula: CNFFormula | None = None

    def _coerce(self, pattern):
        if pattern is None:
            return None
        if isinstance(pattern, str):
            pattern = TruncatedXorDifference.parse(pattern)
        if not isinstance(pattern, TruncatedXorDifference):
            raise TypeError("patterns must be strings or TruncatedXorDifference values")
        if len(pattern.bits) != self.width:
            raise ValueError(f"patterns must contain {self.width} bits")
        return pattern

    def cnf_formula(self) -> CNFFormula:
        """Return the pinned legacy window clauses with fixed boundaries."""

        variables = tuple(
            f"{prefix}_{bit}_{field}"
            for prefix in ("left", "right", "output")
            for bit in range(self.width)
            for field in ("unknown", "value")
        ) + tuple(f"weight_{field}_{bit}" for field in ("p", "q", "r") for bit in range(self.width))
        indices = {name: index for index, name in enumerate(variables, 1)}
        clauses = []
        provenance = []

        def add(literals, label):
            clauses.append(tuple(literals))
            provenance.append(label)

        last = self.width - 1
        for prefix in ("left", "right", "output"):
            add((-indices[f"{prefix}_{last}_unknown"],), "semi_deterministic_lsb")
        left = indices[f"left_{last}_value"]
        right = indices[f"right_{last}_value"]
        output = indices[f"output_{last}_value"]
        for clause in (
            (left, right, -output),
            (left, -right, output),
            (-left, right, output),
            (-left, -right, -output),
        ):
            add(clause, "semi_deterministic_lsb")

        for bit in range(last):
            length = min(5, self.width - bit)
            window = length - 2
            mapping = {
                f"{legacy}_{field}{offset}": f"{current}_{bit + offset}_{name}"
                for legacy, current in (("A", "left"), ("B", "right"), ("C", "output"))
                for field, name in (("t", "unknown"), ("v", "value"))
                for offset in range(length)
            }
            mapping.update({field + "0": f"weight_{field}_{bit}" for field in ("p", "q", "r")})
            for template in WINDOW_TEMPLATES[window]:
                add(
                    (
                        indices[mapping[token.removeprefix("-")]]
                        * (-1 if token.startswith("-") else 1)
                        for token in template
                    ),
                    f"semi_deterministic_window_{window}",
                )

        for field in ("p", "q", "r"):
            add((-indices[f"weight_{field}_{last}"],), "semi_deterministic_lsb_weight")

        for prefix, pattern in (
            ("left", self.left_pattern),
            ("right", self.right_pattern),
            ("output", self.output_pattern),
        ):
            if pattern is None:
                continue
            for bit, value in enumerate(pattern.bits):
                unknown = f"{prefix}_{bit}_unknown"
                known = f"{prefix}_{bit}_value"
                if value is TruncatedBit.UNKNOWN:
                    add((indices[unknown],), f"fixed_{prefix}")
                else:
                    add((-indices[unknown],), f"fixed_{prefix}")
                    add(
                        ((indices[known] if value is TruncatedBit.ONE else -indices[known]),),
                        f"fixed_{prefix}",
                    )

        self._formula = CNFFormula(
            variables,
            tuple(clauses),
            tuple(provenance),
            (ConstraintModelApplication(self.model_provenance),),
        )
        return self._formula

    def decode_transition(self, assignment):
        """Decode truncated operands, output, and the legacy scaled weight."""

        if self._formula is None:
            raise ValueError("build the formula before decoding")
        if not self._formula.is_satisfied(assignment):
            raise ValueError("invalid semi-deterministic modular-add SAT witness")

        def pattern(prefix):
            return TruncatedXorDifference(
                tuple(
                    TruncatedBit.UNKNOWN
                    if assignment[f"{prefix}_{bit}_unknown"]
                    else TruncatedBit.ONE
                    if assignment[f"{prefix}_{bit}_value"]
                    else TruncatedBit.ZERO
                    for bit in range(self.width)
                )
            )

        codes = tuple(
            4 * int(bool(assignment[f"weight_p_{bit}"]))
            + 2 * int(bool(assignment[f"weight_q_{bit}"]))
            + int(bool(assignment[f"weight_r_{bit}"]))
            for bit in range(self.width)
        )
        if any(code not in _WEIGHTS for code in codes):
            raise ValueError("legacy semi-deterministic witness has an invalid weight code")
        return (
            pattern("left"),
            pattern("right"),
            pattern("output"),
            sum(_WEIGHTS[code] for code in codes),
        )


__all__ = ["ModularAddSemiDeterministicTruncatedSATModel"]
