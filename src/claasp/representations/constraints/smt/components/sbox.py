"""SMT encodings of S-box transition relations."""

from claasp.representations.constraints.smt.model import SMTFormula
from claasp.semantics.cryptanalysis import SBoxTransitionSemantics, TrailKind


class SBoxTransitionSMTModel:
    """Lower a selected S-box DDT or LAT support relation to Boolean SMT.

    Prefer :class:`SBoxXorDifferentialSMTModel` or
    :class:`SBoxXorLinearSMTModel` in new code.

    EXAMPLES::

        >>> model = SBoxTransitionSMTModel((0, 1), TrailKind.XOR_DIFFERENTIAL)
        >>> formula = model.smt_formula(input_pattern=1, output_pattern=1)
        >>> formula.variables
        ('input_0', 'output_0')
        >>> formula.provenance[-2:]
        ('fixed_input', 'fixed_output')
    """

    def __init__(self, table: tuple[int, ...] | list[int], kind: TrailKind) -> None:
        if kind not in (TrailKind.XOR_DIFFERENTIAL, TrailKind.XOR_LINEAR):
            raise ValueError("S-box SMT model requires differential or linear semantics")
        self.semantics = SBoxTransitionSemantics(table)
        self.kind = kind

    def smt_formula(
        self,
        *,
        input_pattern: int | None = None,
        output_pattern: int | None = None,
    ) -> SMTFormula:
        """Return the exact transition-support relation with optional patterns."""

        width = self.semantics.width
        variables = tuple(f"input_{bit}" for bit in range(width)) + tuple(
            f"output_{bit}" for bit in range(width)
        )
        clauses = []
        provenance = []
        for source in range(1 << width):
            for target in range(1 << width):
                transition = (
                    self.semantics.xor_differential(source, target)
                    if self.kind is TrailKind.XOR_DIFFERENTIAL
                    else self.semantics.xor_linear(source, target)
                )
                if transition.is_possible:
                    continue
                assignment = _bits(source, width) + _bits(target, width)
                clauses.append(
                    tuple(
                        -(position + 1) if value else position + 1
                        for position, value in enumerate(assignment)
                    )
                )
                provenance.append(f"{self.kind.value}_support")
        for prefix, value, offset in (
            ("input", input_pattern, 0),
            ("output", output_pattern, width),
        ):
            if value is None:
                continue
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 1 << width:
                raise ValueError(f"{prefix}_pattern must fit the S-box width")
            for bit, encoded in enumerate(_bits(value, width)):
                variable = offset + bit + 1
                clauses.append((variable if encoded else -variable,))
                provenance.append(f"fixed_{prefix}")
        return SMTFormula(variables, tuple(clauses), tuple(provenance))

    def decode_transition(self, assignment: dict[str, int]):
        """Project an SMT assignment back to the shared transition object."""

        width = self.semantics.width
        source = _integer(tuple(assignment[f"input_{bit}"] for bit in range(width)))
        target = _integer(tuple(assignment[f"output_{bit}"] for bit in range(width)))
        return (
            self.semantics.xor_differential(source, target)
            if self.kind is TrailKind.XOR_DIFFERENTIAL
            else self.semantics.xor_linear(source, target)
        )


class SBoxXorDifferentialSMTModel(SBoxTransitionSMTModel):
    """Lower one S-box XOR-differential support relation to Boolean SMT.

    EXAMPLES::

        >>> model = SBoxXorDifferentialSMTModel((0, 1))
        >>> transition = model.decode_transition({"input_0": 1, "output_0": 1})
        >>> (transition.is_possible, transition.weight == 0.0)
        (True, True)
    """

    def __init__(self, table: tuple[int, ...] | list[int]) -> None:
        super().__init__(table, TrailKind.XOR_DIFFERENTIAL)


class SBoxXorLinearSMTModel(SBoxTransitionSMTModel):
    """Lower one S-box XOR-linear support relation to Boolean SMT.

    EXAMPLES::

        >>> model = SBoxXorLinearSMTModel((0, 1))
        >>> transition = model.decode_transition({"input_0": 1, "output_0": 1})
        >>> (transition.is_possible, transition.sign)
        (True, 1)
    """

    def __init__(self, table: tuple[int, ...] | list[int]) -> None:
        super().__init__(table, TrailKind.XOR_LINEAR)


def _bits(value: int, width: int) -> tuple[int, ...]:
    return tuple((value >> (width - 1 - bit)) & 1 for bit in range(width))


def _integer(bits: tuple[int, ...]) -> int:
    value = 0
    for bit in bits:
        value = (value << 1) | bit
    return value
