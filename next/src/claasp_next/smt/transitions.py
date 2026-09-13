"""SMT lowering of shared component transition semantics."""

from claasp_next.analysis import SBoxTransitionSemantics, TrailKind
from claasp_next.smt.formula import SMTFormula


class SBoxTransitionSMTModel:
    """Lower an S-box DDT or LAT support relation to Boolean SMT."""

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
                clauses.append(tuple(
                    -(position + 1) if value else position + 1
                    for position, value in enumerate(assignment)
                ))
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


def _bits(value: int, width: int) -> tuple[int, ...]:
    return tuple((value >> (width - 1 - bit)) & 1 for bit in range(width))


def _integer(bits: tuple[int, ...]) -> int:
    value = 0
    for bit in bits:
        value = (value << 1) | bit
    return value
