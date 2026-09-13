"""SMT lowering of shared component transition semantics."""

from claasp_next.analysis import ModularAddLinearSemantics, SBoxTransitionSemantics, TrailKind
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


class ModularAddLinearSMTModel:
    """Boolean SMT relation for exact modular-add linear correlations."""

    def __init__(self, width: int) -> None:
        self.semantics = ModularAddLinearSemantics(width)
        self.width = width

    def smt_formula(
        self,
        *,
        left_mask: int | None = None,
        right_mask: int | None = None,
        output_mask: int | None = None,
    ) -> SMTFormula:
        """Return the LWR carry relation with optional fixed masks."""

        variables = (
            tuple(f"left_{bit}" for bit in range(self.width))
            + tuple(f"right_{bit}" for bit in range(self.width))
            + tuple(f"output_{bit}" for bit in range(self.width))
            + tuple(f"weight_{bit}" for bit in range(self.width))
        )
        indices = {name: index for index, name in enumerate(variables, 1)}
        clauses = [(-indices["weight_0"],)]
        provenance = ["linear_weight_msb"]
        for bit in range(1, self.width):
            names = (
                f"weight_{bit}",
                f"weight_{bit - 1}",
                f"output_{bit - 1}",
                f"left_{bit - 1}",
                f"right_{bit - 1}",
            )
            _xor_equivalence(names, indices, clauses, provenance)
        for bit in range(self.width):
            for operand in ("left", "right"):
                a = indices[f"output_{bit}"]
                b = indices[f"{operand}_{bit}"]
                weight = indices[f"weight_{bit}"]
                clauses.extend(((-a, b, weight), (a, -b, weight)))
                provenance.extend(("linear_support", "linear_support"))
        for prefix, value, offset in (
            ("left", left_mask, 0),
            ("right", right_mask, self.width),
            ("output", output_mask, 2 * self.width),
        ):
            if value is None:
                continue
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 1 << self.width:
                raise ValueError(f"{prefix}_mask must fit the modular-add width")
            for bit, encoded in enumerate(_bits(value, self.width)):
                variable = offset + bit + 1
                clauses.append((variable if encoded else -variable,))
                provenance.append(f"fixed_{prefix}")
        return SMTFormula(variables, tuple(clauses), tuple(provenance))

    def decode_transition(self, assignment: dict[str, int]):
        """Project masks to the shared exact Walsh-correlation semantics."""

        left = _integer(tuple(assignment[f"left_{bit}"] for bit in range(self.width)))
        right = _integer(tuple(assignment[f"right_{bit}"] for bit in range(self.width)))
        output = _integer(tuple(assignment[f"output_{bit}"] for bit in range(self.width)))
        transition = self.semantics.xor_linear(left, right, output)
        encoded_weight = sum(assignment[f"weight_{bit}"] for bit in range(self.width))
        if not transition.is_possible or transition.weight != encoded_weight:
            raise ValueError("SMT assignment disagrees with exact modular-add semantics")
        return transition


def _bits(value: int, width: int) -> tuple[int, ...]:
    return tuple((value >> (width - 1 - bit)) & 1 for bit in range(width))


def _integer(bits: tuple[int, ...]) -> int:
    value = 0
    for bit in bits:
        value = (value << 1) | bit
    return value


def _xor_equivalence(names, indices, clauses, provenance):
    # names[0] equals the XOR of the remaining variables. Forbid precisely the
    # assignments with odd parity over all names.
    for assignment in range(1 << len(names)):
        values = tuple((assignment >> (len(names) - 1 - bit)) & 1 for bit in range(len(names)))
        if sum(values) % 2 == 0:
            continue
        clauses.append(tuple(
            -indices[name] if value else indices[name]
            for name, value in zip(names, values)
        ))
        provenance.append("linear_weight_recurrence")
