"""SMT encodings of modular-addition transition relations."""

from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _unaudited_model,
)
from claasp.representations.constraints.smt.model import SMTFormula
from claasp.semantics.cryptanalysis import (
    ModularAddLinearSemantics,
    ModularAddTransitionSemantics,
)


class ModularAddDifferentialSMTModel:
    """Exact paired-carry support and unary XOR-differential weights.

    EXAMPLES::

        >>> formula = ModularAddDifferentialSMTModel(4).smt_formula()
        >>> formula.variables[:4]
        ('left_0', 'left_1', 'left_2', 'left_3')
        >>> formula.variables[-3:]
        ('weight_0', 'weight_1', 'weight_2')
    """

    model_provenance = _unaudited_model(
        ConstraintBackend.SMT,
        "ModularAddDifferentialSMTModel",
        "xor_differential",
        "paired-carry Boolean support with unary weight",
        "The exact correspondence with a primary-source construction has not been audited.",
    )

    def __init__(self, width):
        self.semantics = ModularAddTransitionSemantics(width)
        self.width = width

    def smt_formula(self):
        """Compute the SMT formula for this public typed contract."""

        from itertools import product

        variables = tuple(
            f"{prefix}_{bit}" for prefix in ("left", "right", "output") for bit in range(self.width)
        ) + tuple(f"weight_{bit}" for bit in range(self.width - 1))
        indices = {name: index for index, name in enumerate(variables, 1)}
        clauses, provenance = [], []

        def forbid(names, bits, label):
            clauses.append(
                tuple(
                    -indices[name] if value else indices[name] for name, value in zip(names, bits)
                )
            )
            provenance.append(label)

        last = tuple(f"{prefix}_{self.width - 1}" for prefix in ("left", "right", "output"))
        for bits in product((0, 1), repeat=3):
            if bits[0] ^ bits[1] ^ bits[2]:
                forbid(last, bits, "differential_lsb_parity")
        for bit in range(self.width - 1):
            upper = tuple(f"{prefix}_{bit}" for prefix in ("left", "right", "output"))
            lower = tuple(f"{prefix}_{bit + 1}" for prefix in ("left", "right", "output"))
            for bits in product((0, 1), repeat=6):
                if bits[3] == bits[4] == bits[5] and (bits[0] ^ bits[1] ^ bits[2]) != bits[4]:
                    forbid(upper + lower, bits, "differential_carry_support")
            for bits in product((0, 1), repeat=4):
                if bits[3] != int(not (bits[0] == bits[1] == bits[2])):
                    forbid(lower + (f"weight_{bit}",), bits, "differential_weight")
        return SMTFormula(
            variables,
            tuple(clauses),
            tuple(provenance),
            (ConstraintModelApplication(self.model_provenance),),
        )

    def decode_transition(self, assignment):
        """Decode and validate a modular-add XOR-differential transition."""

        from claasp.representations.constraints.sat import CNFFormula

        formula = self.smt_formula()
        if not CNFFormula(formula.variables, formula.assertions, formula.provenance).is_satisfied(
            assignment
        ):
            raise ValueError("invalid modular-add differential witness")
        values = [
            _integer(tuple(assignment[f"{prefix}_{bit}"] for bit in range(self.width)))
            for prefix in ("left", "right", "output")
        ]
        transition = self.semantics.xor_differential(*values)
        if not transition.is_possible or transition.weight != sum(
            assignment[f"weight_{bit}"] for bit in range(self.width - 1)
        ):
            raise ValueError("modular-add differential weight disagrees with exact semantics")
        return transition


class ModularAddLinearSMTModel:
    """Boolean SMT relation for exact modular-add XOR-linear correlations.

    EXAMPLES::

        >>> formula = ModularAddLinearSMTModel(4).smt_formula(
        ...     left_mask=1, right_mask=0, output_mask=1
        ... )
        >>> formula.variables[-4:]
        ('weight_0', 'weight_1', 'weight_2', 'weight_3')
        >>> formula.provenance[-1]
        'fixed_output'
    """

    model_provenance = _unaudited_model(
        ConstraintBackend.SMT,
        "ModularAddLinearSMTModel",
        "xor_linear",
        "Boolean mask recurrence with unary weight",
        "The exact correspondence with a primary-source construction has not been audited.",
    )

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
        """Return the carry relation with optional fixed masks."""

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
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or not 0 <= value < 1 << self.width
            ):
                raise ValueError(f"{prefix}_mask must fit the modular-add width")
            for bit, encoded in enumerate(_bits(value, self.width)):
                variable = offset + bit + 1
                clauses.append((variable if encoded else -variable,))
                provenance.append(f"fixed_{prefix}")
        return SMTFormula(
            variables,
            tuple(clauses),
            tuple(provenance),
            (ConstraintModelApplication(self.model_provenance),),
        )

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
    for assignment in range(1 << len(names)):
        values = tuple((assignment >> (len(names) - 1 - bit)) & 1 for bit in range(len(names)))
        if sum(values) % 2 == 0:
            continue
        clauses.append(
            tuple(-indices[name] if value else indices[name] for name, value in zip(names, values))
        )
        provenance.append("linear_weight_recurrence")
