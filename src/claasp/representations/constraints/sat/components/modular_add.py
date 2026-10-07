"""Functional SAT encoding for modular addition."""

from claasp.components import ModularAdd
from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _direct_model,
    _verified_model,
)
from claasp.representations.constraints.sat.model import CNFFormula


class ModularAddFunctionalSATModel:
    """Encode the exact functional relation for addition modulo a word size.

    EXAMPLES::

        >>> from claasp.components import ModularAdd
        >>> from claasp.primitives import Speck
        >>> from claasp.representations.constraints.sat import BooleanCNFModel
        >>> primitive = Speck(number_of_rounds=1)
        >>> component = next(item for item in primitive.components if isinstance(item, ModularAdd))
        >>> encoding = ModularAddFunctionalSATModel(component)
        >>> formula = BooleanCNFModel(primitive).cnf_formula()
        >>> encoding.component.component_id in formula.provenance
        True
    """

    model_provenance = _direct_model(
        ConstraintBackend.SAT,
        "ModularAddFunctionalSATModel",
        "functional",
        "ripple-carry Boolean clauses",
        "The clauses are generated directly from full-adder truth tables.",
    )

    def __init__(self, component) -> None:
        if not isinstance(component, ModularAdd):
            raise TypeError("component must be a ModularAdd")
        self.component = component

    def encode(self, context, outputs, selected) -> None:
        """Append the component's functional clauses to ``context``."""

        component = self.component
        label = component.component_id
        width = component.output_type.domain.width
        for position, output in enumerate(outputs):
            accumulator = selected[0][position]
            for operand_number, operand in enumerate(
                (group[position] for group in selected[1:]), start=1
            ):
                is_last = operand_number == len(selected) - 1
                target = (
                    output
                    if is_last
                    else tuple(
                        context.allocate(f"__aux_{label}_{position}_{operand_number}_{bit}")
                        for bit in range(width)
                    )
                )
                carry = None
                for bit in range(width - 1, -1, -1):
                    if carry is None:
                        context.xor(target[bit], accumulator[bit], operand[bit], label)
                        if not is_last:
                            context.auxiliary.append(
                                ("xor", (target[bit], accumulator[bit], operand[bit]))
                            )
                    else:
                        partial = context.allocate(
                            f"__aux_{label}_{position}_{operand_number}_xor_{bit}"
                        )
                        context.xor(partial, accumulator[bit], operand[bit], label)
                        context.xor(target[bit], partial, carry, label)
                        context.auxiliary.append(("xor", (partial, accumulator[bit], operand[bit])))
                        if not is_last:
                            context.auxiliary.append(("xor", (target[bit], partial, carry)))
                    if bit:
                        next_carry = context.allocate(
                            f"__aux_{label}_{position}_{operand_number}_carry_{bit}"
                        )
                        if carry is None:
                            context.and_(next_carry, accumulator[bit], operand[bit], label)
                            context.auxiliary.append(
                                ("and", (next_carry, accumulator[bit], operand[bit]))
                            )
                        else:
                            context.majority(
                                next_carry, accumulator[bit], operand[bit], carry, label
                            )
                            context.auxiliary.append(
                                (
                                    "majority",
                                    (next_carry, accumulator[bit], operand[bit], carry),
                                )
                            )
                        carry = next_carry
                accumulator = target


class ModularAddNativeXorSATModel(ModularAddFunctionalSATModel):
    """Use native parity records inside the functional ripple-carry adder.

    EXAMPLES::

        >>> ModularAddNativeXorSATModel.model_provenance.encoding_name
        'ripple-carry with CryptoMiniSat native XOR records'
    """

    model_provenance = _direct_model(
        ConstraintBackend.SAT,
        "ModularAddNativeXorSATModel",
        "functional",
        "ripple-carry with CryptoMiniSat native XOR records",
        "Sum parity is native XOR; carry majority constraints remain ordinary CNF.",
    )


class ModularAddDifferentialSATModel:
    """Exact paired-carry CNF support and unary XOR-differential weights.

    EXAMPLES::

        >>> model = ModularAddDifferentialSATModel(4)
        >>> formula = model.cnf_formula()
        >>> formula.variables[-3:]
        ('weight_0', 'weight_1', 'weight_2')
        >>> formula.constraint_models[0].model.backend.value
        'sat'
    """

    model_provenance = _verified_model(
        ConstraintBackend.SAT,
        "ModularAddDifferentialSATModel",
        "xor_differential",
        "paired-carry Boolean support with unary weight",
        "https://eprint.iacr.org/2001/001",
        "Efficient Algorithms for Computing Differential Properties of Addition",
        "section 4, Algorithm 2 and Theorem 1",
    )

    def __init__(self, width: int) -> None:
        from claasp.representations.constraints.smt.components.modular_add import (
            ModularAddDifferentialSMTModel,
        )

        self._shared = ModularAddDifferentialSMTModel(width)
        self.semantics = self._shared.semantics
        self.width = self._shared.width

    def cnf_formula(self) -> CNFFormula:
        """Return the backend-neutral Boolean clauses in a SAT container."""

        return _as_cnf(self._shared.smt_formula(), self.model_provenance)

    def decode_transition(self, assignment):
        """Validate and decode one complete modular-add assignment."""

        if not self.cnf_formula().is_satisfied(assignment):
            raise ValueError("invalid modular-add differential witness")
        transition = self.semantics.xor_differential(
            *(_integer(assignment, prefix, self.width) for prefix in ("left", "right", "output"))
        )
        if not transition.is_possible or transition.weight != sum(
            assignment[f"weight_{bit}"] for bit in range(self.width - 1)
        ):
            raise ValueError("modular-add differential weight disagrees with exact semantics")
        return transition


class ModularAddNWindowSATModel:
    """Bound consecutive modular-add carry differences with direct CNF.

    A carry-difference bit is the XOR of the two input differences and the
    output difference at the same position.  The least-significant bit is
    omitted because exact modular-add support fixes it to zero.  A window of
    size ``n`` forbids ``n + 1`` consecutive carry-difference ones and exposes
    variables identifying every run of exactly ``n`` positions for optional
    whole-trail counting.

    EXAMPLES::

        >>> model = ModularAddNWindowSATModel(4, 2)
        >>> formula = model.cnf_formula()
        >>> (model.carry_difference_names, model.full_window_names)
        (('carry_difference_0', 'carry_difference_1', 'carry_difference_2'), ('full_window_0', 'full_window_1'))
        >>> formula.provenance.count("n_window_run_bound")
        1
    """

    model_provenance = _direct_model(
        ConstraintBackend.SAT,
        "ModularAddNWindowSATModel",
        "xor_differential",
        "direct carry-difference run bound",
        "Pure-Python parity and conjunction clauses recover the optional legacy n-window heuristic.",
    )

    def __init__(self, width: int, window_size: int) -> None:
        if not isinstance(width, int) or isinstance(width, bool) or width < 2:
            raise ValueError("width must be an integer of at least two")
        if (
            not isinstance(window_size, int)
            or isinstance(window_size, bool)
            or not 0 <= window_size <= width - 1
        ):
            raise ValueError("window_size must be between zero and width - 1")
        self.width = width
        self.window_size = window_size
        self.carry_difference_names = tuple(f"carry_difference_{bit}" for bit in range(width - 1))
        self.full_window_names = (
            tuple(f"full_window_{start}" for start in range(width - window_size))
            if window_size
            else ()
        )

    def cnf_formula(self) -> CNFFormula:
        """Return parity, run-bound, and full-window indicator clauses."""

        boundary_names = tuple(
            f"{prefix}_{bit}" for prefix in ("left", "right", "output") for bit in range(self.width)
        )
        variables = boundary_names + self.carry_difference_names + self.full_window_names
        indices = {name: index for index, name in enumerate(variables, 1)}
        clauses = []
        provenance = []

        def add(literals, label):
            clauses.append(tuple(literals))
            provenance.append(label)

        for bit, carry in enumerate(self.carry_difference_names):
            names = (carry, f"left_{bit}", f"right_{bit}", f"output_{bit}")
            for assignment in range(16):
                values = tuple((assignment >> (3 - position)) & 1 for position in range(4))
                if sum(values) % 2 == 0:
                    continue
                add(
                    (
                        -indices[name] if value else indices[name]
                        for name, value in zip(names, values)
                    ),
                    "n_window_carry_difference",
                )

        run_length = self.window_size + 1
        for start in range(len(self.carry_difference_names) - run_length + 1):
            add(
                (
                    -indices[name]
                    for name in self.carry_difference_names[start : start + run_length]
                ),
                "n_window_run_bound",
            )

        if self.window_size:
            for start, full_window in enumerate(self.full_window_names):
                window = self.carry_difference_names[start : start + self.window_size]
                for carry in window:
                    add((-indices[full_window], indices[carry]), "n_window_full_indicator")
                add(
                    (indices[full_window], *(-indices[carry] for carry in window)),
                    "n_window_full_indicator",
                )

        return CNFFormula(
            variables,
            tuple(clauses),
            tuple(provenance),
            (ConstraintModelApplication(self.model_provenance),),
        )


class ModularAddDeterministicTruncatedSATModel:
    """Recover the legacy two-bit deterministic-truncated addition clauses.

    Each trit uses an ``unknown`` flag and a value bit. The value bit is
    ignored whenever ``unknown`` is true, matching the legacy SAT encoding.
    Decoding projects that redundant representation to ``0``, ``1``, or ``?``
    and checks it against the backend-neutral paired-carry semantics.

    EXAMPLES::

        >>> model = ModularAddDeterministicTruncatedSATModel(4)
        >>> formula = model.cnf_formula()
        >>> (formula.variable_count, formula.clause_count)
        (32, 47)
        >>> model.encode_pattern("10??")
        ((0, 1), (0, 0), (1, 0), (1, 0))
    """

    model_provenance = _direct_model(
        ConstraintBackend.SAT,
        "ModularAddDeterministicTruncatedSATModel",
        "deterministic_truncated_xor",
        "legacy two-bit paired-carry clauses",
        "The dependency-free clauses recover the legacy deterministic-truncated modular-add encoding.",
    )

    def __init__(self, width: int) -> None:
        if not isinstance(width, int) or isinstance(width, bool) or width < 2:
            raise ValueError("width must be an integer of at least two")
        self.width = width

    @staticmethod
    def encode_pattern(pattern: str) -> tuple[tuple[int, int], ...]:
        """Encode a user pattern with canonical value zero for unknown trits."""

        from claasp.semantics.cryptanalysis import TruncatedXorDifference

        difference = TruncatedXorDifference.parse(pattern)
        return tuple(
            (int(bit.encoded == 2), 0 if bit.encoded == 2 else bit.encoded)
            for bit in difference.bits
        )

    def cnf_formula(self) -> CNFFormula:
        """Return the recovered local modular-add formula."""

        variables = tuple(
            f"{prefix}_{bit}_{field}"
            for prefix in ("left", "right", "output", "carry")
            for bit in range(self.width)
            for field in ("unknown", "value")
        )
        indices = {name: index for index, name in enumerate(variables, 1)}
        clauses = []
        provenance = []

        def pair(prefix, bit):
            return (f"{prefix}_{bit}_unknown", f"{prefix}_{bit}_value")

        def add(items, label):
            clauses.append(
                tuple(indices[name] if positive else -indices[name] for name, positive in items)
            )
            provenance.append(label)

        def lsb(result, left, right, next_carry):
            return (
                ((next_carry[0], True), (next_carry[1], False)),
                ((next_carry[0], True), (right[1], False)),
                ((next_carry[0], True), (result[0], False)),
                ((next_carry[0], True), (result[1], False)),
                ((result[0], True), (left[0], False)),
                ((result[0], True), (right[0], False)),
                ((left[0], True), (right[0], True), (result[0], False)),
                ((left[1], True), (right[1], True), (result[0], True), (next_carry[0], False)),
                ((left[1], True), (result[0], True), (result[1], True), (right[1], False)),
                ((right[1], True), (result[0], True), (result[1], True), (left[1], False)),
                ((result[0], True), (left[1], False), (right[1], False), (result[1], False)),
            )

        def middle(result, left, right, carry, next_carry):
            return (
                ((next_carry[0], True), (next_carry[1], False)),
                ((next_carry[0], True), (right[1], False)),
                ((next_carry[0], True), (result[0], False)),
                ((next_carry[0], True), (result[1], False)),
                ((result[0], True), (carry[0], False)),
                ((result[0], True), (carry[1], False)),
                ((result[0], True), (left[0], False)),
                ((result[0], True), (right[0], False)),
                ((left[1], True), (right[1], True), (result[0], True), (next_carry[0], False)),
                ((left[1], True), (result[0], True), (result[1], True), (right[1], False)),
                ((right[1], True), (result[0], True), (result[1], True), (left[1], False)),
                (
                    (carry[0], True),
                    (carry[1], True),
                    (left[0], True),
                    (right[0], True),
                    (result[0], False),
                ),
                ((result[0], True), (left[1], False), (right[1], False), (result[1], False)),
            )

        def msb(result, left, right, carry):
            return (
                ((result[0], True), (carry[0], False)),
                ((result[0], True), (carry[1], False)),
                ((result[0], True), (left[0], False)),
                ((result[0], True), (right[0], False)),
                ((left[1], True), (right[1], True), (result[0], True), (result[1], False)),
                ((left[1], True), (result[0], True), (result[1], True), (right[1], False)),
                ((right[1], True), (result[0], True), (result[1], True), (left[1], False)),
                (
                    (carry[0], True),
                    (carry[1], True),
                    (left[0], True),
                    (right[0], True),
                    (result[0], False),
                ),
                ((result[0], True), (left[1], False), (right[1], False), (result[1], False)),
            )

        final_carry = pair("carry", self.width - 1)
        add(((final_carry[0], False), (final_carry[1], False)), "truncated_carry_domain")
        for clause in msb(pair("output", 0), pair("left", 0), pair("right", 0), pair("carry", 0)):
            add(clause, "truncated_modadd_msb")
        for bit in range(1, self.width - 1):
            for clause in middle(
                pair("output", bit),
                pair("left", bit),
                pair("right", bit),
                pair("carry", bit),
                pair("carry", bit - 1),
            ):
                add(clause, "truncated_modadd_middle")
        for clause in lsb(
            pair("output", self.width - 1),
            pair("left", self.width - 1),
            pair("right", self.width - 1),
            pair("carry", self.width - 2),
        ):
            add(clause, "truncated_modadd_lsb")
        return CNFFormula(
            variables,
            tuple(clauses),
            tuple(provenance),
            (ConstraintModelApplication(self.model_provenance),),
        )

    def decode_transition(self, assignment):
        """Decode and independently check one satisfying local assignment."""

        from claasp.semantics.cryptanalysis import (
            TruncatedBit,
            TruncatedXorDifference,
            truncated_modular_add,
        )

        formula = self.cnf_formula()
        if not formula.is_satisfied(assignment):
            raise ValueError("invalid deterministic-truncated modular-add witness")

        def pattern(prefix):
            bits = []
            for bit in range(self.width):
                if assignment[f"{prefix}_{bit}_unknown"]:
                    bits.append(TruncatedBit.UNKNOWN)
                elif assignment[f"{prefix}_{bit}_value"]:
                    bits.append(TruncatedBit.ONE)
                else:
                    bits.append(TruncatedBit.ZERO)
            return TruncatedXorDifference(tuple(bits))

        left, right, output = (pattern(prefix) for prefix in ("left", "right", "output"))
        if output != truncated_modular_add(left, right):
            raise ValueError("truncated output disagrees with paired-carry semantics")
        return left, right, output


class ModularSubtractDeterministicTruncatedSATModel(ModularAddDeterministicTruncatedSATModel):
    """Encode deterministic-truncated subtraction with paired-borrow clauses.

    The recovered legacy implementation deliberately used the same local
    clauses for modular addition and subtraction. Decoding remains independent
    and checks ``truncated_modular_subtract`` explicitly.

    EXAMPLES::

        >>> model = ModularSubtractDeterministicTruncatedSATModel(4)
        >>> formula = model.cnf_formula()
        >>> (formula.variable_count, formula.constraint_models[0].model.component_model)
        (32, 'ModularSubtractDeterministicTruncatedSATModel')
    """

    model_provenance = _direct_model(
        ConstraintBackend.SAT,
        "ModularSubtractDeterministicTruncatedSATModel",
        "deterministic_truncated_xor",
        "legacy two-bit paired-borrow clauses",
        "Legacy modular subtraction reuses the paired-carry Boolean relation.",
    )

    def cnf_formula(self) -> CNFFormula:
        """Return the recovered relation with subtraction provenance."""

        formula = super().cnf_formula()
        return CNFFormula(
            formula.variables,
            formula.clauses,
            formula.provenance,
            (ConstraintModelApplication(self.model_provenance),),
        )

    def decode_transition(self, assignment):
        """Decode and independently check a truncated subtraction witness."""

        from claasp.semantics.cryptanalysis import (
            TruncatedBit,
            TruncatedXorDifference,
            truncated_modular_subtract,
        )

        formula = self.cnf_formula()
        if not formula.is_satisfied(assignment):
            raise ValueError("invalid deterministic-truncated modular-subtract witness")

        def pattern(prefix):
            bits = []
            for bit in range(self.width):
                if assignment[f"{prefix}_{bit}_unknown"]:
                    bits.append(TruncatedBit.UNKNOWN)
                elif assignment[f"{prefix}_{bit}_value"]:
                    bits.append(TruncatedBit.ONE)
                else:
                    bits.append(TruncatedBit.ZERO)
            return TruncatedXorDifference(tuple(bits))

        left, right, output = (pattern(prefix) for prefix in ("left", "right", "output"))
        if output != truncated_modular_subtract(left, right):
            raise ValueError("truncated output disagrees with paired-borrow semantics")
        return left, right, output


class ModularAddLinearSATModel:
    """Exact modular-add XOR-linear mask recurrence in CNF.

    EXAMPLES::

        >>> model = ModularAddLinearSATModel(4)
        >>> formula = model.cnf_formula(left_mask=1, right_mask=0, output_mask=1)
        >>> (formula.variables[-1], formula.provenance[-1])
        ('weight_3', 'fixed_output')
    """

    model_provenance = _verified_model(
        ConstraintBackend.SAT,
        "ModularAddLinearSATModel",
        "xor_linear",
        "Boolean mask recurrence with unary weight",
        "10.1007/978-3-319-39555-5_26",
        "Automatic Search of Linear Trails in ARX with Applications to SPECK and Chaskey",
        "section 3.1, Proposition 1 and equation (1)",
    )

    def __init__(self, width: int) -> None:
        from claasp.representations.constraints.smt.components.modular_add import (
            ModularAddLinearSMTModel,
        )

        self._shared = ModularAddLinearSMTModel(width)
        self.semantics = self._shared.semantics
        self.width = self._shared.width

    def cnf_formula(
        self,
        *,
        left_mask: int | None = None,
        right_mask: int | None = None,
        output_mask: int | None = None,
    ) -> CNFFormula:
        """Return exact mask support with optional fixed masks."""

        formula = self._shared.smt_formula(
            left_mask=left_mask,
            right_mask=right_mask,
            output_mask=output_mask,
        )
        return _as_cnf(formula, self.model_provenance)

    def decode_transition(self, assignment):
        """Validate and decode one complete modular-add mask assignment."""

        if not self.cnf_formula().is_satisfied(assignment):
            raise ValueError("invalid modular-add linear witness")
        transition = self.semantics.xor_linear(
            *(_integer(assignment, prefix, self.width) for prefix in ("left", "right", "output"))
        )
        if not transition.is_possible or transition.weight != sum(
            assignment[f"weight_{bit}"] for bit in range(self.width)
        ):
            raise ValueError("modular-add linear weight disagrees with exact semantics")
        return transition


def _as_cnf(formula, provenance) -> CNFFormula:
    return CNFFormula(
        formula.variables,
        formula.assertions,
        formula.provenance,
        (ConstraintModelApplication(provenance),),
    )


def _integer(assignment, prefix: str, width: int) -> int:
    value = 0
    for bit in range(width):
        value = (value << 1) | assignment[f"{prefix}_{bit}"]
    return value


__all__ = [
    "ModularAddDifferentialSATModel",
    "ModularAddDeterministicTruncatedSATModel",
    "ModularAddFunctionalSATModel",
    "ModularAddLinearSATModel",
    "ModularAddNativeXorSATModel",
    "ModularAddNWindowSATModel",
    "ModularSubtractDeterministicTruncatedSATModel",
]
