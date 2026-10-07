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
    "ModularAddFunctionalSATModel",
    "ModularAddLinearSATModel",
    "ModularAddNativeXorSATModel",
]
