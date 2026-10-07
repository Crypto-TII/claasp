"""Functional SAT encoding for modular addition."""

from claasp.components import ModularAdd
from claasp.representations.constraints import ConstraintBackend, _direct_model


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
