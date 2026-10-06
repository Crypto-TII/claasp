"""Functional SAT encodings for Boolean operators."""

from claasp.components import Add, BitwiseAnd, Xor


class BooleanFunctionalSATModel:
    """Encode one functional XOR or bitwise-AND component.

    EXAMPLES::

        >>> from claasp.components import BitwiseAnd
        >>> from claasp.primitives import Simon
        >>> from claasp.representations.constraints.sat import BooleanCNFModel
        >>> primitive = Simon(number_of_rounds=1)
        >>> component = next(item for item in primitive.components if isinstance(item, BitwiseAnd))
        >>> encoding = BooleanFunctionalSATModel(component)
        >>> formula = BooleanCNFModel(primitive).cnf_formula()
        >>> encoding.component.component_id in formula.provenance
        True
    """

    def __init__(self, component) -> None:
        if not isinstance(component, (Add, BitwiseAnd, Xor)):
            raise TypeError("component must be Add, Xor, or BitwiseAnd")
        self.component = component

    def encode(self, context, outputs, selected) -> None:
        """Append the component's functional clauses to ``context``."""

        component = self.component
        label = component.component_id
        if isinstance(component, Add):
            for position, output in enumerate(outputs):
                operands = [group[position][0] for group in selected]
                accumulator = operands[0]
                for operand_number, operand in enumerate(operands[1:], start=1):
                    is_last = operand_number == len(operands) - 1
                    target = (
                        output[0]
                        if is_last
                        else context.allocate(f"__aux_{label}_{position}_{operand_number}")
                    )
                    if not is_last:
                        context.auxiliary.append(("xor", (target, accumulator, operand)))
                    context.xor(target, accumulator, operand, label)
                    accumulator = target
        elif isinstance(component, Xor):
            for position, output in enumerate(outputs):
                for bit, target_output in enumerate(output):
                    operands = [group[position][bit] for group in selected]
                    accumulator = operands[0]
                    for operand_number, operand in enumerate(operands[1:], start=1):
                        is_last = operand_number == len(operands) - 1
                        target = (
                            target_output
                            if is_last
                            else context.allocate(
                                f"__aux_{label}_{position}_{bit}_{operand_number}"
                            )
                        )
                        if not is_last:
                            context.auxiliary.append(("xor", (target, accumulator, operand)))
                        context.xor(target, accumulator, operand, label)
                        accumulator = target
        else:
            for position, output in enumerate(outputs):
                for bit, target in enumerate(output):
                    context.and_(
                        target, selected[0][position][bit], selected[1][position][bit], label
                    )
