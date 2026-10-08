"""Functional SAT encodings for Boolean operators."""

from claasp.components import Add, BitwiseAnd, BitwiseNot, BitwiseOr, Xor
from claasp.representations.constraints import ConstraintBackend, _direct_model


class BooleanFunctionalSATModel:
    """Encode one functional bitwise Boolean component.

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

    model_provenance = _direct_model(
        ConstraintBackend.SAT,
        "BooleanFunctionalSATModel",
        "functional",
        "direct Boolean operator clauses",
        "The clauses are generated directly from XOR, AND, OR, and NOT truth tables.",
    )

    def __init__(self, component) -> None:
        if not isinstance(component, (Add, BitwiseAnd, BitwiseNot, BitwiseOr, Xor)):
            raise TypeError("component must be Add, Xor, BitwiseAnd, BitwiseOr, or BitwiseNot")
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
        elif isinstance(component, BitwiseAnd):
            for position, output in enumerate(outputs):
                for bit, target in enumerate(output):
                    context.and_(
                        target, selected[0][position][bit], selected[1][position][bit], label
                    )
        elif isinstance(component, BitwiseOr):
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
                            context.auxiliary.append(("or", (target, accumulator, operand)))
                        context.or_(target, accumulator, operand, label)
                        accumulator = target
        else:
            for position, output in enumerate(outputs):
                for bit, target in enumerate(output):
                    context.not_(target, selected[0][position][bit], label)


class BooleanNativeXorSATModel(BooleanFunctionalSATModel):
    """Encode Boolean operators with native parity records when available.

    EXAMPLES::

        >>> from claasp.components import Xor
        >>> from claasp.primitives import Simon
        >>> component = next(item for item in Simon(number_of_rounds=1).components
        ...                  if isinstance(item, Xor))
        >>> BooleanNativeXorSATModel(component).model_provenance.encoding_name
        'CryptoMiniSat native XOR records'
    """

    model_provenance = _direct_model(
        ConstraintBackend.SAT,
        "BooleanNativeXorSATModel",
        "functional",
        "CryptoMiniSat native XOR records",
        "Parity equations are emitted directly; non-XOR operators retain ordinary CNF.",
    )


__all__ = ["BooleanFunctionalSATModel", "BooleanNativeXorSATModel"]
