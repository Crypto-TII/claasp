"""Functional SAT encodings for multiplication modulo a word size."""

from claasp.components import ModularMultiply
from claasp.representations.constraints import ConstraintBackend, _direct_model


class ModularMultiplyFunctionalSATModel:
    """Encode exact multiplication modulo ``2**width`` with Boolean gates.

    EXAMPLES::

        >>> from claasp.primitives.single_component_primitives import ModularMultiply
        >>> from claasp.representations.constraints.sat import BooleanCNFModel
        >>> primitive = ModularMultiply(word_bit_size=4, number_of_inputs=3)
        >>> model = BooleanCNFModel(primitive)
        >>> model.cnf_formula().is_satisfied(
        ...     model.witness(primitive.evaluate_with_trace(3, 5, 7)))
        True
    """

    model_provenance = _direct_model(
        ConstraintBackend.SAT,
        "ModularMultiplyFunctionalSATModel",
        "functional",
        "shift-and-add Boolean multiplier",
        "Partial products are accumulated with exact ripple-carry adders.",
    )

    def __init__(self, component) -> None:
        if not isinstance(component, ModularMultiply):
            raise TypeError("component must be a ModularMultiply")
        width = component.output_type.domain.width
        if component.modulus != 1 << width:
            raise NotImplementedError(
                "functional SAT multiplication currently requires modulus 2**word_width"
            )
        self.component = component

    @staticmethod
    def _auxiliary_word(context, prefix, width):
        return tuple(context.allocate(f"{prefix}_{bit}") for bit in range(width))

    @staticmethod
    def _add(context, left, right, target, prefix, label, record_target) -> None:
        carry = None
        width = len(target)
        for bit in range(width - 1, -1, -1):
            if carry is None:
                context.xor(target[bit], left[bit], right[bit], label)
                if record_target:
                    context.auxiliary.append(("xor", (target[bit], left[bit], right[bit])))
            else:
                partial = context.allocate(f"{prefix}_xor_{bit}")
                context.xor(partial, left[bit], right[bit], label)
                context.xor(target[bit], partial, carry, label)
                context.auxiliary.append(("xor", (partial, left[bit], right[bit])))
                if record_target:
                    context.auxiliary.append(("xor", (target[bit], partial, carry)))
            if bit:
                next_carry = context.allocate(f"{prefix}_carry_{bit}")
                if carry is None:
                    context.and_(next_carry, left[bit], right[bit], label)
                    context.auxiliary.append(("and", (next_carry, left[bit], right[bit])))
                else:
                    context.majority(next_carry, left[bit], right[bit], carry, label)
                    context.auxiliary.append(
                        ("majority", (next_carry, left[bit], right[bit], carry))
                    )
                carry = next_carry

    def _multiply(self, context, left, right, target, prefix, label, target_is_output):
        width = len(target)
        rows = []
        for shift, selector in enumerate(reversed(right)):
            is_only_row = width == 1
            row = (
                target
                if is_only_row and target_is_output
                else self._auxiliary_word(context, f"{prefix}_partial_{shift}", width)
            )
            for output_bit, row_bit in enumerate(row):
                source = output_bit + shift
                if source < width:
                    context.and_(row_bit, left[source], selector, label)
                    if not (is_only_row and target_is_output):
                        context.auxiliary.append(("and", (row_bit, left[source], selector)))
                else:
                    context.add_clause((-context.indices[row_bit],), label)
                    context.auxiliary.append(("zero", (row_bit,)))
            rows.append(row)

        accumulator = rows[0]
        for row_number, row in enumerate(rows[1:], start=1):
            is_last_row = row_number == len(rows) - 1
            add_target = (
                target
                if is_last_row
                else self._auxiliary_word(context, f"{prefix}_sum_{row_number}", width)
            )
            self._add(
                context,
                accumulator,
                row,
                add_target,
                f"{prefix}_add_{row_number}",
                label,
                record_target=not (is_last_row and target_is_output),
            )
            accumulator = add_target
        return accumulator

    def encode(self, context, outputs, selected) -> None:
        """Append a sequential multiplier for every output word."""

        label = self.component.component_id
        width = self.component.output_type.domain.width
        for position, output in enumerate(outputs):
            accumulator = selected[0][position]
            for operand_number, operand in enumerate(
                (group[position] for group in selected[1:]), start=1
            ):
                is_last = operand_number == len(selected) - 1
                target = (
                    output
                    if is_last
                    else self._auxiliary_word(
                        context, f"__aux_{label}_{position}_product_{operand_number}", width
                    )
                )
                accumulator = self._multiply(
                    context,
                    accumulator,
                    operand,
                    target,
                    f"__aux_{label}_{position}_{operand_number}",
                    label,
                    target_is_output=is_last,
                )


class ModularMultiplyNativeXorSATModel(ModularMultiplyFunctionalSATModel):
    """Use native parity records inside the shift-and-add multiplier.

    EXAMPLES::

        >>> ModularMultiplyNativeXorSATModel.model_provenance.encoding_name
        'shift-and-add with CryptoMiniSat native XOR records'
    """

    model_provenance = _direct_model(
        ConstraintBackend.SAT,
        "ModularMultiplyNativeXorSATModel",
        "functional",
        "shift-and-add with CryptoMiniSat native XOR records",
        "Adder parity is native XOR; product and carry constraints remain ordinary CNF.",
    )


__all__ = ["ModularMultiplyFunctionalSATModel", "ModularMultiplyNativeXorSATModel"]
