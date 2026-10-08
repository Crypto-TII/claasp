"""Functional SAT encodings for constants and structural wiring."""

from claasp.components import (
    Constant,
    Identity,
    Permutation,
    Rotate,
    Shift,
    VariableRotate,
    VariableShift,
)
from claasp.representations.constraints import ConstraintBackend, _direct_model
from claasp.representations.constraints.sat.encoding import encode_unit


class WiringFunctionalSATModel:
    """Encode one functional constant or wiring component.

    EXAMPLES::

        >>> from claasp.components import Permutation
        >>> from claasp.primitives import Present80
        >>> from claasp.representations.constraints.sat import BooleanCNFModel
        >>> primitive = Present80(number_of_rounds=1)
        >>> component = next(item for item in primitive.components if isinstance(item, Permutation))
        >>> encoding = WiringFunctionalSATModel(component)
        >>> formula = BooleanCNFModel(primitive).cnf_formula()
        >>> encoding.component.component_id in formula.provenance
        True
    """

    model_provenance = _direct_model(
        ConstraintBackend.SAT,
        "WiringFunctionalSATModel",
        "functional",
        "direct equality and constant clauses",
        "The encoding follows the graph wiring definition directly.",
    )

    def __init__(self, component) -> None:
        if not isinstance(component, (Constant, Identity, Permutation, Rotate, Shift)):
            raise TypeError("component must be a constant or wiring component")
        self.component = component

    def encode(self, context, outputs, selected) -> None:
        """Append the component's functional clauses to ``context``."""

        component = self.component
        label = component.component_id
        if isinstance(component, Constant):
            for output, value in zip(outputs, component.values):
                for bit_name, bit in zip(output, encode_unit(value, component.output_type)):
                    context.add_clause(
                        ((context.indices[bit_name] if bit else -context.indices[bit_name]),), label
                    )
        elif isinstance(component, Identity):
            for output, input_ in zip(outputs, selected[0]):
                for output_bit, input_bit in zip(output, input_):
                    context.equal(output_bit, input_bit, label)
        elif isinstance(component, Permutation):
            for output, position in zip(outputs, component.mapping):
                for output_bit, input_bit in zip(output, selected[0][position]):
                    context.equal(output_bit, input_bit, label)
        elif isinstance(component, Rotate):
            width = component.output_type.domain.width
            offset = component.amount if component.direction == "left" else -component.amount
            for output, input_ in zip(outputs, selected[0]):
                for bit, output_bit in enumerate(output):
                    context.equal(output_bit, input_[(bit + offset) % width], label)
        else:
            width = component.output_type.domain.width
            offset = component.amount if component.direction == "left" else -component.amount
            for output, input_ in zip(outputs, selected[0]):
                for bit, output_bit in enumerate(output):
                    source = bit + offset
                    if 0 <= source < width:
                        context.equal(output_bit, input_[source], label)
                    else:
                        context.add_clause((-context.indices[output_bit],), label)


class VariableWiringFunctionalSATModel:
    """Encode data-dependent word shifts and rotations as barrel networks.

    EXAMPLES::

        >>> from claasp.primitives.single_component_primitives import VariableRotate
        >>> from claasp.representations.constraints.sat import BooleanCNFModel
        >>> primitive = VariableRotate(bit_size=4, amount_bit_size=2)
        >>> model = BooleanCNFModel(primitive)
        >>> model.cnf_formula().is_satisfied(
        ...     model.witness(primitive.evaluate_with_trace(9, 1)))
        True
    """

    model_provenance = _direct_model(
        ConstraintBackend.SAT,
        "VariableWiringFunctionalSATModel",
        "functional",
        "Boolean variable shift/rotation network",
        "Rotation uses barrel stages; shift tracks the exact modulo-width amount.",
    )

    def __init__(self, component) -> None:
        if not isinstance(component, (VariableRotate, VariableShift)):
            raise TypeError("component must be a VariableRotate or VariableShift")
        self.component = component

    def encode(self, context, outputs, selected) -> None:
        """Append an exact rotation barrel or modulo-width shift network."""

        component = self.component
        label = component.component_id
        width = component.output_type.domain.width
        amount = selected[1][0]
        if isinstance(component, VariableShift):
            self._encode_shift(context, outputs, selected[0], amount, label, width)
            return
        for position, output in enumerate(outputs):
            accumulator = selected[0][position]
            for stage, selector in enumerate(amount):
                distance = 1 << (len(amount) - stage - 1)
                offset = distance if component.direction == "left" else -distance
                is_last = stage == len(amount) - 1
                target = (
                    output
                    if is_last
                    else tuple(
                        context.allocate(f"__aux_{label}_{position}_{stage}_{bit}")
                        for bit in range(width)
                    )
                )
                for bit, output_bit in enumerate(target):
                    source = bit + offset
                    shifted = accumulator[source % width]
                    context.relation(
                        output_bit,
                        (selector, accumulator[bit], shifted),
                        lambda choose, direct, alternate: alternate if choose else direct,
                        label,
                    )
                    if not is_last:
                        context.auxiliary.append(
                            ("mux", (output_bit, selector, accumulator[bit], shifted))
                        )
                accumulator = target

    def _encode_shift(self, context, outputs, inputs, amount, label, width) -> None:
        """Encode CLAASP's modulo-width variable-shift amount exactly."""

        states = None
        for stage, selector in enumerate(amount):
            next_states = tuple(
                context.allocate(f"__aux_{label}_remainder_{stage}_{remainder}")
                for remainder in range(width)
            )
            context.add_clause(tuple(context.indices[item] for item in next_states), label)
            for left in range(width):
                for right in range(left + 1, width):
                    context.add_clause(
                        (-context.indices[next_states[left]], -context.indices[next_states[right]]),
                        label,
                    )
            if states is None:
                zero_target = next_states[0]
                one_target = next_states[1 % width]
                context.add_clause((context.indices[selector], context.indices[zero_target]), label)
                context.add_clause((-context.indices[selector], context.indices[one_target]), label)
            else:
                for remainder, state in enumerate(states):
                    zero_target = next_states[(2 * remainder) % width]
                    one_target = next_states[(2 * remainder + 1) % width]
                    context.add_clause(
                        (
                            -context.indices[state],
                            context.indices[selector],
                            context.indices[zero_target],
                        ),
                        label,
                    )
                    context.add_clause(
                        (
                            -context.indices[state],
                            -context.indices[selector],
                            context.indices[one_target],
                        ),
                        label,
                    )
            prefix = amount[: stage + 1]
            for remainder, state in enumerate(next_states):
                context.auxiliary.append((f"prefix_mod:{remainder}:{width}", (state, *prefix)))
            states = next_states

        for output, input_ in zip(outputs, inputs):
            for bit, output_bit in enumerate(output):
                for remainder, state in enumerate(states):
                    offset = remainder if self.component.direction == "left" else -remainder
                    source = bit + offset
                    if 0 <= source < width:
                        input_bit = input_[source]
                        context.add_clause(
                            (
                                -context.indices[state],
                                -context.indices[input_bit],
                                context.indices[output_bit],
                            ),
                            label,
                        )
                        context.add_clause(
                            (
                                -context.indices[state],
                                context.indices[input_bit],
                                -context.indices[output_bit],
                            ),
                            label,
                        )
                    else:
                        context.add_clause(
                            (-context.indices[state], -context.indices[output_bit]), label
                        )


__all__ = ["VariableWiringFunctionalSATModel", "WiringFunctionalSATModel"]
