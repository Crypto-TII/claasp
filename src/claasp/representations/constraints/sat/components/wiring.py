"""Functional SAT encodings for constants and structural wiring."""

from claasp.components import Constant, Identity, Permutation, Rotate, Shift
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
