"""Functional SAT encoding for bit-vector S-boxes."""

from claasp.components import BitVectorSBox
from claasp.representations.constraints import ConstraintBackend, _direct_model


class SBoxFunctionalSATModel:
    """Encode the exact input/output function of one bit-vector S-box.

    EXAMPLES::

        >>> from claasp.components import BitVectorSBox
        >>> from claasp.primitives import Present80
        >>> from claasp.representations.constraints.sat import BooleanCNFModel
        >>> primitive = Present80(number_of_rounds=1)
        >>> component = next(item for item in primitive.components if isinstance(item, BitVectorSBox))
        >>> encoding = SBoxFunctionalSATModel(component)
        >>> formula = BooleanCNFModel(primitive).cnf_formula()
        >>> encoding.component.component_id in formula.provenance
        True
    """

    model_provenance = _direct_model(
        ConstraintBackend.SAT,
        "SBoxFunctionalSATModel",
        "functional",
        "exhaustive truth-table implication clauses",
        "The clauses are generated exhaustively from the supplied lookup table.",
    )

    def __init__(self, component) -> None:
        if not isinstance(component, BitVectorSBox):
            raise TypeError("component must be a BitVectorSBox")
        self.component = component

    def encode(self, context, outputs, selected) -> None:
        """Append the component's functional clauses to ``context``."""

        component = self.component
        label = component.component_id
        inputs = [group[0] for group in selected[0]]
        output_bits = [group[0] for group in outputs]
        input_width = len(inputs)
        output_width = len(output_bits)
        for input_value, output_value in enumerate(component.table):
            antecedent = tuple(
                -context.indices[name]
                if (input_value >> (input_width - 1 - i)) & 1
                else context.indices[name]
                for i, name in enumerate(inputs)
            )
            for i, output in enumerate(output_bits):
                expected = (output_value >> (output_width - 1 - i)) & 1
                literal = context.indices[output] if expected else -context.indices[output]
                context.add_clause(antecedent + (literal,), label)
