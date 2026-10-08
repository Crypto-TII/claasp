"""Generic component semantics for Boolean monomial trails."""

from claasp.components import Add, BitVectorSBox, Constant, Identity, Permutation
from claasp.domains import Bit
from claasp.representations.constraints.polynomial import monomial_transition_table


class ComponentMonomialSemantics:
    """Check exact local 3SDP-woU transitions selected by component type.

    Masks are MSB-first exponent vectors encoded as integers. The relation is
    deliberately local and dependency-free, allowing graph composers and
    solver representations to share the same checker.

    EXAMPLES::

        >>> from claasp import Bit, Primitive, ValueType
        >>> from claasp.components import Identity
        >>> from claasp.semantics.cryptanalysis import ComponentMonomialSemantics
        >>> graph = Primitive("identity", {"x": ValueType(Bit(), (2,))})
        >>> component = Identity(graph.graph.input("x"))
        >>> ComponentMonomialSemantics.is_possible(component, (0b10,), 0b10)
        True
    """

    @staticmethod
    def is_possible(component, input_masks: tuple[int, ...], output_mask: int) -> bool:
        """Return whether a local component monomial transition is possible.

        EXAMPLES::

            >>> from claasp import Bit, Primitive, ValueType
            >>> from claasp.components import Identity
            >>> from claasp.semantics.cryptanalysis import ComponentMonomialSemantics
            >>> graph = Primitive("identity", {"x": ValueType(Bit(), (1,))})
            >>> ComponentMonomialSemantics.is_possible(Identity(graph.graph.input("x")), (1,), 1)
            True
        """

        if not isinstance(component.output_type.domain, Bit):
            raise TypeError("Boolean monomial semantics currently require the Bit domain")
        output_width = component.output_type.unit_count
        ComponentMonomialSemantics._mask(output_mask, output_width, "output_mask")
        if len(input_masks) != len(component.inputs):
            raise ValueError("one input mask is required for each component input")
        for index, (mask, selection) in enumerate(zip(input_masks, component.inputs)):
            ComponentMonomialSemantics._mask(
                mask, selection.value_type.unit_count, f"input_masks[{index}]"
            )

        if isinstance(component, BitVectorSBox):
            return input_masks[0] in monomial_transition_table(component.table)[output_mask]
        if isinstance(component, Identity):
            return input_masks == (output_mask,)
        if isinstance(component, Permutation):
            return input_masks == (
                ComponentMonomialSemantics._permutation_input(component, output_mask),
            )
        if isinstance(component, Add):
            # Over GF(2), each selected output variable chooses exactly one of
            # the corresponding operand variables. Input masks form a disjoint
            # partition of the output mask.
            union = 0
            for mask in input_masks:
                if union & mask:
                    return False
                union |= mask
            return union == output_mask
        if isinstance(component, Constant):
            selected_positions = (
                index
                for index in range(output_width)
                if output_mask & (1 << (output_width - 1 - index))
            )
            return all(component.values[index] == 1 for index in selected_positions)
        raise NotImplementedError(f"no monomial semantics for {type(component).__name__}")

    @staticmethod
    def _permutation_input(component: Permutation, output_mask: int) -> int:
        width = component.output_type.unit_count
        result = 0
        for output_position, input_position in enumerate(component.mapping):
            if output_mask & (1 << (width - 1 - output_position)):
                result |= 1 << (width - 1 - input_position)
        return result

    @staticmethod
    def _mask(value: int, width: int, name: str) -> None:
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 1 << width:
            raise ValueError(f"{name} must fit its {width}-bit exponent vector")
