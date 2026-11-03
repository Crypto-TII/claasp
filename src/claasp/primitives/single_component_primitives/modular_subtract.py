"""Single-component modular-subtraction primitive implementation."""

from claasp.components import Constant
from claasp.components import ModularAdd as ModularAddComponent
from claasp.components import ModularSubtract as ModularSubtractComponent
from claasp.graph import Primitive, PrimitiveKind, UnitArrayType
from claasp.unit_types import Bit, Word

from ._base import word_inputs


class ModularSubtract(Primitive):
    """Subtract fixed-width words modulo a power of two.

    The default width is four bits, so ``3 - 5 = -2`` wraps modulo 16.

    >>> ModularSubtract().evaluate(3, 5)
    14

    >>> three_way = ModularSubtract(word_bit_size=8, number_of_inputs=3)
    >>> three_way.evaluate(20, 7, 2)
    11


    Explicit moduli use a widened composite so subtraction cannot wrap before
    reduction.

    >>> ModularSubtract(4, modulus=13).evaluate(1, 15)
    12

    EXAMPLES::

        >>> primitive = ModularSubtract()
        >>> inputs = {name: 0 for name in primitive.graph.input_arrays}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x0', 0)
    """

    def __init__(
        self, word_bit_size: int = 4, number_of_inputs: int = 2, *, modulus: int | None = None
    ) -> None:
        super().__init__(
            "modsub",
            word_inputs(word_bit_size, number_of_inputs),
            kind=PrimitiveKind.FUNCTION,
        )
        self._builder.add_round()
        operands = self.graph.inputs()
        if modulus is not None and (
            not isinstance(modulus, int)
            or isinstance(modulus, bool)
            or not 1 < modulus <= 1 << word_bit_size
        ):
            raise ValueError("modulus must be an integer in (1, 2^width]")
        if modulus is None or modulus == 1 << word_bit_size:
            output = self._builder.add_component(ModularSubtractComponent(operands))
        else:
            zero = self._builder.add_component(
                Constant(UnitArrayType(Word(word_bit_size), (1,)), (0,))
            )
            # Validate and reduce before negating in a wider word. No unsigned
            # overflow may happen before the explicit modulus is applied.
            reduced = [
                self._builder.add_component(ModularAddComponent((value, zero), modulus=modulus))
                for value in operands
            ]
            leading_zero = self._builder.add_component(Constant(UnitArrayType(Bit(), (1,)), (0,)))

            def widen(value):
                return self._builder.pack_bits(
                    self._builder.join(leading_zero, self._builder.unpack_bits(value)),
                    word_bit_size + 1,
                )

            value = widen(reduced[0])
            constant = self._builder.add_component(
                Constant(UnitArrayType(Word(word_bit_size + 1), (1,)), (modulus,))
            )
            for operand in reduced[1:]:
                negative = self._builder.add_component(
                    ModularSubtractComponent((constant, widen(operand)))
                )
                value = self._builder.add_component(
                    ModularAddComponent((value, negative), modulus=modulus)
                )
            output = self._builder.pack_bits(self._builder.unpack_bits(value)[1:], word_bit_size)
        self._builder.set_output(output)


__all__ = ["ModularSubtract"]
