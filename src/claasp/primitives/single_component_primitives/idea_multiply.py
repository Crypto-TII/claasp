"""One-component IDEA zero-encoded multiplication primitive."""

from claasp.components import BitwiseAnd, BitwiseNot
from claasp.components import IDEAMultiply as IDEAMultiplyComponent
from claasp.components import ModularMultiply as ModularMultiplyComponent
from claasp.graph import Primitive, PrimitiveKind, as_selection

from ._base import word_inputs


class IDEAMultiply(Primitive):
    """Multiply words using IDEA's zero encoding.

    For four-bit words, encoded zero denotes 16; multiplication is modulo
    17, and a result of 16 is encoded back as zero. Thus ``0 * 2`` means
    ``16 * 2 mod 17``, which is 15.

    >>> IDEAMultiply(4).evaluate(0, 2)
    15

    >>> three_way = IDEAMultiply(word_bit_size=16, number_of_inputs=3)
    >>> three_way.evaluate(2, 3, 4)
    24


    Explicit smaller moduli retain the input zero encoding.

    >>> IDEAMultiply(4, modulus=13).evaluate(0, 2)
    6

    EXAMPLES::

        >>> primitive = IDEAMultiply()
        >>> inputs = {name: 0 for name in primitive.graph.input_arrays}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x1', 1)
    """

    def __init__(
        self, word_bit_size: int = 16, number_of_inputs: int = 2, *, modulus: int | None = None
    ) -> None:
        super().__init__(
            "idea_modmul",
            word_inputs(word_bit_size, number_of_inputs),
            kind=PrimitiveKind.FUNCTION,
        )
        self._builder.add_round()
        operands = self.graph.inputs()
        if modulus is not None and (
            not isinstance(modulus, int)
            or isinstance(modulus, bool)
            or not 1 < modulus <= (1 << word_bit_size) + 1
        ):
            raise ValueError("modulus must fit the zero-encoded output")
        if modulus is None or modulus == (1 << word_bit_size) + 1:
            output = self._builder.add_component(IDEAMultiplyComponent(operands))
        else:
            encoded = []
            for operand in operands:
                bits = self._builder.unpack_bits(operand)
                flags = self._builder.add_component(BitwiseNot(self._builder.pack_bits(bits, 1)))
                is_zero = flags[0]
                for index in range(1, word_bit_size):
                    is_zero = as_selection(
                        self._builder.add_component(BitwiseAnd((is_zero, flags[index])))
                    )
                widened = self._builder.join(self._builder.unpack_bits(is_zero), bits)
                encoded.append(self._builder.pack_bits(widened, word_bit_size + 1))
            value = self._builder.add_component(ModularMultiplyComponent(encoded, modulus=modulus))
            output = self._builder.pack_bits(self._builder.unpack_bits(value)[1:], word_bit_size)
        self._builder.set_output(output)


__all__ = ["IDEAMultiply"]
