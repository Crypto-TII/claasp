"""Canonical Aradi block primitive."""

from claasp.graph import Primitive

from .._word_graph import bit_and, concatenate, constant, rotate, select, split_word, word_type, xor


class Aradi(Primitive):
    """The 128-bit Aradi primitive with a 256-bit key.

    EXAMPLES::

        >>> primitive = Aradi()
        >>> inputs = {name: 0 for name in primitive.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0xd06c8ab75d191521', 128)
    """

    def __init__(self, number_of_rounds=16):
        super().__init__("aradi", {"plaintext": word_type(16, 8), "key": word_type(32, 8)})
        state = [self.input("plaintext")[2 * index : 2 * index + 2] for index in range(4)]
        key = [select(self.input("key"), 7 - index) for index in range(8)]
        a_values, b_values, c_values = (11, 10, 9, 8), (8, 9, 4, 9), (14, 11, 14, 7)

        def linear(value, round_number):
            left, right = select(value, 0), select(value, 1)
            index = round_number % 4
            return concatenate(
                self,
                xor(
                    self,
                    left,
                    rotate(self, left, -a_values[index]),
                    rotate(self, right, -c_values[index]),
                ),
                xor(
                    self,
                    right,
                    rotate(self, right, -a_values[index]),
                    rotate(self, left, -b_values[index]),
                ),
            )

        def m_function(x, y, first, second):
            rotated_y = rotate(self, y, -first)
            return xor(self, x, rotated_y, rotate(self, x, -second)), xor(self, x, rotated_y)

        for round_number in range(number_of_rounds):
            self._builder.add_round()
            offset = 4 * (round_number % 2)
            round_key = [split_word(self, key[offset + index], 16) for index in range(4)]
            state = [xor(self, value, round_key[index]) for index, value in enumerate(state)]
            w, x, y, z = state
            x = xor(self, x, bit_and(self, w, y))
            z = xor(self, z, bit_and(self, x, y))
            y = xor(self, y, bit_and(self, w, z))
            w = xor(self, w, bit_and(self, x, z))
            state = [linear(value, round_number) for value in (w, x, y, z)]

            k1, k0 = m_function(key[1], key[0], 1, 3)
            k3, k2 = m_function(key[3], key[2], 9, 28)
            k5, k4 = m_function(key[5], key[4], 1, 3)
            k7, k6 = m_function(key[7], key[6], 9, 28)
            k7 = xor(self, k7, constant(self, 32, round_number))
            key = (
                [k0, k2, k1, k3, k4, k6, k5, k7]
                if round_number % 2 == 0
                else [k0, k4, k2, k6, k1, k5, k3, k7]
            )
        final_key = [split_word(self, key[index], 16) for index in range(4)]
        state = [xor(self, value, final_key[index]) for index, value in enumerate(state)]
        self._builder.set_output(concatenate(self, *state))
