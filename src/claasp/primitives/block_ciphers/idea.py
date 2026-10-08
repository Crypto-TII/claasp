"""International Data Encryption Algorithm (IDEA)."""

from claasp.components import Permutation
from claasp.domains import Bit
from claasp.graph import Primitive, ValueType

from ._word_graph import add, concatenate, idea_multiply, select, word_type, xor


class IDEA(Primitive):
    """IDEA with its 128-bit rotating key schedule.

    EXAMPLES::

        >>> primitive = IDEA()
        >>> inputs = {name: 0 for name in primitive.graph.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x1000100000000', 49)
    """

    def __init__(self, number_of_rounds=8):
        if not isinstance(number_of_rounds, int) or not 1 <= number_of_rounds <= 8:
            raise ValueError("IDEA number_of_rounds must be between 1 and 8")
        super().__init__(
            "idea",
            {
                "plaintext": word_type(16, 4),
                "key": ValueType(Bit(), (128,)),
            },
        )
        self._builder.add_round()
        key_state = self.graph.input("key").select_all()
        subkeys = []
        needed = 6 * number_of_rounds + 4
        while len(subkeys) < needed:
            for index in range(8):
                if len(subkeys) == needed:
                    break
                bits = key_state[tuple(range(16 * index, 16 * (index + 1)))]
                subkeys.append(self._builder.pack_bits(bits, 16))
            if len(subkeys) < needed:
                mapping = tuple((index + 25) % 128 for index in range(128))
                key_state = self._builder.add_component(Permutation(key_state, mapping))
        state = [select(self.graph.input("plaintext"), index) for index in range(4)]
        for round_number in range(number_of_rounds):
            self._builder.add_round()
            k1, k2, k3, k4, k5, k6 = subkeys[6 * round_number : 6 * (round_number + 1)]
            y1 = idea_multiply(self, state[0], k1)
            y2 = add(self, state[1], k2)
            y3 = add(self, state[2], k3)
            y4 = idea_multiply(self, state[3], k4)
            t2 = idea_multiply(self, xor(self, y1, y3), k5)
            t4 = idea_multiply(self, add(self, xor(self, y2, y4), t2), k6)
            t5 = add(self, t2, t4)
            out1, out2 = xor(self, y1, t4), xor(self, y2, t5)
            out3, out4 = xor(self, y3, t4), xor(self, y4, t5)
            state = (
                [out1, out2, out3, out4]
                if round_number == number_of_rounds - 1
                else [out1, out3, out2, out4]
            )
        self._builder.add_round()
        final = subkeys[6 * number_of_rounds :]
        state = [
            idea_multiply(self, state[0], final[0]),
            add(self, state[1], final[1]),
            add(self, state[2], final[2]),
            idea_multiply(self, state[3], final[3]),
        ]
        self._builder.set_output(concatenate(self, *state))
