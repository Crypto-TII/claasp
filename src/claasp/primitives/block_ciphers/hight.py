"""HIGHT lightweight block primitive."""

from claasp.graph import Primitive

from ._word_graph import add, concatenate, constant, rotate, select, word_type, xor

DELTA = (
    0x5A,
    0x6D,
    0x36,
    0x1B,
    0x0D,
    0x06,
    0x03,
    0x41,
    0x60,
    0x30,
    0x18,
    0x4C,
    0x66,
    0x33,
    0x59,
    0x2C,
    0x56,
    0x2B,
    0x15,
    0x4A,
    0x65,
    0x72,
    0x39,
    0x1C,
    0x4E,
    0x67,
    0x73,
    0x79,
    0x3C,
    0x5E,
    0x6F,
    0x37,
    0x5B,
    0x2D,
    0x16,
    0x0B,
    0x05,
    0x42,
    0x21,
    0x50,
    0x28,
    0x54,
    0x2A,
    0x55,
    0x6A,
    0x75,
    0x7A,
    0x7D,
    0x3E,
    0x5F,
    0x2F,
    0x17,
    0x4B,
    0x25,
    0x52,
    0x29,
    0x14,
    0x0A,
    0x45,
    0x62,
    0x31,
    0x58,
    0x6C,
    0x76,
    0x3B,
    0x1D,
    0x0E,
    0x47,
    0x63,
    0x71,
    0x78,
    0x7C,
    0x7E,
    0x7F,
    0x3F,
    0x1F,
    0x0F,
    0x07,
    0x43,
    0x61,
    0x70,
    0x38,
    0x5C,
    0x6E,
    0x77,
    0x7B,
    0x3D,
    0x1E,
    0x4F,
    0x27,
    0x53,
    0x69,
    0x34,
    0x1A,
    0x4D,
    0x26,
    0x13,
    0x49,
    0x24,
    0x12,
    0x09,
    0x04,
    0x02,
    0x01,
    0x40,
    0x20,
    0x10,
    0x08,
    0x44,
    0x22,
    0x11,
    0x48,
    0x64,
    0x32,
    0x19,
    0x0C,
    0x46,
    0x23,
    0x51,
    0x68,
    0x74,
    0x3A,
    0x5D,
    0x2E,
    0x57,
    0x6B,
    0x35,
    0x5A,
)


class HIGHT(Primitive):
    """HIGHT with optional whitening transformations and zeroed deltas.

    EXAMPLES::

        >>> primitive = HIGHT()
        >>> inputs = {name: 0 for name in primitive.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x56a0f08c3c5ecb3c', 63)
    """

    def __init__(
        self,
        block_bit_size=64,
        key_bit_size=128,
        number_of_rounds=None,
        sub_keys_zero=False,
        transformations_flag=True,
    ):
        if (block_bit_size, key_bit_size) != (64, 128):
            raise ValueError("HIGHT has a 64-bit block and 128-bit key")
        rounds = 32 if number_of_rounds is None else number_of_rounds
        if not 1 <= rounds <= 32:
            raise ValueError("HIGHT number_of_rounds must be between 1 and 32")
        super().__init__("hight", {"plaintext": word_type(8, 8), "key": word_type(8, 16)})
        state = [select(self.input("plaintext"), index) for index in range(8)]
        master = [select(self.input("key"), index) for index in range(16)]
        reversed_key = list(reversed(master))
        whitening = [
            reversed_key[index + 12] if index < 4 else reversed_key[index - 4] for index in range(8)
        ]
        temporary = []
        for i in range(8):
            for j in range(8):
                temporary.append((reversed_key[(j - i) % 8], DELTA[16 * i + j]))
            for j in range(8):
                temporary.append((reversed_key[((j - i) % 8) + 8], DELTA[16 * i + j + 8]))

        def initial(values):
            p = list(reversed(values))
            transformed = [
                add(self, p[0], whitening[0]),
                p[1],
                xor(self, p[2], whitening[1]),
                p[3],
                add(self, p[4], whitening[2]),
                p[5],
                xor(self, p[6], whitening[3]),
                p[7],
            ]
            return list(reversed(transformed))

        def final(values):
            p = list(reversed(values))
            transformed = [
                add(self, p[1], whitening[4]),
                p[2],
                xor(self, p[3], whitening[5]),
                p[4],
                add(self, p[5], whitening[6]),
                p[6],
                xor(self, p[7], whitening[7]),
                p[0],
            ]
            return list(reversed(transformed))

        def f0(value):
            return xor(
                self, rotate(self, value, -1), rotate(self, value, -2), rotate(self, value, -7)
            )

        def f1(value):
            return xor(
                self, rotate(self, value, -3), rotate(self, value, -4), rotate(self, value, -6)
            )

        for round_number in range(rounds):
            self._builder.add_round()
            if round_number == 0 and transformations_flag:
                state = initial(state)
            entries = temporary[4 * round_number : 4 * round_number + 4]
            if sub_keys_zero:
                round_key = [entries[0][0], entries[1][0], entries[2][0], entries[1][0]]
            else:
                round_key = [
                    add(self, key_word, constant(self, 8, delta)) for key_word, delta in entries
                ]
            state = [
                state[1],
                add(self, state[2], xor(self, f1(state[3]), round_key[2])),
                state[3],
                xor(self, state[4], add(self, f0(state[5]), round_key[1])),
                state[5],
                add(self, state[6], xor(self, f1(state[7]), round_key[0])),
                state[7],
                xor(self, state[0], add(self, f0(state[1]), round_key[3])),
            ]
            if round_number == rounds - 1 and transformations_flag:
                state = final(state)
        self._builder.set_output(concatenate(self, *state))
