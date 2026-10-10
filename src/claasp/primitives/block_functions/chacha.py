"""The fixed-length ChaCha keystream block function."""

from claasp.components import Constant, ModularAdd, Rotate, Xor
from claasp.domains import Bit
from claasp.encoding import bits_from_int
from claasp.graph import ArrayType, Primitive

ROUND_MODE_HALF = "half"
ROUND_MODE_SINGLE = "single"
PARAMETERS_CONFIGURATION_LIST = (
    {"block_bit_size": 512, "key_bit_size": 256, "number_of_rounds": 20},
)
_COLUMNS = ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15))
_DIAGONALS = ((0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14))


def _little_endian_word_positions(word: int) -> tuple[int, ...]:
    start = word * 32
    return tuple(start + byte * 8 + bit for byte in (3, 2, 1, 0) for bit in range(8))


class ChaChaKeystreamBlock(Primitive):
    """Build one ChaCha block from key, nonce, and an explicit block counter.

    The retained fixed-length mapping permutes ``plaintext`` and then adds the
    constants/key/counter/nonce state word by word, matching the historical
    CLAASP block-function interface.


    EXAMPLES::

        >>> primitive = ChaChaKeystreamBlock()
        >>> inputs = {name: 0 for name in primitive.graph.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x617078653320646e', 511)
    """

    def __init__(
        self,
        block_bit_size=512,
        key_bit_size=256,
        number_of_rounds=20,
        block_count=1,
        chacha_constants=0x617078653320646E79622D326B206574,
        round_mode=ROUND_MODE_SINGLE,
    ) -> None:
        if block_bit_size != 512 or key_bit_size != 256:
            raise ValueError("ChaCha requires a 512-bit block and 256-bit key")
        if round_mode not in {ROUND_MODE_SINGLE, ROUND_MODE_HALF}:
            raise ValueError("round_mode must be 'single' or 'half'")
        half_rounds = number_of_rounds * 2 if round_mode == ROUND_MODE_SINGLE else number_of_rounds
        if not isinstance(half_rounds, int) or isinstance(half_rounds, bool) or half_rounds <= 0:
            raise ValueError("number_of_rounds must be positive")
        bit_vector = lambda width: ArrayType(Bit(), (width,))
        super().__init__(
            "chacha_stream_cipher",
            {"plaintext": bit_vector(512), "key": bit_vector(256), "nonce": bit_vector(96)},
            provenance=(("identity", "ChaCha keystream block"),),
        )
        self._builder.add_round()
        constant_bits = self._builder.add_component(
            Constant(
                bit_vector(128),
                bits_from_int(chacha_constants & ((1 << 128) - 1), 128),
                component_id="constants",
            )
        )
        counter_bits = self._builder.add_component(
            Constant(
                bit_vector(32),
                bits_from_int(block_count & 0xFFFFFFFF, 32),
                component_id="counter",
            )
        )
        initial_bits = [constant_bits[index * 32 : (index + 1) * 32] for index in range(4)]
        initial_bits += [
            self.graph.input("key")[_little_endian_word_positions(index)] for index in range(8)
        ]
        initial_bits.append(counter_bits)
        initial_bits += [
            self.graph.input("nonce")[_little_endian_word_positions(index)] for index in range(3)
        ]
        feed_forward = [self._builder.pack_bits(bits, 32) for bits in initial_bits]
        state = [
            self._builder.pack_bits(
                self.graph.input("plaintext")[index * 32 : (index + 1) * 32], 32
            )
            for index in range(16)
        ]
        for half_round in range(half_rounds):
            if half_round:
                self._builder.add_round()
            groups = _COLUMNS if (half_round // 2) % 2 == 0 else _DIAGONALS
            rotations = (16, 12) if half_round % 2 == 0 else (8, 7)
            for quarter, indexes in enumerate(groups):
                a, b, c, d = indexes
                state[a], state[b], state[c], state[d] = self._half_quarter_round(
                    state[a],
                    state[b],
                    state[c],
                    state[d],
                    rotations,
                    f"r{half_round}_q{quarter}",
                )
        self._builder.add_round()
        summed = [
            self._builder.add_component(
                ModularAdd((before, after), component_id=f"feed_forward_{index}")
            )
            for index, (before, after) in enumerate(zip(feed_forward, state))
        ]
        bits = [self._builder.unpack_bits(word) for word in summed]
        self._builder.set_output(bits)

    def _half_quarter_round(self, a, b, c, d, rotations, prefix):
        a = self._builder.add_component(ModularAdd((a, b), component_id=f"{prefix}_add0"))
        d = self._xor_rotate(d, a, rotations[0], f"{prefix}_dr0")
        c = self._builder.add_component(ModularAdd((c, d), component_id=f"{prefix}_add1"))
        b = self._xor_rotate(b, c, rotations[1], f"{prefix}_br0")
        return a, b, c, d

    def _xor_rotate(self, left, right, amount, component_id):
        mixed = self._builder.add_component(Xor((left, right), component_id=f"{component_id}_xor"))
        return self._builder.add_component(Rotate(mixed, amount, "left", component_id=component_id))


__all__ = ["PARAMETERS_CONFIGURATION_LIST", "ChaChaKeystreamBlock"]
