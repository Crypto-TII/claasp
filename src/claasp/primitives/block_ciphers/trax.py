"""TRAX-L tweakable ARX primitive."""

from claasp.graph import Primitive

from ._word_graph import add, concatenate, constant, rotate, select, shift, word_type, xor

ALZETTE_ROTATIONS = ((31, 24), (17, 17), (0, 31), (24, 16))
ROUND_CONSTANTS = (
    0xB7E15162,
    0xBF715880,
    0x38B4DA56,
    0x324E7738,
    0xBB1185EB,
    0x4F7C7B57,
    0xCFBFA1C8,
    0xC2B3293D,
)


class TRAX(Primitive):
    """TRAX-L with a configurable number of Alzette steps.

    EXAMPLES::

        >>> primitive = TRAX()
        >>> inputs = {name: 0 for name in primitive.graph.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x76e1920dad2b0f28', 255)
    """

    def __init__(self, number_of_rounds=17):
        if number_of_rounds <= 0:
            raise ValueError("number_of_rounds must be positive")
        super().__init__(
            "trax",
            {"plaintext": word_type(32, 8), "key": word_type(32, 8), "tweak": word_type(32, 4)},
        )
        state_x = [select(self.graph.input("plaintext"), 2 * i) for i in range(4)]
        state_y = [select(self.graph.input("plaintext"), 2 * i + 1) for i in range(4)]
        key = [select(self.graph.input("key"), i) for i in range(8)]
        tweak = [select(self.graph.input("tweak"), i) for i in range(4)]

        def update_key(values, step):
            k = list(values)
            k0 = add(self, k[0], k[1], constant(self, 32, ROUND_CONSTANTS[(2 * step) % 8]))
            k2 = xor(self, k[2], k[3], constant(self, 32, step))
            k4 = add(self, k[4], k[5], constant(self, 32, ROUND_CONSTANTS[(2 * step + 1) % 8]))
            k6 = xor(self, k[6], k[7], constant(self, 32, (step << 16) & 0xFFFFFFFF))
            return [k[1], k2, k[3], k4, k[5], k6, k[7], k0]

        def alzette(x, y, instance):
            ci = constant(self, 32, instance)
            for ry, rx in ALZETTE_ROTATIONS:
                x = add(self, x, y if ry == 0 else rotate(self, y, ry))
                y = xor(self, y, rotate(self, x, rx))
                x = xor(self, x, ci)
            return x, y

        def ell(value):
            return rotate(self, xor(self, value, shift(self, value, -16)), 16)

        def linear(xs, ys):
            xs, ys = list(xs), list(ys)
            tx = ell(xor(self, xs[2], xs[3]))
            ys[0] = xor(self, ys[0], tx)
            ys[1] = xor(self, ys[1], tx)
            ty = ell(xor(self, ys[2], ys[3]))
            xs[0] = xor(self, xs[0], ty)
            xs[1] = xor(self, xs[1], ty)
            return [xs[3], xs[2], xs[0], xs[1]], [ys[3], ys[2], ys[0], ys[1]]

        for step_number in range(number_of_rounds):
            self._builder.add_round()
            subkey = list(key)
            key = update_key(key, step_number)
            if step_number % 2:
                for branch in range(2):
                    state_x[branch] = xor(self, state_x[branch], tweak[2 * branch])
                    state_y[branch] = xor(self, state_y[branch], tweak[2 * branch + 1])
            for branch in range(4):
                state_x[branch] = xor(self, state_x[branch], subkey[2 * branch])
                state_y[branch] = xor(self, state_y[branch], subkey[2 * branch + 1])
                state_x[branch], state_y[branch] = alzette(
                    state_x[branch],
                    state_y[branch],
                    ROUND_CONSTANTS[(4 * step_number + branch) % 8],
                )
            state_x, state_y = linear(state_x, state_y)
        output = []
        for branch in range(4):
            output.extend(
                (
                    xor(self, state_x[branch], key[2 * branch]),
                    xor(self, state_y[branch], key[2 * branch + 1]),
                )
            )
        self._builder.set_output(concatenate(self, *output))
