"""NOEKEON, NESSIE proposal (2000), sections 3.2--3.7.

The packed state is a0 || a1 || a2 || a3, with big-endian 32-bit words.
The four-bit gamma lookup is indexed a3,a2,a1,a0 as in specification Table 1.
Reference: https://gro.noekeon.org/Noekeon-spec.pdf.
"""

from claasp.components import SBox
from claasp.graph import Primitive

from ._word_graph import concatenate, constant, rotate, word_type, xor

NOEKEON_SBOX = (7, 10, 2, 12, 4, 8, 15, 0, 5, 9, 1, 14, 3, 13, 11, 6)


PARAMETERS_CONFIGURATION_LIST = [
    {"number_of_rounds": 16, "key_mode": "direct"},
    {"number_of_rounds": 16, "key_mode": "indirect"},
]


class Noekeon(Primitive):
    """NOEKEON with direct or indirect keys and one to sixteen rounds.

    ``key_mode='indirect'`` derives the working key with the full sixteen-round
    zero-key NOEKEON instance, including when the data path is round-reduced. Reduced
    instances retain the final constant and theta output transformation.

    EXAMPLES::

        >>> hex(Noekeon().evaluate(plaintext=0, key=0))
        '0xb1656851699e29fa24b70148503d2dfc'
        >>> Noekeon(number_of_rounds=2).number_of_rounds
        2
        >>> Noekeon(key_mode='invalid')
        Traceback (most recent call last):
        ...
        ValueError: key_mode must be 'direct' or 'indirect'
    """

    def __init__(self, number_of_rounds: int = 16, *, key_mode: str = "direct") -> None:
        if type(number_of_rounds) is not int or not 1 <= number_of_rounds <= 16:
            raise ValueError("number_of_rounds must be an integer from 1 to 16")
        if key_mode not in ("direct", "indirect"):
            raise ValueError("key_mode must be 'direct' or 'indirect'")
        self.number_of_rounds = number_of_rounds
        self.key_mode = key_mode
        super().__init__(
            "noekeon",
            {"plaintext": word_type(32, 4), "key": word_type(32, 4)},
            provenance=(("reference", "https://gro.noekeon.org/Noekeon-spec.pdf"),),
        )
        key = self.graph.input("key")
        if key_mode == "indirect":
            self._builder.add_round()
            zero = constant(self, 32, 0)
            key = self._encrypt(key, (zero,) * 4, 16, record_rounds=False)
        state = self._encrypt(self.graph.input("plaintext"), key, number_of_rounds)
        self._builder.set_output(state)

    def _theta(self, state, key):
        a = [state[i] for i in range(4)]
        t = xor(self, a[0], a[2])
        t = xor(self, t, rotate(self, t, 8), rotate(self, t, -8))
        a[1], a[3] = xor(self, a[1], t), xor(self, a[3], t)
        a = [xor(self, a[i], key[i]) for i in range(4)]
        t = xor(self, a[1], a[3])
        t = xor(self, t, rotate(self, t, 8), rotate(self, t, -8))
        a[0], a[2] = xor(self, a[0], t), xor(self, a[2], t)
        return concatenate(self, *a)

    def _encrypt(self, state, key, rounds, *, record_rounds=True):
        rc = 0x80
        for r in range(rounds):
            if record_rounds and (r > 0 or self.key_mode == "direct"):
                self._builder.add_round()
            state = concatenate(
                self, xor(self, state[0], constant(self, 32, rc)), *[state[i] for i in range(1, 4)]
            )
            state = self._theta(state, key)
            state = concatenate(
                self, state[0], *[rotate(self, state[i], -s) for i, s in enumerate((1, 5, 2), 1)]
            )
            bits = self._builder.unpack_bits(state)
            mapping = tuple(w * 32 + j for j in range(32) for w in (3, 2, 1, 0))
            cells = self._builder.pack_bits(bits[mapping], 4)
            cells = self._builder.add_component(SBox(cells, NOEKEON_SBOX))
            bits = self._builder.unpack_bits(cells)
            inverse = tuple(mapping.index(i) for i in range(128))
            state = self._builder.pack_bits(bits[inverse], 32)
            state = concatenate(
                self, state[0], *[rotate(self, state[i], s) for i, s in enumerate((1, 5, 2), 1)]
            )
            rc = ((rc << 1) ^ (0x1B if rc & 0x80 else 0)) & 255
            if r == rounds - 1:
                state = concatenate(
                    self,
                    xor(self, state[0], constant(self, 32, rc)),
                    *[state[i] for i in range(1, 4)],
                )
                state = self._theta(state, key)
            if record_rounds:
                self._builder.set_round_output(state)
        return state


__all__ = ["Noekeon"]
