"""PRIDE, CRYPTO 2014, doi:10.1007/978-3-662-44371-2_4.

The external packing is the designers' bitsliced representation; both boundary
permutations and the special last round are retained. The key is k0 || k1.
Reference: https://eprint.iacr.org/2014/453, sections 5.3--5.4, appendices G--J.
The numeric diffusion matrices are also independently transcribed in pypride
(Felix C. Stegerman, LGPLv3+, https://github.com/obfusk/pypride).
"""

from claasp.components import Constant, LinearMap, ModularAdd, SBox, Xor
from claasp.graph import Primitive, Selection, UnitArray

from ._word_graph import word_type

PRIDE_SBOX = (0, 4, 8, 15, 1, 5, 14, 9, 2, 7, 10, 12, 11, 13, 6, 3)
# Row-major binary matrices, most-significant output row first.
_LINEAR_ROWS = (
    (
        0x888,
        0x444,
        0x222,
        0x111,
        0x8088,
        0x4044,
        0x2022,
        0x1011,
        0x8808,
        0x4404,
        0x2202,
        0x1101,
        0x8880,
        0x4440,
        0x2220,
        0x1110,
    ),
    (
        0xC010,
        0x6008,
        0x3004,
        0x1802,
        0xC01,
        0x680,
        0x340,
        0x8120,
        0x8018,
        0x400C,
        0x2006,
        0x1003,
        0x881,
        0x4C0,
        0x260,
        0x130,
    ),
    (
        0xC01,
        0x680,
        0x340,
        0x8120,
        0xC010,
        0x6008,
        0x3004,
        0x1802,
        0x881,
        0x4C0,
        0x260,
        0x130,
        0x8018,
        0x400C,
        0x2006,
        0x1003,
    ),
    (
        0x8808,
        0x4404,
        0x2202,
        0x1101,
        0x8880,
        0x4440,
        0x2220,
        0x1110,
        0x888,
        0x444,
        0x222,
        0x111,
        0x8088,
        0x4044,
        0x2022,
        0x1011,
    ),
)


PARAMETERS_CONFIGURATION_LIST = [{"number_of_rounds": 20}]


class Pride(Primitive):
    """The 64-bit-block, 128-bit-key PRIDE block cipher, with reduced-round support.

    Rounds are numbered from one for the byte-addition key schedule. Every
    instance keeps whitening and omits diffusion in its last round.

    EXAMPLES::

        >>> hex(Pride().evaluate(plaintext=0, key=0))
        '0x82b4109fcc70bd1f'
        >>> hex(Pride().evaluate(plaintext=0xffffffffffffffff, key=0))
        '0xd70e60680a17b956'
        >>> Pride(number_of_rounds=0)
        Traceback (most recent call last):
        ...
        ValueError: number_of_rounds must be an integer from 1 to 20
    """

    def __init__(self, number_of_rounds: int = 20) -> None:
        if type(number_of_rounds) is not int or not 1 <= number_of_rounds <= 20:
            raise ValueError("number_of_rounds must be an integer from 1 to 20")
        self.number_of_rounds = number_of_rounds
        super().__init__(
            "pride",
            {"plaintext": word_type(8, 8), "key": word_type(8, 16)},
            provenance=(("reference", "https://eprint.iacr.org/2014/453"),),
        )
        self._builder.add_round()
        key = self.graph.input("key")
        whitening = self._builder.pack_bits(self._builder.unpack_bits(key[:8]), 4)
        state = self._to_cells(self._builder.unpack_bits(self.graph.input("plaintext")))
        state = self._builder.add_component(Xor((state, whitening)))
        matrix = tuple(
            tuple((row >> (15 - j % 16) & 1) if j // 16 == block else 0 for j in range(64))
            for block, rows in enumerate(_LINEAR_ROWS)
            for row in rows
        )
        for r in range(1, number_of_rounds + 1):
            if r > 1:
                self._builder.add_round()
            subkey = []
            for i in range(8):
                value: UnitArray | Selection = key[8 + i]
                if i % 2:
                    rc = Constant(word_type(8), ((193, 165, 81, 197)[i // 2] * r % 256,))
                    value = self._builder.add_component(
                        ModularAdd((value, self._builder.add_component(rc)))
                    )
                subkey.append(value)
            round_key = self._to_cells(self._builder.unpack_bits(self._builder.join(*subkey)))
            state = self._builder.add_component(Xor((state, round_key)))
            state = self._builder.add_component(SBox(state, PRIDE_SBOX))
            if r != number_of_rounds:
                bits = self._from_cells(state)
                bits = self._builder.add_component(LinearMap(bits, matrix))
                state = self._to_cells(bits)
            else:
                state = self._builder.add_component(Xor((state, whitening)))
            self._builder.set_round_output(state)
        self._builder.set_output(self._builder.pack_bits(self._from_cells(state), 8))

    def _to_cells(self, bits):
        return self._builder.pack_bits(
            bits[tuple(w * 16 + j for j in range(16) for w in range(4))], 4
        )

    def _from_cells(self, state):
        bits = self._builder.unpack_bits(state)
        return bits[tuple(j * 4 + w for w in range(4) for j in range(16))]


__all__ = ["Pride"]
