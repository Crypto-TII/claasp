"""Published uLBC-128 and uLBC-256 (IACR CiC 1(4), 2025).

Specification: https://doi.org/10.62056/a63zzoja5, section 2 and appendix A.
Constants retain Table 3's entry 23 = 0xc0, also present in the authors' VHDL.
The final round has substitution and key addition only. This is the published
18/22-round family, not the later C++ variants in the authors' repository.
"""

from claasp._catalogue_metadata import _entry
from claasp.components import Constant, LinearMap, Permutation, SBox, Xor
from claasp.graph import Primitive

from ._word_graph import word_type

ULBC_SBOX = (8, 0, 1, 5, 12, 7, 4, 6, 2, 10, 3, 13, 14, 15, 11, 9)
ULBC_PERMUTATION = (
    0,
    25,
    18,
    15,
    4,
    1,
    30,
    19,
    8,
    29,
    22,
    7,
    12,
    9,
    26,
    23,
    20,
    5,
    10,
    31,
    16,
    13,
    2,
    27,
    28,
    17,
    6,
    3,
    24,
    21,
    14,
    11,
)
_KEY_PERMUTATION = (
    8,
    24,
    28,
    23,
    9,
    31,
    14,
    17,
    20,
    19,
    26,
    5,
    18,
    2,
    6,
    30,
    4,
    15,
    11,
    25,
    10,
    29,
    12,
    3,
    21,
    16,
    7,
    0,
    27,
    13,
    22,
    1,
)
_RC_HEAD = (
    0x80,
    0xC0,
    0xE0,
    0xF0,
    0xF8,
    0x7C,
    0xBC,
    0xDC,
    0xEC,
    0xF4,
    0x78,
    0x3C,
    0x9C,
    0xCC,
    0xE4,
    0x70,
    0xB8,
    0x5C,
    0xAC,
    0xD4,
    0x68,
    0x34,
    0x18,
    0xC0,
    0x84,
    0x40,
    0xA0,
    0xD0,
    0xE8,
    0x74,
)
_RC_TAIL = (
    0xA0,
    0xAC,
    0x93,
    0x29,
    0xAC,
    0x4B,
    0xC9,
    0x91,
    0xC2,
    0x31,
    0x32,
    0x19,
    0xC1,
    0x93,
    0xCA,
    0x81,
    0x44,
    0x20,
    0xCB,
    0x8B,
    0x49,
    0xCC,
    0x9B,
    0xA8,
    0x82,
    0xC1,
    0x04,
    0xBA,
    0x4A,
    0x22,
)


def _lfsr(primitive, cells, inverse=False):
    # Encode the nibble LFSR as a binary linear map, not a nonlinear lookup.
    bits = primitive._builder.unpack_bits(cells)
    rows = (4, 2, 1, 12) if inverse else (9, 8, 4, 2)
    matrix = tuple(
        tuple((rows[i % 4] >> (3 - j % 4) & 1) if i // 4 == j // 4 else 0 for j in range(128))
        for i in range(128)
    )
    bits = primitive._builder.add_component(LinearMap(bits, matrix))
    return primitive._builder.pack_bits(bits, 4)


def _build_ulbc(primitive, key, rounds, domain, *, round_started=False):
    if not round_started:
        primitive._builder.add_round()
    halves = [
        key[tuple(range(start, start + 32))] for start in range(0, key.array_type.unit_count, 32)
    ]
    rk = halves[0] if len(halves) == 1 else primitive._builder.add_component(Xor(halves))
    state = primitive._builder.add_component(Xor((primitive.graph.input("plaintext"), rk)))
    for r in range(rounds):
        if r:
            primitive._builder.add_round()
        updated = []
        for i, half in enumerate(halves):
            if i:
                half = _lfsr(primitive, half, inverse=i == 2)
            updated.append(primitive._builder.add_component(Permutation(half, _KEY_PERMUTATION)))
        halves = updated
        rk = halves[0] if len(halves) == 1 else primitive._builder.add_component(Xor(halves))
        state = primitive._builder.add_component(SBox(state, ULBC_SBOX))
        if r != rounds - 1:
            rc = (_RC_HEAD[r] << 24) | (domain << 8) | _RC_TAIL[r]
            values = tuple((rc >> (28 - 4 * i)) & 15 for i in range(8)) + (0,) * 24
            const = primitive._builder.add_component(Constant(word_type(4, 32), values))
            state = primitive._builder.add_component(Xor((state, const)))
            state = primitive._builder.add_component(Permutation(state, ULBC_PERMUTATION))
            state = primitive._builder.join(
                *[
                    primitive._builder.add_component(
                        Xor(tuple(state[4 * c + j] for j in range(4) if j != i))
                    )
                    for c in range(8)
                    for i in range(4)
                ]
            )
        state = primitive._builder.add_component(Xor((state, rk)))
        primitive._builder.set_round_output(state)
    primitive._builder.set_output(state)


PARAMETERS_CONFIGURATION_LIST = [
    {"key_bit_size": 128, "number_of_rounds": 18},
    {"key_bit_size": 256, "number_of_rounds": 22},
]


class ULBC(Primitive):
    """Published uLBC block cipher with a 128- or 256-bit key.

    The default round counts are 18 and 22 respectively. A reduced instance
    retains whitening and the special last round. Cells are packed MSB first.

    EXAMPLES::

        >>> hex(ULBC().evaluate(plaintext=0, key=0))
        '0xe6b6b249c25994a425c480b852f4899a'
        >>> hex(ULBC(key_bit_size=256).evaluate(plaintext=0, key=0))
        '0xfb0be7250cfd59a9d2712fb1899ff396'
        >>> ULBC(key_bit_size=192)
        Traceback (most recent call last):
        ...
        ValueError: key_bit_size must be 128 or 256
    """

    def __init__(self, key_bit_size: int = 128, number_of_rounds: int | None = None) -> None:
        if type(key_bit_size) is not int or key_bit_size not in (128, 256):
            raise ValueError("key_bit_size must be 128 or 256")
        full = 18 if key_bit_size == 128 else 22
        rounds = full if number_of_rounds is None else number_of_rounds
        if type(rounds) is not int or not 1 <= rounds <= full:
            raise ValueError(f"number_of_rounds must be an integer from 1 to {full}")
        self.key_bit_size = key_bit_size
        self.number_of_rounds = rounds
        super().__init__(
            "ulbc",
            {"plaintext": word_type(4, 32), "key": word_type(4, key_bit_size // 4)},
            provenance=(("reference", "doi:10.62056/a63zzoja5"),),
        )
        _build_ulbc(
            self, self.graph.input("key"), rounds, 0xC5C5 if key_bit_size == 128 else 0x3C3C
        )


__all__ = ["ULBC"]


__catalogue__ = (
    _entry("primitive", ULBC, evidence=("tests/unit/primitives/block_ciphers/test_ulbc.py",)),
)
