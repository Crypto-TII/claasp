"""CRAFT with its genuine round constants, tweak schedule and final round.

Reference: Beierle et al., ToSC 2019(1), doi:10.46586/tosc.v2019.i1.5-45.
Reduced windows keep the absolute round numbers; a window ending at round 31
therefore includes the special final round without PN and SB.
"""

from claasp.components import Constant, Permutation, SBox, Xor
from claasp.graph import Primitive, UnitArrayType
from claasp.unit_types import Word

CRAFT_SBOX = (12, 10, 13, 3, 14, 11, 15, 7, 8, 9, 1, 5, 0, 2, 4, 6)
CRAFT_PERMUTATION = (15, 12, 13, 14, 10, 9, 8, 11, 6, 5, 4, 7, 1, 2, 3, 0)
CRAFT_TWEAK_PERMUTATION = (12, 10, 15, 5, 14, 8, 9, 2, 11, 3, 7, 4, 6, 0, 1, 13)
_RC3 = (1, 4, 2, 5, 6, 7, 3)
_RC4 = (1, 8, 4, 2, 9, 12, 6, 11, 5, 10, 13, 14, 15, 7, 3)


class Craft(Primitive):
    """The 64-bit, 128-bit-key tweakable CRAFT block cipher.

    Packed inputs have cell 0 in the most significant nibble. Key K0 is
    the most significant 64-bit half. The public tweak is always explicit.

    EXAMPLES::

        >>> hex(Craft().evaluate(plaintext=0, key=0, tweak=0))
        '0xf630538883063100'
        >>> hex(Craft(number_of_rounds=8).evaluate(plaintext=0, key=0, tweak=0))
        '0x28e562ef6c580a8c'
        >>> hex(Craft().evaluate(plaintext=0x5734F006D8D88A3E, key=0x27A6781A43F364BC916708D5FBB5AEFE, tweak=0x54CD94FFD0670A58))
        '0xa17d6bd4beeb996f'
    """

    def __init__(self, number_of_rounds: int = 32, *, round_offset: int = 0) -> None:
        if any(
            isinstance(value, bool) or not isinstance(value, int)
            for value in (number_of_rounds, round_offset)
        ):
            raise ValueError("round count and offset must be integers")
        if number_of_rounds < 1 or round_offset < 0 or round_offset + number_of_rounds > 32:
            raise ValueError("CRAFT windows must lie inside rounds 0..31")
        self.number_of_rounds = number_of_rounds
        self.round_offset = round_offset
        state_type = UnitArrayType(Word(4), (16,))
        super().__init__(
            "craft",
            {"plaintext": state_type, "key": UnitArrayType(Word(4), (32,)), "tweak": state_type},
            provenance=(("reference", "doi:10.46586/tosc.v2019.i1.5-45"),),
        )
        state = self.graph.input("plaintext")
        key = self.graph.input("key")
        tweak = self.graph.input("tweak")
        for r in range(round_offset, round_offset + number_of_rounds):
            self._builder.add_round()
            cells = []
            for i in range(16):
                sources = (i, i + 8, i + 12) if i < 4 else ((i, i + 8) if i < 8 else (i,))
                cells.append(
                    self._builder.add_component(Xor(tuple(state[j] for j in sources)))
                    if len(sources) > 1
                    else state[i]
                )
            mixed = self._builder.join(*cells)
            constants = [0] * 16
            constants[4], constants[5] = _RC4[r % 15], _RC3[r % 7]
            constant = self._builder.add_component(Constant(state_type, constants))
            rk = key[tuple(range((r % 2) * 16, (r % 2 + 1) * 16))]
            tw = tweak if r % 4 < 2 else tweak[CRAFT_TWEAK_PERMUTATION]
            state = self._builder.add_component(Xor((mixed, constant, rk, tw)))
            if r != 31:
                state = self._builder.add_component(Permutation(state, CRAFT_PERMUTATION))
                state = self._builder.add_component(SBox(state, CRAFT_SBOX))
            self._builder.set_round_output(state)
        self._builder.set_output(state)

    def circle_linear_model(self, *, bibrace=None, tweak: int = 0):
        """Build a generic free-subgroup SPN model with affine master-key rows.

        The special last round is deliberately rejected by this optimized
        backend; ordinary endpoint correlation measurements still support it.
        A nonzero tweak changes affine conditions without being averaged out.

        EXAMPLES::

            >>> model = Craft(number_of_rounds=14).circle_linear_model()
            >>> t = model.trail(0x00720000)
            >>> t.cost, t.conditions.key_count == 2**108
            (22, True)
        """
        from claasp.analysis.circle_linear_spn import FreeSubgroupSPN
        from claasp.semantics.cryptanalysis._circle_algebra import integer
        from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace, CircleBasis
        from claasp.semantics.cryptanalysis.circle_linear import CircleAffineLayer

        integer(tweak, 64, "tweak")
        if self.round_offset + self.number_of_rounds == 32:
            raise ValueError("the free-subgroup backend excludes CRAFT's special final round")
        brace = BinaryBibrace.craft() if bibrace is None else bibrace
        if brace.width != 4:
            raise ValueError("CRAFT's parallel circle layout has four-bit cells")
        diffusion = tuple(
            ((1 << i) | (1 << (i + 8)) | (1 << (i + 12)))
            if i < 4
            else (((1 << i) | (1 << (i + 8))) if i < 8 else 1 << i)
            for i in range(16)
        )
        basis = CircleBasis((brace,) * 16)
        rows = [0] * 64
        for i, row in enumerate(diffusion):
            for b in range(4):
                rows[4 * (15 - i) + b] = sum(
                    1 << (4 * (15 - j) + b) for j in range(16) if row >> j & 1
                )
        layers = []
        for r in range(self.round_offset, self.round_offset + self.number_of_rounds):
            tw = [(tweak >> (4 * (15 - i))) & 15 for i in range(16)]
            if r % 4 >= 2:
                tw = [tw[i] for i in CRAFT_TWEAK_PERMUTATION]
            tw[4] ^= _RC4[r % 15]
            tw[5] ^= _RC3[r % 7]
            offset = 0
            for value in tw:
                offset = (offset << 4) | value
            layers.append(
                CircleAffineLayer(
                    basis,
                    basis,
                    tuple(rows),
                    offset=offset,
                    key_width=128,
                    key_rows=tuple(1 << (bit + (64 if r % 2 == 0 else 0)) for bit in range(64)),
                )
            )
        return FreeSubgroupSPN(
            brace,
            CRAFT_SBOX,
            diffusion,
            CRAFT_PERMUTATION,
            self.number_of_rounds,
            affine_layers=tuple(layers),
        )


__all__ = ["Craft"]
