"""Published thirty-round uLBC-384t with an explicit key/tweak split."""

from claasp.graph import Primitive, Selection, UnitArray, UnitArrayType
from claasp.primitives.block_ciphers._word_graph import word_type
from claasp.primitives.block_ciphers.ulbc import _build_ulbc
from claasp.unit_types import Bit

# Representative specification-approved splits of the 384-bit tweakey.
PARAMETERS_CONFIGURATION_LIST = [
    {"key_bit_size": 128, "number_of_rounds": 30},
    {"key_bit_size": 256, "number_of_rounds": 30},
    {"key_bit_size": 384, "number_of_rounds": 30},
]


class ULBCTweakable(Primitive):
    """uLBC-384t; packed tweakey is key || tweak, totalling 384 bits.

    Keys have 128 to 384 bits. With a 384-bit key there is no tweak input.
    Whitening includes all three 128-bit subtweakeys, as in the authors' VHDL
    and appendix A vectors; section 2.4's RK0 expression omits the third term.
    Reduced instances retain the special final round.

    EXAMPLES::

        >>> hex(ULBCTweakable().evaluate(plaintext=0, key=0, tweak=0))
        '0x64adeb0232294d9c1e268365764e674a'
        >>> ULBCTweakable(key_bit_size=127)
        Traceback (most recent call last):
        ...
        ValueError: key_bit_size must be an integer from 128 to 384
    """

    def __init__(self, key_bit_size: int = 128, number_of_rounds: int = 30) -> None:
        if type(key_bit_size) is not int or not 128 <= key_bit_size <= 384:
            raise ValueError("key_bit_size must be an integer from 128 to 384")
        if type(number_of_rounds) is not int or not 1 <= number_of_rounds <= 30:
            raise ValueError("number_of_rounds must be an integer from 1 to 30")
        self.key_bit_size = key_bit_size
        self.tweak_bit_size = 384 - key_bit_size
        self.number_of_rounds = number_of_rounds
        inputs = {"plaintext": word_type(4, 32), "key": UnitArrayType(Bit(), (key_bit_size,))}
        if self.tweak_bit_size:
            inputs["tweak"] = UnitArrayType(Bit(), (self.tweak_bit_size,))
        super().__init__("ulbc_384t", inputs, provenance=(("reference", "doi:10.62056/a63zzoja5"),))
        # Input re-grouping needs a graph round before adding PackBits nodes.
        self._builder.add_round()
        bits: UnitArray | Selection = self.graph.input("key")
        if self.tweak_bit_size:
            bits = self._builder.join(bits, self.graph.input("tweak"))
        key = self._builder.pack_bits(bits, 4)
        _build_ulbc(self, key, number_of_rounds, 0x5A5A, round_started=True)


__all__ = ["ULBCTweakable"]
