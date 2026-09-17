"""Canonical word-oriented Simon block primitive."""

from claasp_next.components import BitwiseAnd, Concatenate, Constant, Rotate, Xor
from claasp_next.domains import Word
from claasp_next.graph import Primitive, Port, Selection, ValueType

PARAMETERS_CONFIGURATION_LIST = (
    (32, 64, 32), (48, 72, 36), (48, 96, 36), (64, 96, 42),
    (64, 128, 44), (96, 96, 52), (96, 144, 54), (128, 128, 68),
    (128, 192, 69), (128, 256, 72),
)
_Z = (4506230155203752166, 2575579794259089498, 3160415496042964403,
      3957284701066611983, 3781244162168104175)
_Z_INDEX = {16: {4: 0}, 24: {3: 0, 4: 1}, 32: {3: 2, 4: 3},
            48: {2: 2, 3: 3}, 64: {2: 2, 3: 3, 4: 4}}


class Simon(Primitive):
    """Construct a standard Simon variant over typed word components.

    EXAMPLES::

        >>> from claasp_next.primitives import Simon
        >>> primitive = Simon()
        >>> hex(primitive.evaluate(0x65656877, 0x1918111009080100))
        '0xc69be9bb'
    """

    def __init__(self, block_bit_size=32, key_bit_size=64, number_of_rounds=None):
        configuration = next((item for item in PARAMETERS_CONFIGURATION_LIST
                              if item[:2] == (block_bit_size, key_bit_size)), None)
        if configuration is None:
            raise ValueError("unsupported Simon block/key size combination")
        standard_rounds = configuration[2]
        rounds = standard_rounds if number_of_rounds is None else number_of_rounds
        if not isinstance(rounds, int) or isinstance(rounds, bool):
            raise TypeError("number_of_rounds must be an integer")
        if not 0 < rounds <= standard_rounds:
            raise ValueError(f"Simon{block_bit_size}/{key_bit_size} requires between 1 and {standard_rounds} rounds")
        width = block_bit_size // 2
        key_words = key_bit_size // width
        word_type = ValueType(Word(width), (1,))
        super().__init__("simon", {
            "plaintext": ValueType(Word(width), (2,)),
            "key": ValueType(Word(width), (key_words,)),
        })
        plaintext, key = self.input("plaintext"), self.input("key")
        left, right = plaintext[0], plaintext[1]
        round_keys: list[Port | Selection] = [key[key_words - index - 1] for index in range(key_words)]
        z = _Z[_Z_INDEX[width][key_words]]
        for round_number in range(rounds):
            self.add_round()
            if round_number >= key_words:
                index = round_number - key_words
                operation = self.add_component(Rotate(round_keys[-1], 3, "right"))
                if key_words == 4:
                    operation = self.add_component(Xor((operation, round_keys[index + 1])))
                rotated = self.add_component(Rotate(operation, 1, "right"))
                constant = self.add_component(Constant(
                    word_type, (((1 << width) - 4) ^ ((z >> (61 - index % 62)) & 1),)
                ))
                round_keys.append(self.add_component(Xor(
                    (constant, round_keys[index], operation, rotated),
                    component_id=f"round_key_{round_number}",
                )))
            left, right = self._round(left, right, round_keys[round_number], round_number)
        self.set_output(self.add_component(Concatenate((left, right), component_id="primitive_output")))

    def _round(self, left, right, round_key, round_number):
        rotate_1 = self.add_component(Rotate(left, 1, "left"))
        rotate_8 = self.add_component(Rotate(left, 8, "left"))
        nonlinear = self.add_component(BitwiseAnd((rotate_1, rotate_8)))
        rotate_2 = self.add_component(Rotate(left, 2, "left"))
        function = self.add_component(Xor((nonlinear, rotate_2)))
        new_left = self.add_component(Xor(
            (right, function, round_key), component_id=f"round_{round_number}_xor"
        ))
        return new_left, left
