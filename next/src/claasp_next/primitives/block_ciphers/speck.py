"""Reference Speck implementation following the designers' pseudocode."""

from types import MappingProxyType

from claasp_next.components import Concatenate, Constant, ModularAdd, Rotate, Xor
from claasp_next.domains import Word
from claasp_next.graph import Primitive, PrimitiveKind, ValueType


PARAMETERS_CONFIGURATION_LIST = (
    {"block_bit_size": 32, "key_bit_size": 64, "number_of_rounds": 22},
    {"block_bit_size": 48, "key_bit_size": 72, "number_of_rounds": 22},
    {"block_bit_size": 48, "key_bit_size": 96, "number_of_rounds": 23},
    {"block_bit_size": 64, "key_bit_size": 96, "number_of_rounds": 26},
    {"block_bit_size": 64, "key_bit_size": 128, "number_of_rounds": 27},
    {"block_bit_size": 96, "key_bit_size": 96, "number_of_rounds": 28},
    {"block_bit_size": 96, "key_bit_size": 144, "number_of_rounds": 29},
    {"block_bit_size": 128, "key_bit_size": 128, "number_of_rounds": 32},
    {"block_bit_size": 128, "key_bit_size": 192, "number_of_rounds": 33},
    {"block_bit_size": 128, "key_bit_size": 256, "number_of_rounds": 34},
)


def _validate_parameters(
    block_bit_size, key_bit_size, number_of_rounds, rotation_alpha, rotation_beta,
):
    configuration = Primitive.select_configuration(
        PARAMETERS_CONFIGURATION_LIST,
        block_bit_size=block_bit_size,
        key_bit_size=key_bit_size,
    )
    rounds = Primitive.validate_number_of_rounds(
        number_of_rounds,
        default=configuration["number_of_rounds"],
        maximum=configuration["number_of_rounds"],
        name=f"Speck{block_bit_size}/{key_bit_size}",
    )
    word_size = block_bit_size // 2
    alpha = (7 if word_size == 16 else 8) if rotation_alpha is None else rotation_alpha
    beta = (2 if word_size == 16 else 3) if rotation_beta is None else rotation_beta
    for name, amount in (("rotation_alpha", alpha), ("rotation_beta", beta)):
        if not isinstance(amount, int) or isinstance(amount, bool) or not 0 <= amount < word_size:
            raise ValueError(f"{name} must be an integer in range({word_size})")
    return word_size, key_bit_size // word_size, rounds, alpha, beta


class Speck(Primitive):
    """Construct a standard Speck variant as a graph over word units.

    The variables and assignments in the constructor mirror the round and key
    schedule pseudocode; component identifiers are generated automatically.

    EXAMPLES::

        >>> primitive = Speck(block_bit_size=64, key_bit_size=128)
        >>> plaintext = 0x3B7265747475432D
        >>> key = 0x1B1A1918131211100B0A090803020100
        >>> hex(primitive.evaluate(plaintext, key))
        '0x8c6fa548454e028b'
    """

    def __init__(
        self,
        block_bit_size: int = 32,
        key_bit_size: int = 64,
        number_of_rounds: int | None = None,
        rotation_alpha: int | None = None,
        rotation_beta: int | None = None,
    ) -> None:
        word_size, key_word_count, rounds, alpha, beta = _validate_parameters(
            block_bit_size, key_bit_size, number_of_rounds, rotation_alpha, rotation_beta,
        )
        word_type = ValueType(Word(word_size), (1,))
        super().__init__(
            "speck",
            {
                "plaintext": ValueType(Word(word_size), (2,)),
                "key": ValueType(Word(word_size), (key_word_count,)),
            },
            kind=PrimitiveKind.BLOCK_CIPHER,
        )

        x, y = self.input("plaintext")[0], self.input("plaintext")[1]
        key = self.input("key")
        schedule = [key[position] for position in range(key_word_count - 2, -1, -1)]
        round_key = key[key_word_count - 1]
        round_states = []
        round_keys = []
        key_schedule_states = []
        round_operations = []

        def round_function(x, y, key):
            x = self.add_component(Rotate(x, alpha, "right"))
            x = self.add_component(ModularAdd((x, y)))
            x = self.add_component(Xor((x, key)))
            y = self.add_component(Rotate(y, beta, "left"))
            y = self.add_component(Xor((y, x)))
            return x, y

        for round_number in range(rounds):
            self.add_round()
            round_keys.append(round_key)
            start = len(self.rounds[-1].components)
            x, y = round_function(x, y, round_key)
            operations = self.rounds[-1].components[start:]
            round_operations.append(MappingProxyType({
                "rotate_right": operations[0],
                "modular_add": operations[1],
                "rotate_left": operations[3],
            }))
            round_states.append((x, y))

            if round_number + 1 < rounds:
                index = round_number % len(schedule)
                constant = self.add_component(Constant(word_type, (round_number,)))
                schedule[index], round_key = round_function(
                    schedule[index], round_key, constant,
                )
                key_schedule_states.append((schedule[index], round_key))

        self.round_keys = tuple(round_keys)
        self.round_states = tuple(round_states)
        self.key_schedule_states = tuple(key_schedule_states)
        self.round_operations = tuple(round_operations)
        self.set_output(self.add_component(Concatenate((x, y))))
