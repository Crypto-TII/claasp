"""Reference AES implementation following the FIPS 197 pseudocode."""

from claasp.components import (
    Add,
    BinaryAffineMap,
    Constant,
    LinearMap,
    Permutation,
    Power,
    SBox,
)
from claasp.composites.aes import (
    AES_AFFINE_MATRIX,
    AES_FIELD,
    AES_SBOX,
    MIX_COLUMNS_MATRIX,
    ROUND_CONSTANTS,
    SHIFT_ROWS_MAPPING,
)
from claasp.graph import (
    Primitive,
    PrimitiveKind,
    RealizationDescriptor,
    ValueType,
    as_selection,
)

PARAMETERS_CONFIGURATION_LIST = (
    {"key_bit_size": 128, "number_of_rounds": 10},
    {"key_bit_size": 192, "number_of_rounds": 12},
    {"key_bit_size": 256, "number_of_rounds": 14},
)


def _validate_parameters(key_bit_size, number_of_rounds, realization):
    configuration = Primitive.select_configuration(
        PARAMETERS_CONFIGURATION_LIST,
        key_bit_size=key_bit_size,
    )
    rounds = Primitive.validate_number_of_rounds(
        number_of_rounds,
        default=configuration["number_of_rounds"],
        maximum=configuration["number_of_rounds"],
        name=f"AES-{key_bit_size}",
    )
    descriptors = {item.name: item for item in AES.REALIZATIONS}
    if not isinstance(realization, str) or realization not in descriptors:
        raise ValueError(f"AES realization must be one of {tuple(descriptors)}")
    return configuration, rounds, descriptors[realization]


def _sub_bytes(primitive, state, realization):
    if realization == "lookup":
        return primitive._builder.add_component(SBox(state, AES_SBOX))
    inverse = primitive._builder.add_component(Power(state, 254))
    return primitive._builder.add_component(BinaryAffineMap(inverse, AES_AFFINE_MATRIX, 0x63))


def _key_schedule(primitive, key, key_word_count, number_of_rounds, realization):
    """FIPS 197 KEYEXPANSION, returning round keys in their natural order."""

    word_type = ValueType(AES_FIELD, (4,))
    words = [key[4 * index : 4 * index + 4] for index in range(key_word_count)]
    while len(words) < 4 * (number_of_rounds + 1):
        word_index = len(words)
        temporary = as_selection(words[-1])
        if word_index % key_word_count == 0:
            temporary = temporary.source.select(
                temporary.positions[1],
                temporary.positions[2],
                temporary.positions[3],
                temporary.positions[0],
            )
            temporary = _sub_bytes(primitive, temporary, realization)
            round_constant = primitive._builder.add_component(
                Constant(
                    word_type,
                    (ROUND_CONSTANTS[word_index // key_word_count - 1], 0, 0, 0),
                )
            )
            temporary = primitive._builder.add_component(Add((temporary, round_constant)))
        elif key_word_count == 8 and word_index % key_word_count == 4:
            temporary = _sub_bytes(primitive, temporary, realization)
        words.append(primitive._builder.add_component(Add((words[word_index - key_word_count], temporary))))

    return [
        key[:16]
        if round_number == 0
        else primitive._builder.join(*words[4 * round_number : 4 * round_number + 4])
        for round_number in range(number_of_rounds + 1)
    ]


class AES(Primitive):
    """Build AES directly from the steps in FIPS 197 Algorithms 1 and 2.

    The source deliberately uses the specification's ``state``, ``words``, and
    ``round_key`` vocabulary and leaves component identifiers to ``Primitive``.

    EXAMPLES::

        >>> primitive = AES()
        >>> plaintext = 0x00112233445566778899AABBCCDDEEFF
        >>> key = 0x000102030405060708090A0B0C0D0E0F
        >>> hex(primitive.evaluate(plaintext, key))
        '0x69c4e0d86a7b0430d8cdb78070b4c55a'
    """

    REALIZATIONS = (
        RealizationDescriptor(
            "lookup",
            frozenset(("scalar_evaluation", "batch_evaluation", "sbox_semantics")),
            frozenset(("lookup_sbox", "matrix_linear_layer")),
            "AES S-boxes represented by their complete lookup table",
            provenance=("FIPS 197 substitution table",),
            priority=0,
        ),
        RealizationDescriptor(
            "algebraic",
            frozenset(("scalar_evaluation", "batch_evaluation", "algebraic_semantics")),
            frozenset(("field_inverse", "binary_affine_map", "matrix_linear_layer")),
            "AES S-boxes represented as field inversion followed by the affine map",
            provenance=("FIPS 197 section 5.1.1",),
            priority=10,
        ),
    )

    def __init__(
        self,
        key_bit_size: int = 128,
        number_of_rounds: int | None = None,
        realization: str = "lookup",
    ) -> None:
        configuration, rounds, descriptor = _validate_parameters(
            key_bit_size,
            number_of_rounds,
            realization,
        )
        self.Nk = key_bit_size // 32
        self.Nr = rounds
        self.realization = descriptor
        state_type = ValueType(AES_FIELD, (16,))
        super().__init__(
            "aes",
            {"plaintext": state_type, "key": ValueType(AES_FIELD, (key_bit_size // 8,))},
            kind=PrimitiveKind.BLOCK_CIPHER,
            provenance=(("identity", "AES"), ("specification", "FIPS 197")),
            instance_name=f"AES-{key_bit_size}",
            round_count=rounds,
        )

        # KEYEXPANSION(key)
        self._builder.add_round()
        round_keys = self._builder.set_round_keys(
            _key_schedule(self, self.input("key"), self.Nk, rounds, descriptor.name),
        )

        # state <- ADDROUNDKEY(state, round_key[0])
        state = self._builder.add_component(Add((self.input("plaintext"), round_keys[0])))
        self.initial_state = state

        # Rounds 1..Nr follow FIPS 197's main algorithm. Reduced studies retain
        # MixColumns because they are prefixes of the standard AES execution.
        for round_number in range(1, rounds + 1):
            self._builder.add_round()
            state = _sub_bytes(self, state, descriptor.name)
            boundaries = {"sub_bytes": state}
            state = self._builder.add_component(Permutation(state, SHIFT_ROWS_MAPPING))
            boundaries["shift_rows"] = state
            if round_number != configuration["number_of_rounds"]:
                state = self._builder.add_component(LinearMap(state, MIX_COLUMNS_MATRIX))
                boundaries["mix_columns"] = state
            state = self._builder.add_component(Add((state, round_keys[round_number])))
            boundaries["add_round_key"] = state
            self._builder.add_round_state(**boundaries)

        self._builder.set_output(state)

    @classmethod
    def realize(cls, name: str = "lookup", **parameters) -> "AES":
        """Resolve this primitive through the registered realization policy."""
        cls.realization_descriptor(name)
        return cls(realization=name, **parameters)


class AES128(AES):
    """Convenience constructor for AES-128.

    EXAMPLES::

        >>> primitive = AES128()
        >>> inputs = {name: 0 for name in primitive.input_ports}
        >>> output = primitive.evaluate(inputs)
        >>> (hex(output)[:18], output.bit_length())
        ('0x66e94bd4ef8a2c3b', 127)
    """

    def __init__(self, number_of_rounds: int = 10, realization: str = "lookup") -> None:
        super().__init__(
            key_bit_size=128,
            number_of_rounds=number_of_rounds,
            realization=realization,
        )
