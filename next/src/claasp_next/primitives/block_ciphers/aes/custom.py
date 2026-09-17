"""Block-composed AES-derived primitives for research studies."""

from collections.abc import Iterable

from claasp_next.components import Add
from claasp_next.composites.aes import AES_FIELD, AES_SBOX, AESKeySchedule, AESRound
from claasp_next.graph import Primitive, PrimitiveKind, ValueType


class CustomAES(Primitive):
    """Build an explicitly modified AES-derived graph from reusable blocks.

    This class is intentionally distinct from canonical :class:`AES` and from
    the reduced-size teaching primitive ``ToyAES``.
    """

    def __init__(
        self,
        *,
        sbox_table: Iterable[int] = AES_SBOX,
        include_mix_columns: bool = True,
        key_bit_size: int = 128,
        number_of_rounds: int | None = None,
    ) -> None:
        configuration = Primitive.select_configuration(
            (
                {"key_bit_size": 128, "number_of_rounds": 10},
                {"key_bit_size": 192, "number_of_rounds": 12},
                {"key_bit_size": 256, "number_of_rounds": 14},
            ),
            key_bit_size=key_bit_size,
        )
        rounds = Primitive.validate_number_of_rounds(
            number_of_rounds,
            default=configuration["number_of_rounds"],
            maximum=configuration["number_of_rounds"],
            name=f"CustomAES-{key_bit_size}",
        )
        if not isinstance(include_mix_columns, bool):
            raise TypeError("include_mix_columns must be a bool")
        table = tuple(sbox_table)
        modifications = []
        if table != AES_SBOX:
            modifications.append("replaced AES S-box in rounds and key schedule")
        if not include_mix_columns:
            modifications.append("removed MixColumns")
        if not modifications:
            modifications.append("explicit AES-derived block composition")

        state_type = ValueType(AES_FIELD, (16,))
        super().__init__(
            "custom_aes",
            {"plaintext": state_type, "key": ValueType(AES_FIELD, (key_bit_size // 8,))},
            kind=PrimitiveKind.BLOCK_CIPHER,
            provenance=(("derived_from", "AES"), ("modifications", "; ".join(modifications))),
        )

        self.add_round()
        key_schedule = self.add_composite(
            AESKeySchedule(key_bit_size, rounds, sbox_table=table),
            {"key": self.input("key")},
        )
        state = self.add_component(Add((self.input("plaintext"), key_schedule.output[0])))
        for round_number in range(1, rounds + 1):
            self.add_round()
            round_function = self.add_composite(
                AESRound(
                    sbox_table=table,
                    mix_columns=include_mix_columns and round_number != configuration["number_of_rounds"],
                ),
                {"state": state, "round_key": key_schedule.output[round_number]},
            )
            state = round_function.output()
        self.set_output(state)
