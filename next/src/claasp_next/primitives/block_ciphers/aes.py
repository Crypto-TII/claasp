"""Canonical AES and explicitly derived AES study variants."""

from collections.abc import Iterable

from claasp_next.components import Add
from claasp_next.composites.aes import (
    AES_AFFINE_MATRIX, AES_FIELD, AES_SBOX, MIX_COLUMNS_MATRIX, SHIFT_ROWS_MAPPING,
    AESKeySchedule, AESRound,
)
from claasp_next.graph import Primitive, RealizationDescriptor, ValueType


PARAMETERS_CONFIGURATION_LIST = (
    {"key_bit_size": 128, "number_of_rounds": 10},
    {"key_bit_size": 192, "number_of_rounds": 12},
    {"key_bit_size": 256, "number_of_rounds": 14},
)


class _AESComposition(Primitive):
    def __init__(
        self,
        *,
        family_name: str,
        key_bit_size: int,
        number_of_rounds: int | None,
        realization: str,
        sbox_table: Iterable[int],
        include_mix_columns: bool,
        provenance: tuple[tuple[str, str], ...],
    ) -> None:
        if key_bit_size not in (128, 192, 256):
            raise ValueError("AES key_bit_size must be 128, 192, or 256")
        self.Nk = key_bit_size // 32
        standard_rounds = {128: 10, 192: 12, 256: 14}[key_bit_size]
        rounds = standard_rounds if number_of_rounds is None else number_of_rounds
        if not isinstance(rounds, int) or isinstance(rounds, bool):
            raise TypeError("number_of_rounds must be an integer")
        if rounds <= 0 or rounds > standard_rounds:
            raise ValueError(f"AES-{key_bit_size} requires between 1 and {standard_rounds} rounds")
        if not isinstance(include_mix_columns, bool):
            raise TypeError("include_mix_columns must be a bool")
        table = tuple(sbox_table)
        self.Nr = rounds
        state_type = ValueType(AES_FIELD, (16,))
        super().__init__(
            family_name,
            {"plaintext": state_type, "key": ValueType(AES_FIELD, (key_bit_size // 8,))},
            provenance=provenance,
        )

        self.add_round()
        schedule = self.add_composite(
            AESKeySchedule(key_bit_size, rounds, sbox_table=table, realization=realization),
            {"key": self.input("key")}, scope_id="key_schedule",
        )
        state = self.add_component(Add(
            (self.input("plaintext"), schedule.output("round_key_0")),
            component_id="initial_add_round_key",
        ))
        for round_number in range(1, rounds + 1):
            self.add_round()
            round_scope = self.add_composite(
                AESRound(
                    sbox_table=table,
                    mix_columns=include_mix_columns and round_number != standard_rounds,
                    realization=realization,
                ),
                {"state": state, "round_key": schedule.output(f"round_key_{round_number}")},
                scope_id=f"round_{round_number}",
            )
            state = round_scope.output()
        self.set_output(state)


class AES(_AESComposition):
    """Construct canonical AES-128, AES-192, or AES-256 from reusable blocks."""

    REALIZATIONS = (
        RealizationDescriptor(
            "lookup",
            frozenset(("scalar_evaluation", "batch_evaluation", "sbox_semantics")),
            frozenset(("lookup_sbox", "matrix_linear_layer", "composite_scopes")),
            "AES S-boxes represented by their complete lookup table",
        ),
        RealizationDescriptor(
            "algebraic",
            frozenset(("scalar_evaluation", "batch_evaluation", "algebraic_semantics")),
            frozenset(("field_inverse", "binary_affine_map", "matrix_linear_layer", "composite_scopes")),
            "AES S-boxes represented as field inversion followed by the affine map",
        ),
    )

    def __init__(self, key_bit_size: int = 128, number_of_rounds: int | None = None,
                 realization: str = "lookup") -> None:
        descriptors = {descriptor.name: descriptor for descriptor in self.REALIZATIONS}
        if not isinstance(realization, str) or realization not in descriptors:
            raise ValueError(f"AES realization must be one of {tuple(descriptors)}")
        self.realization = descriptors[realization]
        super().__init__(
            family_name="aes", key_bit_size=key_bit_size, number_of_rounds=number_of_rounds,
            realization=realization, sbox_table=AES_SBOX, include_mix_columns=True,
            provenance=(("identity", "AES"), ("specification", "FIPS 197")),
        )

    @classmethod
    def available_realizations(cls) -> tuple[RealizationDescriptor, ...]:
        return cls.REALIZATIONS

    @classmethod
    def for_capabilities(cls, requirements, **parameters) -> "AES":
        requested = frozenset(requirements)
        for descriptor in cls.REALIZATIONS:
            if descriptor.supports(requested):
                return cls(realization=descriptor.name, **parameters)
        raise ValueError(f"no AES realization supports {tuple(sorted(requested))}")


class AESVariant(_AESComposition):
    """An AES-derived research graph with explicit, provenance-recorded changes."""

    def __init__(
        self,
        *,
        sbox_table: Iterable[int] = AES_SBOX,
        include_mix_columns: bool = True,
        key_bit_size: int = 128,
        number_of_rounds: int | None = None,
    ) -> None:
        table = tuple(sbox_table)
        modifications = []
        if table != AES_SBOX:
            modifications.append("replaced AES S-box in rounds and key schedule")
        if not include_mix_columns:
            modifications.append("removed MixColumns")
        if not modifications:
            modifications.append("explicit AES-derived block composition")
        super().__init__(
            family_name="aes_variant", key_bit_size=key_bit_size,
            number_of_rounds=number_of_rounds, realization="lookup", sbox_table=table,
            include_mix_columns=include_mix_columns,
            provenance=(("derived_from", "AES"), ("modifications", "; ".join(modifications))),
        )


class AES128(AES):
    """Convenience constructor for AES-128."""

    def __init__(self, number_of_rounds: int = 10) -> None:
        super().__init__(key_bit_size=128, number_of_rounds=number_of_rounds)
