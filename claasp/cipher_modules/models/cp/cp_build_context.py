from dataclasses import dataclass, field


@dataclass(frozen=True)
class CpBuildContext:
    """Read-only configuration snapshot taken from ``MznModel`` at build time.

    Generators receive this instead of the full model so they never
    depend on mutable solver state.
    """

    cipher: object = None
    word_size: int = 0
    data_type: str = "bool"
    true_value: str = "true"
    false_value: str = "false"
    float_and_lat_values: tuple = ()
    bit_bindings_for_intermediate_output: dict = field(default_factory=dict)

    @classmethod
    def from_model(cls, model):
        return cls(
            cipher=model._cipher,
            word_size=getattr(model, 'word_size', 0),
            data_type=model.data_type,
            true_value=model.true_value,
            false_value=model.false_value,
            float_and_lat_values=tuple(getattr(model, '_float_and_lat_values', [])),
            bit_bindings_for_intermediate_output=getattr(model, 'bit_bindings_for_intermediate_output', {}),
        )
