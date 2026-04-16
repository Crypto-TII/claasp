from dataclasses import dataclass, field


@dataclass
class CpBuildState:
    """Mutable accumulator for state that CP constraint generators read and write.

    Passed through the builder loop so generators never touch the model directly.
    """

    next_probability_index: int = 0
    shift_declaration_cache: list = field(default_factory=list)
    component_probability_map: dict = field(default_factory=dict)
    sbox_table_cache: list = field(default_factory=list)
    intermediate_constraints_array: list = field(default_factory=list)
    mzn_output_directives: list = field(default_factory=list)

    @classmethod
    def from_model(cls, model):
        return cls(
            next_probability_index=model.component_probability_index,
            shift_declaration_cache=list(model.modadd_two_term_shift_cache),
            component_probability_map=dict(model.component_and_probability),
            sbox_table_cache=list(model.sbox_table_cache),
            intermediate_constraints_array=list(getattr(model, 'intermediate_constraints_array', [])),
            mzn_output_directives=list(getattr(model, 'mzn_output_directives', [])),
        )

    def apply_to_model(self, model):
        model.component_probability_index = self.next_probability_index
        model.modadd_two_term_shift_cache = self.shift_declaration_cache
        model.component_and_probability = self.component_probability_map
        model.sbox_table_cache = self.sbox_table_cache
        model.intermediate_constraints_array = self.intermediate_constraints_array
        model.mzn_output_directives = self.mzn_output_directives

    def allocate_probability_index(self):
        idx = self.next_probability_index
        self.next_probability_index += 1
        return idx