import pytest

from claasp.primitives import Present, ToySpeck
from claasp.representations.constraints.sat import KeyScheduleMinimaxSATModel


def test_weights_are_partitioned_by_physical_input_dependencies():
    model = KeyScheduleMinimaxSATModel(ToySpeck(3))
    assert model.key_components == {"modular_add_0_7", "modular_add_1_7"}
    assert model.data_components == {"modular_add_0_1", "modular_add_1_1", "modular_add_2_1"}
    formula = model.cnf_formula(maximum_partition_weight=1)
    assert "key_schedule_weight_bound" in formula.provenance
    assert "data_path_weight_bound" in formula.provenance
    assert formula.constraint_models[-1].model is model.model_provenance
    assert formula == model.cnf_formula(maximum_partition_weight=1)


def test_non_arx_components_and_malformed_bounds_are_not_silently_accepted():
    with pytest.raises(NotImplementedError, match="single-word ARX"):
        KeyScheduleMinimaxSATModel(Present(number_of_rounds=2))
    model = KeyScheduleMinimaxSATModel(ToySpeck(2))
    with pytest.raises(ValueError, match="nonnegative integer"):
        model.cnf_formula(maximum_partition_weight=True)
