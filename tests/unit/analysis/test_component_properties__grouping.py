from claasp.analysis.component_properties import (
    PropertyDomain,
    semantic_component_groups,
    semantic_component_key,
)
from claasp.components import BitVectorSBox
from claasp.primitives import Present


def test_equal_sboxes_group_by_semantics_not_component_id_or_source():
    primitive = Present(number_of_rounds=2)
    sboxes = tuple(item for item in primitive.components if isinstance(item, BitVectorSBox))
    groups = semantic_component_groups(primitive, PropertyDomain.LOOKUP_TABLE)
    sbox_groups = tuple(
        group for group in groups if isinstance(group.representative, BitVectorSBox)
    )

    assert len(sboxes) == 34
    assert len(sbox_groups) == 1
    assert sbox_groups[0].count == 34
    assert all("sbox_" not in repr(group.key) for group in sbox_groups)
    assert len({item.component.component_id for item in sbox_groups[0].occurrences}) == 34


def test_analysis_domain_is_part_of_semantic_group_identity():
    component = next(
        item for item in Present(number_of_rounds=1).components if isinstance(item, BitVectorSBox)
    )
    lookup = semantic_component_key(component, PropertyDomain.LOOKUP_TABLE)
    boolean = semantic_component_key(component, PropertyDomain.BOOLEAN)

    assert lookup != boolean
    assert lookup.parameters == boolean.parameters


def test_structural_bindings_are_not_discovered_as_components():
    primitive = Present(number_of_rounds=1)
    assert primitive.bindings
    groups = semantic_component_groups(primitive, PropertyDomain.BOOLEAN)

    assert sum(group.count for group in groups) == len(primitive.components)
    assert sum(group.count for group in groups) != len(primitive.components) + len(
        primitive.bindings
    )
    assert all(occurrence.graph_location for group in groups for occurrence in group.occurrences)


def test_typed_parameters_separate_distinct_operations():
    primitive = Present(number_of_rounds=1)
    groups = semantic_component_groups(primitive, PropertyDomain.BOOLEAN)
    assert len({group.key for group in groups}) == len(groups)
    assert any(
        left.key.component_type == right.key.component_type
        and left.key.parameters == right.key.parameters
        and left.key.input_types != right.key.input_types
        for left in groups
        for right in groups
        if left is not right
    )
