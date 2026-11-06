"""Constraint provenance over the common graph propagation schedule."""

from claasp.graph import GraphPropagation
from claasp.representations.constraints import ConstraintModelApplication, ConstraintModelProvenance


def component_applications(primitive, default, specialized=()):
    grouped: dict[ConstraintModelProvenance, list[str]] = {model: [] for _, model in specialized}
    grouped[default] = []
    for component in GraphPropagation(primitive).components:
        model = next((model for kind, model in specialized if isinstance(component, kind)), default)
        assert component.component_id is not None
        grouped[model].append(component.component_id)
    return tuple(
        ConstraintModelApplication(model, tuple(ids)) for model, ids in grouped.items() if ids
    )
