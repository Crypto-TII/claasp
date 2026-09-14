"""Compile typed primitive graphs and annotations to the diagram IR."""

import re

from claasp_next.annotations import AnnotationRole, ExecutionTrace, GraphAnnotation, SideChannelTrace
from claasp_next.graph import Primitive
from claasp_next.representations.diagrams.model import (
    PrimitiveDiagram, DiagramEdge, DiagramNode, DiagramRound,
)


class DiagramCompiler:
    """Preserve graph dependencies, selections, rounds, and annotations."""

    OUTPUT_ID = "__primitive_output__"

    def compile(
        self,
        primitive: Primitive,
        annotation: GraphAnnotation | ExecutionTrace | SideChannelTrace | None = None,
    ) -> PrimitiveDiagram:
        """Return a representation suitable for diagram serializers."""

        if not isinstance(primitive, Primitive):
            raise TypeError("primitive must be a Primitive")
        if isinstance(annotation, (ExecutionTrace, SideChannelTrace)):
            annotation = annotation.annotation
        if annotation is not None:
            if not isinstance(annotation, GraphAnnotation):
                raise TypeError(
                    "annotation must be a GraphAnnotation, ExecutionTrace, or SideChannelTrace"
                )
            if annotation.primitive is not primitive:
                raise ValueError("diagram annotation belongs to a different primitive object")
        values = {
            (entry.role, entry.source_id): entry.value
            for entry in (() if annotation is None else annotation.entries)
        }
        nodes = [
            DiagramNode(
                name, name, "input", None,
                values.get((AnnotationRole.INPUT, name)),
            )
            for name in primitive.inputs
        ]
        edges = []
        rounds = []
        for primitive_round in primitive.rounds:
            round_ids = []
            for component in primitive_round.components:
                component_id = component.component_id
                round_ids.append(component_id)
                nodes.append(DiagramNode(
                    component_id,
                    _human_label(type(component).__name__),
                    type(component).__name__,
                    primitive_round.number,
                    values.get((AnnotationRole.COMPONENT, component_id)),
                ))
                edges.extend(
                    DiagramEdge(
                        selected.source.owner_id, component_id,
                        selected.positions, input_index,
                    )
                    for input_index, selected in enumerate(component.inputs)
                )
            rounds.append(DiagramRound(primitive_round.number, tuple(round_ids)))
        if primitive.output is not None:
            nodes.append(DiagramNode(
                self.OUTPUT_ID, "output", "output", None,
                values.get((AnnotationRole.OUTPUT, "primitive_output")),
            ))
            edges.append(DiagramEdge(
                primitive.output.source.owner_id, self.OUTPUT_ID,
                primitive.output.positions, 0,
            ))
        return PrimitiveDiagram(primitive.family_name, tuple(nodes), tuple(edges), tuple(rounds))


def _human_label(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", " ", name)
