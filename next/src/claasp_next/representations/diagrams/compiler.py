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
            for name in primitive.input_ports
        ]
        edges = []

        def routed_edges(selected, destination_id, input_index):
            if selected.source.owner_id not in {binding.binding_id for binding in primitive.bindings}:
                return (DiagramEdge(
                    selected.source.owner_id, destination_id, selected.positions, input_index,
                ),)
            grouped = []
            for owner_id, bit in primitive.selection_bit_sources(selected):
                if grouped and grouped[-1][0] == owner_id:
                    grouped[-1][1].append(bit)
                else:
                    grouped.append((owner_id, [bit]))
            return tuple(
                DiagramEdge(owner_id, destination_id, tuple(bits), input_index)
                for owner_id, bits in grouped
            )

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
                for input_index, selected in enumerate(component.inputs):
                    edges.extend(routed_edges(selected, component_id, input_index))
            rounds.append(DiagramRound(primitive_round.number, tuple(round_ids)))
        if primitive.output is not None:
            nodes.append(DiagramNode(
                self.OUTPUT_ID, "output", "output", None,
                values.get((AnnotationRole.OUTPUT, "primitive_output")),
            ))
            edges.extend(routed_edges(primitive.output, self.OUTPUT_ID, 0))
        return PrimitiveDiagram(primitive.family_name, tuple(nodes), tuple(edges), tuple(rounds))


def _human_label(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", " ", name)
