"""Compile typed cipher graphs and annotations to the diagram IR."""

import re

from claasp_next.annotations import AnnotationRole, ExecutionTrace, GraphAnnotation, SideChannelTrace
from claasp_next.core import Cipher
from claasp_next.representations.diagrams.model import (
    CipherDiagram, DiagramEdge, DiagramNode, DiagramRound,
)


class DiagramCompiler:
    """Preserve graph dependencies, selections, rounds, and annotations."""

    OUTPUT_ID = "__cipher_output__"

    def compile(
        self,
        cipher: Cipher,
        annotation: GraphAnnotation | ExecutionTrace | SideChannelTrace | None = None,
    ) -> CipherDiagram:
        """Return a representation suitable for diagram serializers."""

        if not isinstance(cipher, Cipher):
            raise TypeError("cipher must be a Cipher")
        if isinstance(annotation, (ExecutionTrace, SideChannelTrace)):
            annotation = annotation.annotation
        if annotation is not None:
            if not isinstance(annotation, GraphAnnotation):
                raise TypeError(
                    "annotation must be a GraphAnnotation, ExecutionTrace, or SideChannelTrace"
                )
            if annotation.cipher is not cipher:
                raise ValueError("diagram annotation belongs to a different cipher object")
        values = {
            (entry.role, entry.source_id): entry.value
            for entry in (() if annotation is None else annotation.entries)
        }
        nodes = [
            DiagramNode(
                name, name, "input", None,
                values.get((AnnotationRole.INPUT, name)),
            )
            for name in cipher.inputs
        ]
        edges = []
        rounds = []
        for cipher_round in cipher.rounds:
            round_ids = []
            for component in cipher_round.components:
                component_id = component.component_id
                round_ids.append(component_id)
                nodes.append(DiagramNode(
                    component_id,
                    _human_label(type(component).__name__),
                    type(component).__name__,
                    cipher_round.number,
                    values.get((AnnotationRole.COMPONENT, component_id)),
                ))
                edges.extend(
                    DiagramEdge(
                        selected.source.owner_id, component_id,
                        selected.positions, input_index,
                    )
                    for input_index, selected in enumerate(component.inputs)
                )
            rounds.append(DiagramRound(cipher_round.number, tuple(round_ids)))
        if cipher.output is not None:
            nodes.append(DiagramNode(
                self.OUTPUT_ID, "output", "output", None,
                values.get((AnnotationRole.OUTPUT, "cipher_output")),
            ))
            edges.append(DiagramEdge(
                cipher.output.source.owner_id, self.OUTPUT_ID,
                cipher.output.positions, 0,
            ))
        return CipherDiagram(cipher.family_name, tuple(nodes), tuple(edges), tuple(rounds))


def _human_label(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", " ", name)
