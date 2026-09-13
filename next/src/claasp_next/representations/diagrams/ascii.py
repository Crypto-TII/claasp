"""Work-in-progress textual serialization of cipher diagrams."""

import warnings

from claasp_next.representations.diagrams.formatting import format_annotation, format_positions
from claasp_next.representations.diagrams.model import CipherDiagram


class ASCIIArtWorkInProgressWarning(UserWarning):
    """Warn that routed ASCII-art diagrams are not implemented yet."""


class ASCIIArtSerializer:
    """Render a temporary line-oriented listing, not routed ASCII art.

    .. warning::

       This serializer is a work in progress. Its output is useful for
       inspecting the diagram IR, but it does not yet draw an actual cipher
       diagram with boxes and routed connectors.
    """

    def serialize(self, diagram: CipherDiagram) -> str:
        """Return the temporary graph listing and emit a WIP warning."""

        if not isinstance(diagram, CipherDiagram):
            raise TypeError("diagram must be a CipherDiagram")
        warnings.warn(
            "ASCII cipher diagrams are a work in progress; the current output "
            "is a structural listing, not routed ASCII art",
            ASCIIArtWorkInProgressWarning,
            stacklevel=2,
        )
        lines = [f"cipher {diagram.cipher_name}", "inputs"]
        for node in diagram.nodes:
            if node.kind == "input":
                lines.append(f"  {node.node_id}{_annotation(node.annotation)}")
        incoming = {}
        for edge in diagram.edges:
            incoming.setdefault(edge.destination_id, []).append(edge)
        for group in diagram.rounds:
            lines.append(f"round {group.number}")
            for node_id in group.node_ids:
                node = diagram.node(node_id)
                sources = ", ".join(
                    f"{edge.source_id}[{format_positions(edge.positions)}]"
                    for edge in sorted(incoming.get(node_id, ()), key=lambda item: item.input_index)
                )
                lines.append(
                    f"  {node.node_id}: {node.label} <- {sources}{_annotation(node.annotation)}"
                )
        if "__cipher_output__" in incoming:
            edge = incoming["__cipher_output__"][0]
            node = diagram.node("__cipher_output__")
            lines.append(
                f"output <- {edge.source_id}[{format_positions(edge.positions)}]"
                f"{_annotation(node.annotation)}"
            )
        return "\n".join(lines) + "\n"


def _annotation(value: object | None) -> str:
    label = format_annotation(value)
    return "" if label is None else f"  # {label}"
