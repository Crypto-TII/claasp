"""Standalone TikZ serialization of primitive diagram representations."""

import re

from claasp.representations.diagrams.formatting import format_annotation, format_positions
from claasp.representations.diagrams.model import PrimitiveDiagram


class TikZSerializer:
    """Render a diagram as a compilable LaTeX document.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> from claasp.representations.diagrams import TikZSerializer
        >>> TikZSerializer().serialize(Speck(number_of_rounds=1).diagram()).startswith("\\\\documentclass")
        True
    """

    def serialize(self, diagram: PrimitiveDiagram) -> str:
        """Return deterministic TikZ with no external Python dependencies."""

        if not isinstance(diagram, PrimitiveDiagram):
            raise TypeError("diagram must be a PrimitiveDiagram")
        coordinates = _coordinates(diagram)
        names = {node.node_id: f"n{index}" for index, node in enumerate(diagram.nodes)}
        lines = [
            r"\documentclass{article}",
            r"\usepackage{tikz}",
            r"\usetikzlibrary{arrows.meta,positioning}",
            r"\pagestyle{empty}",
            r"\begin{document}",
            r"\begin{tikzpicture}[>=Latex,component/.style={draw,rounded corners,align=center,font=\scriptsize},annotated/.style={fill=yellow!20}]",
        ]
        for node in diagram.nodes:
            x, y = coordinates[node.node_id]
            style = "component,annotated" if node.annotation is not None else "component"
            annotation = format_annotation(node.annotation)
            label = _escape(node.label)
            if annotation is not None:
                label += r"\\{\tiny " + _escape(annotation) + "}"
            lines.append(f"\\node[{style}] ({names[node.node_id]}) at ({x},{y}) {{{label}}};")
        for edge in diagram.edges:
            label = _escape(format_positions(edge.positions))
            lines.append(
                f"\\draw[->] ({names[edge.source_id]}) -- node[above,font=\\tiny] {{{label}}} ({names[edge.destination_id]});"
            )
        lines.extend((r"\end{tikzpicture}", r"\end{document}", ""))
        return "\n".join(lines)


def _coordinates(diagram: PrimitiveDiagram):
    coordinates = {}
    inputs = [node for node in diagram.nodes if node.kind == "input"]
    for index, node in enumerate(inputs):
        coordinates[node.node_id] = (0, -2 * index)
    for group in diagram.rounds:
        for index, node_id in enumerate(group.node_ids):
            coordinates[node_id] = (2 * (group.number + 1), -1.2 * index)
    output = next((node for node in diagram.nodes if node.kind == "output"), None)
    if output is not None:
        coordinates[output.node_id] = (2 * (len(diagram.rounds) + 1), 0)
    return coordinates


def _escape(value: str) -> str:
    replacements = {
        "\\": r"\textbackslash{}",
        "_": r"\_",
        "%": r"\%",
        "#": r"\#",
        "&": r"\&",
        "{": r"\{",
        "}": r"\}",
    }
    return re.sub(r"[\\_%#&{}]", lambda match: replacements[match.group()], value)
