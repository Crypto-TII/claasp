"""Dependency-free routed ASCII serialization of primitive diagrams."""

from claasp.representations.diagrams.formatting import format_annotation, format_positions
from claasp.representations.diagrams.model import DiagramNode, PrimitiveDiagram


class ASCIIArtSerializer:
    """Render diagram nodes as boxes with deterministic dependency routes.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> from claasp.representations.diagrams import ASCIIArtSerializer
        >>> ASCIIArtSerializer().serialize(Speck(number_of_rounds=1).diagram()).startswith("primitive speck\\n")
        True
    """

    def serialize(self, diagram: PrimitiveDiagram) -> str:
        """Return stable box-and-connector ASCII art for the diagram IR."""

        if not isinstance(diagram, PrimitiveDiagram):
            raise TypeError("diagram must be a PrimitiveDiagram")
        lines = [f"primitive {diagram.primitive_name}", "inputs"]
        for node in diagram.nodes:
            if node.kind == "input":
                lines.extend(_indent(_box(node), 2))

        incoming = {}
        for edge in diagram.edges:
            incoming.setdefault(edge.destination_id, []).append(edge)
        for group in diagram.rounds:
            lines.append(f"round {group.number}")
            for node_id in group.node_ids:
                edges = sorted(incoming.get(node_id, ()), key=lambda item: item.input_index)
                routes = tuple(
                    f"[{edge.input_index}] {edge.source_id}[{format_positions(edge.positions)}]"
                    for edge in edges
                )
                lines.extend(_routed_box(routes, _box(diagram.node(node_id))))

        if "__primitive_output__" in incoming:
            edge = incoming["__primitive_output__"][0]
            route = f"[{edge.input_index}] {edge.source_id}[{format_positions(edge.positions)}]"
            lines.append("output")
            lines.extend(_routed_box((route,), _box(diagram.node("__primitive_output__"))))
        return "\n".join(lines) + "\n"


def _box(node: DiagramNode) -> tuple[str, ...]:
    contents = [node.label if node.kind in {"input", "output"} else node.node_id]
    if node.kind not in {"input", "output"} and node.label != node.node_id:
        contents.append(node.label)
    annotation = format_annotation(node.annotation)
    if annotation is not None:
        contents.append(f"# {annotation}")
    width = max(len(content) for content in contents)
    border = "+-" + "-" * width + "-+"
    return (border, *(f"| {content:<{width}} |" for content in contents), border)


def _routed_box(routes: tuple[str, ...], box: tuple[str, ...]) -> tuple[str, ...]:
    if not routes:
        return _indent(box, 2)
    width = max(len(route) for route in routes)
    lines = [f"  {route:<{width}} --+" for route in routes[:-1]]
    connector = "-->" if len(routes) == 1 else "--+-->"
    prefix = f"  {routes[-1]:<{width}} {connector} "
    lines.append(prefix + box[0])
    lines.extend(" " * len(prefix) + line for line in box[1:])
    return tuple(lines)


def _indent(lines: tuple[str, ...], amount: int) -> tuple[str, ...]:
    prefix = " " * amount
    return tuple(prefix + line for line in lines)
