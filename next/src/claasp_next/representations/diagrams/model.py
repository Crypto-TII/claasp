"""Backend-neutral diagram representation for annotated cipher graphs."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DiagramNode:
    """One input, component, or output in a diagram."""

    node_id: str
    label: str
    kind: str
    round_number: int | None
    annotation: object | None = None

    def __post_init__(self) -> None:
        if not self.node_id or not self.label or not self.kind:
            raise ValueError("diagram node ID, label, and kind must not be empty")
        if self.round_number is not None and self.round_number < 0:
            raise ValueError("diagram round numbers must be nonnegative")


@dataclass(frozen=True, slots=True)
class DiagramEdge:
    """A selection-level dependency between two diagram nodes."""

    source_id: str
    destination_id: str
    positions: tuple[int, ...]
    input_index: int

    def __post_init__(self) -> None:
        if not self.source_id or not self.destination_id:
            raise ValueError("diagram edge endpoints must not be empty")
        if not self.positions or any(position < 0 for position in self.positions):
            raise ValueError("diagram edge positions must be nonempty and nonnegative")
        if self.input_index < 0:
            raise ValueError("diagram edge input_index must be nonnegative")


@dataclass(frozen=True, slots=True)
class DiagramRound:
    """An ordered round group in a diagram."""

    number: int
    node_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CipherDiagram:
    """Validated nodes, selection edges, and round groups."""

    cipher_name: str
    nodes: tuple[DiagramNode, ...]
    edges: tuple[DiagramEdge, ...]
    rounds: tuple[DiagramRound, ...]

    def __post_init__(self) -> None:
        identifiers = tuple(node.node_id for node in self.nodes)
        if not self.cipher_name or len(set(identifiers)) != len(identifiers):
            raise ValueError("diagram name must be nonempty and node IDs unique")
        known = set(identifiers)
        if any(edge.source_id not in known or edge.destination_id not in known for edge in self.edges):
            raise ValueError("every diagram edge must connect declared nodes")
        grouped = tuple(node_id for group in self.rounds for node_id in group.node_ids)
        component_ids = tuple(node.node_id for node in self.nodes if node.round_number is not None)
        if grouped != component_ids:
            raise ValueError("diagram round groups must cover components in node order")

    def node(self, node_id: str) -> DiagramNode:
        """Return one node by its stable graph-derived identifier."""

        for node in self.nodes:
            if node.node_id == node_id:
                return node
        raise KeyError(f"diagram node {node_id!r} does not exist")
