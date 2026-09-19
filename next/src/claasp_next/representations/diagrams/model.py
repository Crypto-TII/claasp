"""Backend-neutral diagram representation for annotated primitive graphs."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DiagramNode:
    """One input, component, or output in a diagram.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (DiagramNode.__dataclass_params__.frozen, tuple(field.name for field in fields(DiagramNode)))
        (True, ('node_id', 'label', 'kind', 'round_number', 'annotation'))
    """

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
    """A selection-level dependency between two diagram nodes.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (DiagramEdge.__dataclass_params__.frozen, tuple(field.name for field in fields(DiagramEdge)))
        (True, ('source_id', 'destination_id', 'positions', 'input_index'))
    """

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
    """An ordered round group in a diagram.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (DiagramRound.__dataclass_params__.frozen, tuple(field.name for field in fields(DiagramRound)))
        (True, ('number', 'node_ids'))
    """

    number: int
    node_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PrimitiveDiagram:
    """Validated nodes, selection edges, and round groups.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (PrimitiveDiagram.__dataclass_params__.frozen, tuple(field.name for field in fields(PrimitiveDiagram)))
        (True, ('primitive_name', 'nodes', 'edges', 'rounds'))
    """

    primitive_name: str
    nodes: tuple[DiagramNode, ...]
    edges: tuple[DiagramEdge, ...]
    rounds: tuple[DiagramRound, ...]

    def __post_init__(self) -> None:
        identifiers = tuple(node.node_id for node in self.nodes)
        if not self.primitive_name or len(set(identifiers)) != len(identifiers):
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
