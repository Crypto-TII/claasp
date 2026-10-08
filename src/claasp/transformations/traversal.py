"""Dependency traversal for typed primitive graphs."""

from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType

from claasp.graph import Primitive, ValueType
from claasp.transformations.contracts import (
    TransformationError,
    TransformationFailureReason,
)


class GraphSourceKind(str, Enum):
    """The role of an addressable source in a typed graph.

    EXAMPLES::

        >>> GraphSourceKind.BINDING.value
        'binding'
    """

    INPUT = "input"
    COMPONENT = "component"
    BINDING = "binding"


@dataclass(frozen=True, slots=True)
class GraphSource:
    """One input, component output, or structural-binding output.

    EXAMPLES::

        >>> from claasp import Bit, ValueType
        >>> from claasp.transformations import GraphSource, GraphSourceKind
        >>> source = GraphSource("state", GraphSourceKind.INPUT, ValueType(Bit(), (4,)))
        >>> (source.source_id, source.value_type.unit_count)
        ('state', 4)
    """

    source_id: str
    kind: GraphSourceKind
    value_type: ValueType
    round_number: int | None = None
    scopes: tuple[str, ...] = ()


class DependencyIndex:
    """Immutable dependency index over components and structural bindings.

    The implementation uses only the Python standard library and never turns
    bindings into semantic components.

    EXAMPLES::

        >>> from claasp import Bit, PrimitiveBuilder, ValueType
        >>> from claasp.components import Identity
        >>> builder = PrimitiveBuilder("walk", {"state": ValueType(Bit(), (2,))})
        >>> builder.add_round()
        Round(number=0)
        >>> copied = builder.add_component(Identity(builder.input("state")))
        >>> primitive = builder.build(copied)
        >>> index = DependencyIndex(primitive)
        >>> index.topological_ids
        ('state', 'identity_0_0')
        >>> index.predecessors("identity_0_0")
        ('state',)
    """

    def __init__(self, primitive: Primitive) -> None:
        if not isinstance(primitive, Primitive):
            raise TypeError("dependency traversal requires a Primitive")
        self._primitive = primitive
        round_by_component = {
            component.component_id: primitive_round.number
            for primitive_round in primitive.graph.rounds
            for component in primitive_round.components
        }
        scope_by_component: dict[str, list[str]] = {}
        for scope in primitive.graph.scopes:
            for component_id in scope.component_ids:
                scope_by_component.setdefault(component_id, []).append(scope.path)

        sources: dict[str, GraphSource] = {}
        dependencies: dict[str, tuple[str, ...]] = {}
        order: list[str] = []
        for name, port in primitive.graph.input_ports.items():
            sources[name] = GraphSource(name, GraphSourceKind.INPUT, port.value_type)
            dependencies[name] = ()
            order.append(name)
        for binding in primitive.graph.bindings:
            source_id = binding.binding_id
            sources[source_id] = GraphSource(
                source_id,
                GraphSourceKind.BINDING,
                binding.output_type,
                scopes=tuple(
                    path for path in primitive._scopes if source_id.startswith(f"{path}/")
                ),
            )
            dependencies[source_id] = self._unique(item.source.owner_id for item in binding.inputs)
            order.append(source_id)
        for component in primitive.graph.components:
            source_id = component.component_id
            sources[source_id] = GraphSource(
                source_id,
                GraphSourceKind.COMPONENT,
                component.output_type,
                round_by_component[source_id],
                tuple(scope_by_component.get(source_id, ())),
            )
            dependencies[source_id] = self._unique(
                item.source.owner_id for item in component.inputs
            )
            order.append(source_id)

        missing = tuple(
            sorted(
                {dependency for values in dependencies.values() for dependency in values}
                - set(sources)
            )
        )
        if missing:
            raise TransformationError(
                TransformationFailureReason.DISCONNECTED_DEPENDENCY,
                "graph source depends on an unavailable source",
                source_ids=missing,
            )

        successors = {source_id: [] for source_id in sources}
        for target, predecessors in dependencies.items():
            for predecessor in predecessors:
                successors[predecessor].append(target)
        priority = {source_id: position for position, source_id in enumerate(order)}
        topological = self._topological(dependencies, successors, priority)
        self._sources = MappingProxyType(sources)
        self._predecessors = MappingProxyType(dependencies)
        self._successors = MappingProxyType(
            {key: tuple(value) for key, value in successors.items()}
        )
        self._topological_ids = topological

    @staticmethod
    def _unique(values: Iterable[str]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(values))

    @staticmethod
    def _topological(dependencies, successors, priority) -> tuple[str, ...]:
        remaining = {source_id: len(values) for source_id, values in dependencies.items()}
        ready = [source_id for source_id, count in remaining.items() if count == 0]
        ready.sort(key=priority.__getitem__)
        result = []
        while ready:
            source_id = ready.pop(0)
            result.append(source_id)
            newly_ready = []
            for successor in successors[source_id]:
                remaining[successor] -= 1
                if remaining[successor] == 0:
                    newly_ready.append(successor)
            ready.extend(newly_ready)
            ready.sort(key=priority.__getitem__)
        if len(result) != len(dependencies):
            stalled = tuple(source_id for source_id, count in remaining.items() if count)
            raise TransformationError(
                TransformationFailureReason.INVALID_GRAPH,
                "graph dependencies contain a cycle",
                source_ids=stalled,
            )
        return tuple(result)

    @property
    def sources(self) -> Mapping[str, GraphSource]:
        """All graph sources by stable identifier."""

        return self._sources

    @property
    def topological_ids(self) -> tuple[str, ...]:
        """Source ids in deterministic dependency order."""

        return self._topological_ids

    def source(self, source_id: str) -> GraphSource:
        """Resolve one source or report a disconnected boundary."""

        try:
            return self._sources[source_id]
        except KeyError as error:
            raise TransformationError(
                TransformationFailureReason.DISCONNECTED_DEPENDENCY,
                "graph source does not exist",
                source_ids=(source_id,),
            ) from error

    def predecessors(self, source_id: str) -> tuple[str, ...]:
        """Immediate dependencies of ``source_id``."""

        self.source(source_id)
        return self._predecessors[source_id]

    def successors(self, source_id: str) -> tuple[str, ...]:
        """Immediate consumers of ``source_id``."""

        self.source(source_id)
        return self._successors[source_id]

    def ancestors(self, source_ids: str | Iterable[str]) -> tuple[str, ...]:
        """Sources in the inclusive backward dependency closure."""

        return self._closure(source_ids, self._predecessors)

    def descendants(self, source_ids: str | Iterable[str]) -> tuple[str, ...]:
        """Sources in the inclusive forward dependency closure."""

        return self._closure(source_ids, self._successors)

    def _closure(self, source_ids, adjacency) -> tuple[str, ...]:
        requested = (source_ids,) if isinstance(source_ids, str) else tuple(source_ids)
        if not requested:
            raise TransformationError(
                TransformationFailureReason.AMBIGUOUS_BOUNDARY,
                "at least one boundary source is required",
            )
        for source_id in requested:
            self.source(source_id)
        visited = set(requested)
        queue = deque(requested)
        while queue:
            for source_id in adjacency[queue.popleft()]:
                if source_id not in visited:
                    visited.add(source_id)
                    queue.append(source_id)
        return tuple(source_id for source_id in self._topological_ids if source_id in visited)


__all__ = ["DependencyIndex", "GraphSource", "GraphSourceKind"]
