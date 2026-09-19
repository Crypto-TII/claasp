"""Backend-neutral cryptanalytic propagation problems and semantic registries."""

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, runtime_checkable

from claasp_next.components import BitVectorSBox, BitwiseAnd, ModularAdd
from claasp_next.semantics.cryptanalysis.bitwise import BitwiseAndSemantics
from claasp_next.graph import Primitive, Component
from claasp_next.semantics.base import (
    DETERMINISTIC_TRUNCATED_XOR,
    PROBABILISTIC_TRUNCATED_XOR,
    SemanticType,
    XOR_DIFFERENTIAL,
    XOR_LINEAR,
)
from claasp_next.semantics.cryptanalysis.trails import (
    ModularAddLinearSemantics, ModularAddTransitionSemantics,
    SBoxTransitionSemantics, Transition,
)


class PropagationObjective(str, Enum):
    """Optimization requested independently of a solver representation.

    EXAMPLES::

        >>> from claasp_next.semantics.cryptanalysis import PropagationObjective
        >>> PropagationObjective.MINIMIZE_WEIGHT.value
        'minimize_weight'
    """

    FEASIBILITY = "feasibility"
    MINIMIZE_WEIGHT = "minimize_weight"


@runtime_checkable
class TransitionProvider(Protocol):
    """Interpret one component transition without encoding it for a solver.

    EXAMPLES::

        >>> from claasp_next.semantics.cryptanalysis import TransitionProvider
        >>> class Provider:
        ...     def transition(self, input_patterns, output_pattern):
        ...         return None
        >>> isinstance(Provider(), TransitionProvider)
        True
    """

    def transition(self, input_patterns: tuple[int, ...], output_pattern: int) -> Transition:
        """Return the exact semantic transition for boundary patterns."""


ProviderFactory = Callable[[Component], TransitionProvider]


@dataclass(frozen=True, slots=True)
class ComponentSemanticsBinding:
    """Bind one component class or instance to a semantic provider factory.

    EXAMPLES::

        >>> from claasp_next.components import BitVectorSBox
        >>> from claasp_next.semantics import XOR_DIFFERENTIAL
        >>> from claasp_next.semantics.cryptanalysis import ComponentSemanticsBinding
        >>> binding = ComponentSemanticsBinding(XOR_DIFFERENTIAL, BitVectorSBox, lambda component: None)
        >>> binding.semantics.name
        'xor_differential'
    """

    semantics: SemanticType
    component_type: type[Component]
    factory: ProviderFactory
    component_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.semantics, SemanticType):
            raise TypeError("binding semantics must be a SemanticType")
        if not isinstance(self.component_type, type) or not issubclass(self.component_type, Component):
            raise TypeError("component_type must be a Component subclass")
        if not callable(self.factory):
            raise TypeError("provider factory must be callable")
        if self.component_id is not None and not self.component_id:
            raise ValueError("component_id override must not be empty")


@dataclass(frozen=True, slots=True)
class ComponentSemanticsRegistry:
    """Immutable global and per-component semantic model selection.

    EXAMPLES::

        >>> from claasp_next.components import BitVectorSBox
        >>> from claasp_next.primitives import Present
        >>> from claasp_next.semantics import XOR_DIFFERENTIAL
        >>> from claasp_next.semantics.cryptanalysis import default_component_semantics
        >>> component = next(item for item in Present(number_of_rounds=1).components
        ...     if isinstance(item, BitVectorSBox))
        >>> default_component_semantics().provider(component, XOR_DIFFERENTIAL).transition((1,), 3).weight
        2.0
    """

    bindings: tuple[ComponentSemanticsBinding, ...] = ()

    def register(self, binding: ComponentSemanticsBinding) -> "ComponentSemanticsRegistry":
        """Return a registry where ``binding`` overrides earlier matches."""

        if not isinstance(binding, ComponentSemanticsBinding):
            raise TypeError("binding must be a ComponentSemanticsBinding")
        return ComponentSemanticsRegistry(self.bindings + (binding,))

    def provider(self, component: Component, semantics: SemanticType) -> TransitionProvider:
        """Construct the most specific provider for a graph component."""

        matches = [
            binding
            for binding in self.bindings
            if binding.semantics == semantics
            and isinstance(component, binding.component_type)
            and binding.component_id in (None, component.component_id)
        ]
        if not matches:
            raise NotImplementedError(
                f"no {semantics.name} semantics for {type(component).__name__}"
            )
        instance_matches = [binding for binding in matches if binding.component_id is not None]
        selected = (instance_matches or matches)[-1]
        provider = selected.factory(component)
        if not isinstance(provider, TransitionProvider):
            raise TypeError("provider factory did not return a TransitionProvider")
        return provider


@dataclass(frozen=True, slots=True, init=False)
class PropagationProblem:
    """A primitive semantics, graph scope, objective, bound, and provenance.

    EXAMPLES::

        >>> from claasp_next.components import BitVectorSBox
        >>> from claasp_next.primitives import Present
        >>> from claasp_next.semantics import XOR_DIFFERENTIAL
        >>> from claasp_next.semantics.cryptanalysis import PropagationProblem
        >>> primitive = Present(number_of_rounds=1)
        >>> component = next(item for item in primitive.components if isinstance(item, BitVectorSBox))
        >>> problem = PropagationProblem(primitive, XOR_DIFFERENTIAL,
        ...     component_ids=(component.component_id,), provenance=("reviewed",))
        >>> problem.provider_for(component).transition((1,), 3).weight
        2.0
    """

    primitive: Primitive
    semantics: SemanticType
    component_ids: tuple[str, ...]
    objective: PropagationObjective
    maximum_weight: int | None
    registry: ComponentSemanticsRegistry
    provenance: tuple[str, ...]

    def __init__(
        self,
        primitive: Primitive,
        semantics: SemanticType,
        *,
        component_ids: Iterable[str] | None = None,
        objective: PropagationObjective = PropagationObjective.MINIMIZE_WEIGHT,
        maximum_weight: int | None = None,
        registry: ComponentSemanticsRegistry | None = None,
        provenance: Iterable[str] = (),
    ) -> None:
        if not isinstance(primitive, Primitive):
            raise TypeError("primitive must be a Primitive")
        if semantics not in (
            XOR_DIFFERENTIAL, XOR_LINEAR, DETERMINISTIC_TRUNCATED_XOR,
            PROBABILISTIC_TRUNCATED_XOR,
        ):
            raise ValueError(
                "propagation problems support XOR differential, linear, or "
                "deterministic- or probabilistic-truncated semantic types"
            )
        if not isinstance(objective, PropagationObjective):
            raise TypeError("objective must be a PropagationObjective")
        if maximum_weight is not None and (
            not isinstance(maximum_weight, int) or isinstance(maximum_weight, bool) or maximum_weight < 0
        ):
            raise ValueError("maximum_weight must be a nonnegative integer or None")
        identifiers = tuple(
            component.component_id for component in primitive.components
        ) if component_ids is None else tuple(component_ids)
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("propagation component IDs must be unique")
        known = {component.component_id for component in primitive.components}
        if unknown := set(identifiers) - known:
            raise ValueError(f"unknown propagation components: {sorted(unknown)!r}")
        selected_registry = registry or default_component_semantics()
        if not isinstance(selected_registry, ComponentSemanticsRegistry):
            raise TypeError("registry must be a ComponentSemanticsRegistry")
        frozen_provenance = tuple(provenance)
        if any(not item for item in frozen_provenance):
            raise ValueError("provenance entries must not be empty")
        object.__setattr__(self, "primitive", primitive)
        object.__setattr__(self, "semantics", semantics)
        object.__setattr__(self, "component_ids", identifiers)
        object.__setattr__(self, "objective", objective)
        object.__setattr__(self, "maximum_weight", maximum_weight)
        object.__setattr__(self, "registry", selected_registry)
        object.__setattr__(self, "provenance", frozen_provenance)

    @property
    def components(self) -> tuple[Component, ...]:
        """Return scoped graph components in primitive order."""

        selected = set(self.component_ids)
        return tuple(component for component in self.primitive.components if component.component_id in selected)

    def provider_for(self, component: Component) -> TransitionProvider:
        """Resolve this problem's selected semantics for ``component``."""

        if component.component_id not in self.component_ids:
            raise ValueError("component is outside this propagation problem's scope")
        return self.registry.provider(component, self.semantics)


class _SBoxProvider:
    def __init__(self, component: BitVectorSBox, semantics: SemanticType) -> None:
        self.transition_semantics = SBoxTransitionSemantics(component.table)
        self.semantic_type = semantics

    def transition(self, input_patterns: tuple[int, ...], output_pattern: int) -> Transition:
        if len(input_patterns) != 1:
            raise ValueError("an S-box transition requires one input pattern")
        operation = (
            self.transition_semantics.xor_differential
            if self.semantic_type == XOR_DIFFERENTIAL
            else self.transition_semantics.xor_linear
        )
        return operation(input_patterns[0], output_pattern)


class _ModularAddProvider:
    def __init__(self, component: ModularAdd, semantics: SemanticType) -> None:
        self.semantic_type = semantics
        width = component.output_type.domain.width
        self.transition_semantics = (
            ModularAddTransitionSemantics(width)
            if semantics == XOR_DIFFERENTIAL
            else ModularAddLinearSemantics(width)
        )

    def transition(self, input_patterns: tuple[int, ...], output_pattern: int) -> Transition:
        if len(input_patterns) != 2:
            raise ValueError("the initial modular-add semantics requires two inputs")
        operation = (
            self.transition_semantics.xor_differential
            if self.semantic_type == XOR_DIFFERENTIAL
            else self.transition_semantics.xor_linear
        )
        return operation(*input_patterns, output_pattern)


class _BitwiseAndProvider(_ModularAddProvider):
    def __init__(self, component, semantics):
        self.semantic_type = semantics
        self.transition_semantics = BitwiseAndSemantics(component.output_type.domain.width)

    def transition(self, input_patterns, output_pattern):
        if len(input_patterns) != 2:
            raise ValueError("AND semantics requires two input patterns")
        return super().transition(input_patterns, output_pattern)


def default_component_semantics() -> ComponentSemanticsRegistry:
    """Return reviewed exact bindings for currently supported components.

    EXAMPLES::

        >>> from claasp_next.semantics.cryptanalysis import default_component_semantics
        >>> len(default_component_semantics().bindings)
        6
    """

    registry = ComponentSemanticsRegistry()
    for semantics in (XOR_DIFFERENTIAL, XOR_LINEAR):
        registry = registry.register(ComponentSemanticsBinding(
            semantics, BitVectorSBox,
            lambda component, meaning=semantics: _SBoxProvider(component, meaning),
        ))
        registry = registry.register(ComponentSemanticsBinding(
            semantics, ModularAdd,
            lambda component, meaning=semantics: _ModularAddProvider(component, meaning),
        ))
        registry = registry.register(ComponentSemanticsBinding(
            semantics, BitwiseAnd,
            lambda component, meaning=semantics: _BitwiseAndProvider(component, meaning),
        ))
    return registry
