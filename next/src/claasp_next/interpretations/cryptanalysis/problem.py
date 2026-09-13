"""Backend-neutral cryptanalytic propagation problems and semantic registries."""

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, runtime_checkable

from claasp_next.components import BitVectorSBox, ModularAdd
from claasp_next.core import Cipher, Component
from claasp_next.interpretations.base import Interpretation, XOR_DIFFERENTIAL, XOR_LINEAR
from claasp_next.interpretations.cryptanalysis.trails import (
    ModularAddLinearSemantics, ModularAddTransitionSemantics,
    SBoxTransitionSemantics, Transition,
)


class PropagationObjective(str, Enum):
    """Optimization requested independently of a solver representation."""

    FEASIBILITY = "feasibility"
    MINIMIZE_WEIGHT = "minimize_weight"


@runtime_checkable
class TransitionProvider(Protocol):
    """Interpret one component transition without encoding it for a solver."""

    def transition(self, input_patterns: tuple[int, ...], output_pattern: int) -> Transition:
        """Return the exact semantic transition for boundary patterns."""


ProviderFactory = Callable[[Component], TransitionProvider]


@dataclass(frozen=True, slots=True)
class ComponentSemanticsBinding:
    """Bind one component class or instance to a semantic provider factory."""

    interpretation: Interpretation
    component_type: type[Component]
    factory: ProviderFactory
    component_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.interpretation, Interpretation):
            raise TypeError("binding interpretation must be an Interpretation")
        if not isinstance(self.component_type, type) or not issubclass(self.component_type, Component):
            raise TypeError("component_type must be a Component subclass")
        if not callable(self.factory):
            raise TypeError("provider factory must be callable")
        if self.component_id is not None and not self.component_id:
            raise ValueError("component_id override must not be empty")


@dataclass(frozen=True, slots=True)
class ComponentSemanticsRegistry:
    """Immutable global and per-component semantic model selection."""

    bindings: tuple[ComponentSemanticsBinding, ...] = ()

    def register(self, binding: ComponentSemanticsBinding) -> "ComponentSemanticsRegistry":
        """Return a registry where ``binding`` overrides earlier matches."""

        if not isinstance(binding, ComponentSemanticsBinding):
            raise TypeError("binding must be a ComponentSemanticsBinding")
        return ComponentSemanticsRegistry(self.bindings + (binding,))

    def provider(self, component: Component, interpretation: Interpretation) -> TransitionProvider:
        """Construct the most specific provider for a graph component."""

        matches = [
            binding
            for binding in self.bindings
            if binding.interpretation == interpretation
            and isinstance(component, binding.component_type)
            and binding.component_id in (None, component.component_id)
        ]
        if not matches:
            raise NotImplementedError(
                f"no {interpretation.name} semantics for {type(component).__name__}"
            )
        instance_matches = [binding for binding in matches if binding.component_id is not None]
        selected = (instance_matches or matches)[-1]
        provider = selected.factory(component)
        if not isinstance(provider, TransitionProvider):
            raise TypeError("provider factory did not return a TransitionProvider")
        return provider


@dataclass(frozen=True, slots=True, init=False)
class PropagationProblem:
    """A cipher interpretation, graph scope, objective, bound, and provenance."""

    cipher: Cipher
    interpretation: Interpretation
    component_ids: tuple[str, ...]
    objective: PropagationObjective
    maximum_weight: int | None
    registry: ComponentSemanticsRegistry
    provenance: tuple[str, ...]

    def __init__(
        self,
        cipher: Cipher,
        interpretation: Interpretation,
        *,
        component_ids: Iterable[str] | None = None,
        objective: PropagationObjective = PropagationObjective.MINIMIZE_WEIGHT,
        maximum_weight: int | None = None,
        registry: ComponentSemanticsRegistry | None = None,
        provenance: Iterable[str] = (),
    ) -> None:
        if not isinstance(cipher, Cipher):
            raise TypeError("cipher must be a Cipher")
        if interpretation not in (XOR_DIFFERENTIAL, XOR_LINEAR):
            raise ValueError("the initial propagation problem supports XOR differential or linear interpretations")
        if not isinstance(objective, PropagationObjective):
            raise TypeError("objective must be a PropagationObjective")
        if maximum_weight is not None and (
            not isinstance(maximum_weight, int) or isinstance(maximum_weight, bool) or maximum_weight < 0
        ):
            raise ValueError("maximum_weight must be a nonnegative integer or None")
        identifiers = tuple(
            component.component_id for component in cipher.components
        ) if component_ids is None else tuple(component_ids)
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("propagation component IDs must be unique")
        known = {component.component_id for component in cipher.components}
        if unknown := set(identifiers) - known:
            raise ValueError(f"unknown propagation components: {sorted(unknown)!r}")
        selected_registry = registry or default_component_semantics()
        if not isinstance(selected_registry, ComponentSemanticsRegistry):
            raise TypeError("registry must be a ComponentSemanticsRegistry")
        frozen_provenance = tuple(provenance)
        if any(not item for item in frozen_provenance):
            raise ValueError("provenance entries must not be empty")
        object.__setattr__(self, "cipher", cipher)
        object.__setattr__(self, "interpretation", interpretation)
        object.__setattr__(self, "component_ids", identifiers)
        object.__setattr__(self, "objective", objective)
        object.__setattr__(self, "maximum_weight", maximum_weight)
        object.__setattr__(self, "registry", selected_registry)
        object.__setattr__(self, "provenance", frozen_provenance)

    @property
    def components(self) -> tuple[Component, ...]:
        """Return scoped graph components in cipher order."""

        selected = set(self.component_ids)
        return tuple(component for component in self.cipher.components if component.component_id in selected)

    def provider_for(self, component: Component) -> TransitionProvider:
        """Resolve this problem's selected semantics for ``component``."""

        if component.component_id not in self.component_ids:
            raise ValueError("component is outside this propagation problem's scope")
        return self.registry.provider(component, self.interpretation)


class _SBoxProvider:
    def __init__(self, component: BitVectorSBox, interpretation: Interpretation) -> None:
        self.semantics = SBoxTransitionSemantics(component.table)
        self.interpretation = interpretation

    def transition(self, input_patterns: tuple[int, ...], output_pattern: int) -> Transition:
        if len(input_patterns) != 1:
            raise ValueError("an S-box transition requires one input pattern")
        operation = (
            self.semantics.xor_differential
            if self.interpretation == XOR_DIFFERENTIAL
            else self.semantics.xor_linear
        )
        return operation(input_patterns[0], output_pattern)


class _ModularAddProvider:
    def __init__(self, component: ModularAdd, interpretation: Interpretation) -> None:
        self.interpretation = interpretation
        width = component.output_type.domain.width
        self.semantics = (
            ModularAddTransitionSemantics(width)
            if interpretation == XOR_DIFFERENTIAL
            else ModularAddLinearSemantics(width)
        )

    def transition(self, input_patterns: tuple[int, ...], output_pattern: int) -> Transition:
        if len(input_patterns) != 2:
            raise ValueError("the initial modular-add semantics requires two inputs")
        operation = (
            self.semantics.xor_differential
            if self.interpretation == XOR_DIFFERENTIAL
            else self.semantics.xor_linear
        )
        return operation(*input_patterns, output_pattern)


def default_component_semantics() -> ComponentSemanticsRegistry:
    """Return reviewed exact bindings for currently supported components."""

    registry = ComponentSemanticsRegistry()
    for interpretation in (XOR_DIFFERENTIAL, XOR_LINEAR):
        registry = registry.register(ComponentSemanticsBinding(
            interpretation, BitVectorSBox,
            lambda component, meaning=interpretation: _SBoxProvider(component, meaning),
        ))
        registry = registry.register(ComponentSemanticsBinding(
            interpretation, ModularAdd,
            lambda component, meaning=interpretation: _ModularAddProvider(component, meaning),
        ))
    return registry
