"""Convenient selection and reporting over exact component-property contracts."""

import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from claasp.analysis.component_properties import (
    ComponentAnalysisProvenance,
    ComponentGroup,
    ComponentProperty,
    ComponentPropertyResult,
    PropertyClaim,
    PropertyDomain,
    PropertyRequest,
    _default_component_requests,
    _rectangular_ddt,
    _semantic_key_identity,
    analyze_component_property,
    semantic_component_groups,
    semantic_component_key,
)

if TYPE_CHECKING:
    from claasp.drivers.renderers.presentation import FigureArtifact


@dataclass(frozen=True, slots=True)
class ComponentPropertiesResult:
    """Selected properties with compact terminal reporting and retained evidence.

    EXAMPLES::

        >>> from claasp.primitives import Present
        >>> result = Present(number_of_rounds=1).analysis.component("sbox").properties("nonlinearity")
        >>> result[0].value, result[0].claim.value
        (4, 'exact')
    """

    component_name: str
    results: tuple[ComponentPropertyResult, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "results", tuple(self.results))
        if not self.results:
            raise ValueError("a property report requires at least one result")

    def __iter__(self) -> Iterator[ComponentPropertyResult]:
        return iter(self.results)

    def __getitem__(self, index: int) -> ComponentPropertyResult:
        return self.results[index]

    def __len__(self) -> int:
        return len(self.results)

    def to_terminal(self, *, details: bool = False, file: TextIO | None = None) -> None:
        """Print selected values with their evidence; details include provenance.

        EXAMPLES::

            >>> from io import StringIO
            >>> from claasp.primitives import Present
            >>> output = StringIO()
            >>> Present(number_of_rounds=1).analysis.component("sbox").properties("nonlinearity").to_terminal(file=output)
            >>> "nonlinearity" in output.getvalue()
            True
        """
        from claasp.presentation._terminal import to_terminal
        from claasp.presentation.adapters import _component_properties_section

        to_terminal(_component_properties_section(self, details=details), file=file)


@dataclass(frozen=True, slots=True)
class ComponentTableResult:
    """An exact S-box DDT, reusable for terminal reporting and heatmaps.

    Rows index input XOR differences and columns output XOR differences.
    ``counts`` retains the zero-input row even when a plot omits it.

    EXAMPLES::

        >>> from claasp.primitives import Present
        >>> ddt = Present(number_of_rounds=1).analysis.component("sbox").ddt()
        >>> sum(ddt.counts[1]), max(ddt.counts[1]), ddt.claim.value
        (16, 4, 'exact')
    """

    component_name: str
    input_bit_size: int
    output_bit_size: int
    counts: tuple[tuple[int, ...], ...]
    provenance: ComponentAnalysisProvenance

    def __post_init__(self) -> None:
        for width in (self.input_bit_size, self.output_bit_size):
            if not isinstance(width, int) or isinstance(width, bool) or width <= 0:
                raise ValueError("DDT widths must be positive integers")
        counts = tuple(tuple(row) for row in self.counts)
        if len(counts) != 1 << self.input_bit_size or any(
            len(row) != 1 << self.output_bit_size for row in counts
        ):
            raise ValueError("DDT dimensions must match input and output widths")
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for row in counts
            for value in row
        ):
            raise ValueError("DDT counts must be nonnegative integers")
        if any(sum(row) != 1 << self.input_bit_size for row in counts):
            raise ValueError("each DDT row must count every input")
        object.__setattr__(self, "counts", counts)

    @property
    def claim(self) -> PropertyClaim:
        """Return exact evidence for this exhaustively counted table."""
        return PropertyClaim.EXACT

    def to_terminal(self, *, include_zero: bool = False, file: TextIO | None = None) -> None:
        """Print exact counts, optionally including the trivial zero-input row."""
        from claasp.presentation._terminal import to_terminal
        from claasp.presentation.adapters import _component_table_section

        to_terminal(_component_table_section(self, include_zero=include_zero), file=file)

    def plot(
        self,
        *,
        include_zero: bool = False,
        scale: str = "counts",
        show: bool = True,
        save_to: str | Path | None = None,
    ) -> "FigureArtifact":
        """Display the retained DDT as a heatmap; no analysis is repeated.

        ``scale="probability"`` divides counts by the input table size.
        ``show=False`` supports headless use; ``save_to`` saves before display.
        """
        from claasp.drivers.renderers.presentation import _plot_component_ddt

        return _plot_component_ddt(
            self, include_zero=include_zero, scale=scale, show=show, save_to=save_to
        )


@dataclass(frozen=True, slots=True)
class ComponentAnalysis:
    """Analyze one semantic group selected from a primitive or composite.

    Default domains follow typed semantics: lookup tables for S-boxes, bit
    weights for bit maps, and word weights for finite-field maps.

    EXAMPLES::

        >>> from claasp.primitives import Present
        >>> sbox = Present(number_of_rounds=2).analysis.component("sbox")
        >>> sbox.count, sbox.properties("differential_uniformity")[0].value
        (34, 4)
    """

    group: ComponentGroup
    primitive_family: str
    realization: str

    @property
    def count(self) -> int:
        """Return how many equivalent operations occur in the graph."""
        return self.group.count

    def properties(
        self,
        *names: str | ComponentProperty,
        domain: str | PropertyDomain | None = None,
        maximum_input_weight: int | None = None,
        maximum_vectors: int | None = None,
        maximum_steps: int | None = None,
    ) -> ComponentPropertiesResult:
        """Compute named properties, or the component's defaults when omitted.

        ``maximum_input_weight`` explicitly requests bounded branch enumeration.
        ``maximum_vectors`` and ``maximum_steps`` configure the corresponding
        exact branch-number and matrix-order calculations.

        EXAMPLES::

            >>> from claasp.composites import AESRound
            >>> mix = AESRound().analyze().component("linear_map")
            >>> bound = mix.properties("differential_branch_number", maximum_input_weight=1)
            >>> bound[0].value, bound[0].claim.value
            (5, 'proved_upper_bound')
        """
        component = self.group.representative
        defaults = _default_component_requests(component)
        if not names:
            names = tuple(request.property for request in defaults)
        if not names:
            raise ValueError("no default properties; specify property names and a domain")
        selected_domain = (
            PropertyDomain(domain) if domain is not None else _component_domain(component)
        )
        properties = tuple(ComponentProperty(name) for name in names)
        branches = {
            ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER,
            ComponentProperty.LINEAR_BRANCH_NUMBER,
        }
        if maximum_vectors is not None and not any(name in branches for name in properties):
            raise ValueError("maximum_vectors requires a branch-number property")
        if maximum_steps is not None and ComponentProperty.ORDER not in properties:
            raise ValueError("maximum_steps requires the order property")
        driver = None
        if maximum_input_weight is not None:
            if any(name not in branches for name in properties):
                raise ValueError("maximum_input_weight applies only to branch-number properties")
            if maximum_vectors is not None:
                raise ValueError("choose bounded input weight or exact maximum_vectors")
            from claasp.drivers.analysis import BoundedBranchNumberDriver

            driver = BoundedBranchNumberDriver(maximum_input_weight=maximum_input_weight)
        results = []
        for property_ in properties:
            options: tuple[tuple[str, object], ...] = ()
            if property_ in branches and maximum_vectors is not None:
                options = (("maximum_vectors", maximum_vectors),)
            elif property_ is ComponentProperty.ORDER and maximum_steps is not None:
                options = (("maximum_steps", maximum_steps),)
            request = PropertyRequest(property_, selected_domain, options)
            if driver is None:
                result = analyze_component_property(
                    component,
                    request,
                    graph_locations=self._locations(),
                    primitive=self.primitive_family,
                    realization=self.realization,
                )
            else:
                from dataclasses import replace

                result = driver.analyze(component, request)
                result = replace(
                    result,
                    provenance=replace(
                        result.provenance,
                        graph_locations=self._locations(),
                        primitive=self.primitive_family,
                        realization=self.realization,
                    ),
                )
            results.append(result)
        return ComponentPropertiesResult(type(component).__name__, tuple(results))

    def ddt(self) -> ComponentTableResult:
        """Count all S-box XOR differential transitions exactly.

        EXAMPLES::

            >>> from claasp.primitives import Present
            >>> ddt = Present(number_of_rounds=1).analysis.component("sbox").ddt()
            >>> max(max(row) for row in ddt.counts[1:])
            4
        """
        from claasp.components import BitVectorSBox, SBox

        component = self.group.representative
        if not isinstance(component, (BitVectorSBox, SBox)):
            raise ValueError("ddt() requires an S-box component")
        if isinstance(component, SBox):
            input_width = component.inputs[0].array_type.unit_type.encoded_bit_size
            output_width = component.output_type.unit_type.encoded_bit_size
        else:
            input_width = component.inputs[0].array_type.encoded_bit_size
            output_width = component.output_type.encoded_bit_size
        if input_width is None or output_width is None:
            raise ValueError("S-box domains must have canonical bit encodings")
        counts = _rectangular_ddt(component.table, 1 << input_width, 1 << output_width)
        provenance = ComponentAnalysisProvenance(
            _semantic_key_identity(semantic_component_key(component, PropertyDomain.LOOKUP_TABLE)),
            "exact_exhaustive_ddt",
            self.primitive_family,
            self.realization,
            self._locations(),
        )
        return ComponentTableResult(
            type(component).__name__, input_width, output_width, counts, provenance
        )

    def _locations(self) -> tuple[str, ...]:
        return tuple(
            item.graph_location
            for item in self.group.occurrences
            if item.graph_location is not None
        )


def _component_domain(component):
    from claasp.components import (
        BinaryAffineMap,
        BitVectorSBox,
        FeedbackRegister,
        LinearMap,
        Permutation,
        SBox,
    )
    from claasp.unit_types import Bit

    if isinstance(component, (BitVectorSBox, SBox)):
        return PropertyDomain.LOOKUP_TABLE
    if isinstance(component, (LinearMap, BinaryAffineMap, Permutation)):
        return (
            PropertyDomain.BIT_LINEAR
            if isinstance(component, BinaryAffineMap)
            or isinstance(component.inputs[0].array_type.unit_type, Bit)
            else PropertyDomain.WORD_LINEAR
        )
    if isinstance(component, FeedbackRegister):
        return PropertyDomain.FEEDBACK_REGISTER
    from claasp.components.word import (
        BitwiseAnd,
        BitwiseNot,
        BitwiseOr,
        ModularAdd,
        Rotate,
        Shift,
        Xor,
    )

    if isinstance(component, (BitwiseAnd, BitwiseNot, BitwiseOr, ModularAdd, Rotate, Shift, Xor)):
        return PropertyDomain.WORD_OPERATION
    raise ValueError("cannot infer a property domain; specify domain explicitly")


def _component_kind(component):
    from claasp.components import BitVectorSBox, SBox

    if isinstance(component, (BitVectorSBox, SBox)):
        return "sbox"
    name = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", type(component).__name__)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower()


def _select_component(primitive, kind, *, index=None, bit_size=None):
    if not isinstance(kind, str) or not kind:
        raise ValueError("component kind must be a nonempty name, such as 'sbox'")
    for name, value in (("index", index), ("bit_size", bit_size)):
        if value is not None and (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < (0 if name == "index" else 1)
        ):
            raise ValueError(f"{name} must be {'nonnegative' if name == 'index' else 'positive'}")
    normalized = kind.replace("_", "").lower()
    groups = tuple(
        group
        for group in semantic_component_groups(primitive, PropertyDomain.BOOLEAN)
        if (
            _component_kind(group.representative).replace("_", "") == normalized
            or type(group.representative).__name__.lower() == normalized
        )
        and (bit_size is None or group.representative.output_type.encoded_bit_size == bit_size)
    )
    if not groups:
        raise ValueError(
            f"no component group matches {kind!r}; inspect component_analysis().to_terminal()"
        )
    if index is None:
        if len(groups) != 1:
            raise ValueError(
                f"{len(groups)} component groups match {kind!r}; specify bit_size or index"
            )
        index = 0
    if index >= len(groups):
        raise ValueError(f"index {index} is outside the {len(groups)} matching component groups")
    return ComponentAnalysis(groups[index], primitive.family_name, primitive.realization.name)


__all__ = ["ComponentAnalysis", "ComponentPropertiesResult", "ComponentTableResult"]
