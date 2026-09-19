"""Internal declarations for audited interchangeable primitive graphs."""

from types import MappingProxyType

from claasp_next.graph import RealizationDescriptor, RealizationMaturity

COMMON_CAPABILITIES = frozenset(("scalar_evaluation", "batch_evaluation"))


def realization(
    name,
    *capabilities,
    structure,
    description,
    priority,
    maturity=RealizationMaturity.STABLE,
    provenance,
):
    """Build one concise, validated descriptor for a catalogue family."""

    return RealizationDescriptor(
        name,
        COMMON_CAPABILITIES | frozenset(capabilities),
        frozenset(structure),
        description,
        maturity,
        tuple(provenance),
        priority,
    )


def register_realizations(canonical, entries):
    """Attach ordered descriptors and builders to one canonical public class."""

    frozen = tuple(entries)
    names = tuple(descriptor.name for descriptor, _ in frozen)
    if len(names) != len(set(names)):
        raise ValueError(f"duplicate realization names for {canonical.__name__}")
    canonical.REALIZATIONS = tuple(descriptor for descriptor, _ in frozen)
    canonical.REALIZATION_BUILDERS = MappingProxyType(
        {descriptor.name: builder for descriptor, builder in frozen}
    )
