"""Exact S-box properties and linear diffusion inside an AES composite."""

from claasp.analysis import ComponentProperty, PropertyDomain, PropertyRequest
from claasp.components import BitVectorSBox, LinearMap
from claasp.composites import AESRound
from claasp.composites.aes import AES_FIELD
from claasp.drivers.analysis import BoundedBranchNumberDriver
from claasp.graph import UnitArray, UnitArrayType
from claasp.presentation import component_property_section, render_section
from claasp.primitives import Present
from claasp.semantics.cryptanalysis import SBoxTransitionSemantics


def run_example():
    """Retain exact, unavailable, and bounded results for reporting."""
    primitive = Present(number_of_rounds=2)
    group = next(
        group
        for group in primitive.analysis.component_groups(PropertyDomain.LOOKUP_TABLE)
        if isinstance(group.representative, BitVectorSBox)
    )
    sbox = group.representative
    sbox_results = primitive.analysis.component_properties(
        sbox,
        tuple(
            PropertyRequest(property_, PropertyDomain.LOOKUP_TABLE)
            for property_ in (
                ComponentProperty.DIFFERENTIAL_UNIFORMITY,
                ComponentProperty.NONLINEARITY,
                ComponentProperty.ALGEBRAIC_DEGREE,
                ComponentProperty.BALANCED,
                ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER,
                ComponentProperty.LINEAR_BRANCH_NUMBER,
                ComponentProperty.BOOMERANG_UNIFORMITY,
            )
        ),
    )
    round_analysis = AESRound().analyze()
    mix = next(
        item for item in round_analysis.primitive.graph.components if isinstance(item, LinearMap)
    )
    linear_results = round_analysis.component_properties(
        mix,
        tuple(
            PropertyRequest(property_, PropertyDomain.WORD_LINEAR)
            for property_ in (
                ComponentProperty.RANK,
                ComponentProperty.INVERTIBLE,
                ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER,
            )
        ),
    )
    bounded = round_analysis.component_property(
        mix,
        ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER,
        PropertyDomain.WORD_LINEAR,
        driver=BoundedBranchNumberDriver(maximum_input_weight=1),
    )
    column = LinearMap(
        UnitArray("column", UnitArrayType(AES_FIELD, (4,))),
        ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2)),
    )
    from claasp.analysis import analyze_component_property

    column_results = tuple(
        analyze_component_property(column, PropertyRequest(property_, PropertyDomain.WORD_LINEAR))
        for property_ in (
            ComponentProperty.RANK,
            ComponentProperty.INVERTIBLE,
            ComponentProperty.MDS,
            ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER,
            ComponentProperty.LINEAR_BRANCH_NUMBER,
        )
    )
    ddt = SBoxTransitionSemantics(sbox.table).difference_distribution_table()
    return group, sbox_results, linear_results, bounded, column_results, ddt


def plot_ddt(ddt):
    """Plot nonzero input differences with exact transition counts."""
    from matplotlib import pyplot

    figure, axis = pyplot.subplots(figsize=(7, 4), layout="constrained")
    image = axis.imshow(
        ddt[1:],
        origin="lower",
        extent=(-0.5, 15.5, 0.5, 15.5),
        interpolation="nearest",
        vmin=0,
        vmax=4,
        cmap="YlOrRd",
    )
    axis.set(
        xlabel="Output XOR difference (decimal)",
        ylabel="Input XOR difference (decimal)",
        title="PRESENT S-box: exact differential counts",
    )
    axis.set_xticks(range(16))
    axis.set_yticks(range(1, 16))
    figure.colorbar(image, ax=axis, label="Count out of 16 inputs", ticks=range(5))
    return figure


if __name__ == "__main__":
    group, sbox_results, linear_results, bounded, column_results, ddt = run_example()
    for results in (sbox_results, linear_results, (bounded,), column_results):
        print(render_section(component_property_section(results, details=False)))
    plot_ddt(ddt)
    from matplotlib import pyplot

    pyplot.show()
