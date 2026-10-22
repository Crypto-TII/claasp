"""Inspect S-boxes and reusable AES diffusion blocks through the public API."""

from claasp.composites import AESMixColumn, AESRound
from claasp.primitives import Present, Serpent


def run_example():
    """Retain exact, unavailable and bounded evidence for every guide example."""
    primitive = Present(number_of_rounds=2)
    sbox = primitive.analysis.component("sbox")
    sbox_results = sbox.properties(
        "differential_uniformity",
        "nonlinearity",
        "algebraic_degree",
        "balanced",
        "differential_branch_number",
        "linear_branch_number",
        "boomerang_uniformity",
    )
    ddt = sbox.ddt()

    mix = AESRound().analyze().component("linear_map")
    linear_results = mix.properties("rank", "invertible", "differential_branch_number")
    bounded = mix.properties("differential_branch_number", maximum_input_weight=1)

    column = AESMixColumn().analyze().component("linear_map")
    column_results = column.properties(
        "rank",
        "invertible",
        "mds",
        "differential_branch_number",
        "linear_branch_number",
    )
    return sbox, sbox_results, linear_results, bounded, column_results, ddt


def run_serpent_example():
    """Select two distinct S-box groups explicitly in standard SERPENT."""
    serpent = Serpent()
    first_sbox = serpent.analysis.component("sbox", index=0)
    second_sbox = serpent.analysis.component("sbox", index=1)
    first_properties = first_sbox.properties()
    second_properties = second_sbox.properties()
    ddt = first_sbox.ddt()
    return serpent, first_sbox, second_sbox, first_properties, second_properties, ddt


if __name__ == "__main__":
    sbox, sbox_results, linear_results, bounded, column_results, ddt = run_example()
    sbox_results.to_terminal()
    ddt.plot()
    linear_results.to_terminal()
    bounded.to_terminal()
    column_results.to_terminal()

    serpent, first_sbox, second_sbox, first_properties, second_properties, serpent_ddt = (
        run_serpent_example()
    )
    first_properties.to_terminal()
    second_properties.to_terminal()
    serpent_ddt.plot()
