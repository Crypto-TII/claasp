"""Inspect S-boxes and reusable AES diffusion blocks through the public API."""

from claasp.composites import AESMixColumn, AESRound
from claasp.primitives import Present


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


if __name__ == "__main__":
    sbox, sbox_results, linear_results, bounded, column_results, ddt = run_example()
    sbox_results.to_terminal()
    ddt.plot()
    linear_results.to_terminal()
    bounded.to_terminal()
    column_results.to_terminal()
