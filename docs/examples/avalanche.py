"""Measure once and present reproducible round-by-round avalanche results.

Run with ``python docs/examples/avalanche.py`` after installing ``.[analysis,presentation]``.
The guide executes the same public calls; CI uses smaller sample budgets.
"""

from matplotlib import pyplot as plt

from claasp.primitives import ChaChaPermutation, Speck


def measure_examples(*, speck_rounds=7, speck_samples=1000, chacha_rounds=5, chacha_samples=100):
    """Return the Speck plaintext/key and ChaCha results without rendering."""
    primitive = Speck(number_of_rounds=speck_rounds)
    result = primitive.analysis.avalanche("plaintext", speck_samples, seed=9, threshold=0.01)
    key_result = primitive.analysis.avalanche("key", speck_samples, seed=9, threshold=0.01)
    chacha_result = ChaChaPermutation(number_of_rounds=chacha_rounds).analysis.avalanche(
        "state", chacha_samples, seed=9, threshold=0.01
    )
    result.dependence()
    result.weight()
    result.entropy()
    result.vectors("dependence")
    result.check_criteria(dependence_threshold=0, weight_threshold=0.32, entropy_threshold=0.32)
    return result, key_result, chacha_result


def plot_examples(result, key_result, chacha_result):
    """Create eight views from existing measurements without displaying them."""
    return (
        result.plot(show=False).figure,
        result.plot(view="heatmap", show=False).figure,
        result.plot(view="heatmap", metric="entropy", show=False).figure,
        key_result.plot(view="heatmap", metric="entropy", show=False).figure,
        result.plot(view="3d", style="dots", show=False).figure,
        result.plot(view="3d", style="planes", show=False).figure,
        chacha_result.plot(view="3d", style="dots", show=False).figure,
        chacha_result.plot(view="3d", style="planes", show=False).figure,
    )


def run_example(**parameters):
    """Return measurements and figures for the headless CI exercise."""
    results = measure_examples(**parameters)
    return results, plot_examples(*results)


if __name__ == "__main__":
    results = measure_examples()
    results[0].to_terminal()
    plot_examples(*results)
    plt.show()
