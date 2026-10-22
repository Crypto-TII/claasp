"""Display reproducible round-by-round avalanche measurements.

Run with ``python docs/examples/avalanche.py`` after installing ``.[presentation]``.
Documentation and CI use this same script, with smaller budgets in CI.
"""

from matplotlib import pyplot as plt

from claasp.primitives import ChaChaPermutation, Speck


def run_example(*, speck_rounds=22, speck_samples=16, chacha_rounds=5, chacha_samples=4):
    """Return the measured results and five figures without displaying them."""
    # example-start
    speck = Speck(number_of_rounds=speck_rounds).analysis.avalanche(
        "plaintext", speck_samples, seed=9
    )
    key = Speck(number_of_rounds=speck_rounds).analysis.avalanche("key", speck_samples, seed=9)
    chacha = ChaChaPermutation(number_of_rounds=chacha_rounds).analysis.avalanche(
        "state", chacha_samples, seed=9
    )
    figures = (
        speck.plot(show=False).figure,
        speck.plot(view="heatmap", metric="entropy", show=False).figure,
        key.plot(view="heatmap", metric="entropy", show=False).figure,
        speck.plot(view="3d", show=False).figure,
        chacha.plot(view="3d", show=False).figure,
    )
    # example-end
    return (speck, key, chacha), figures


if __name__ == "__main__":
    run_example()
    plt.show()
