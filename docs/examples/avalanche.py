"""Display round-by-round avalanche measurements with Matplotlib.

Run with ``python docs/examples/avalanche.py`` after installing ``.[presentation]``.
The documentation and CI execute this same file. Increase the sample counts
for experiments; the defaults keep the documentation demonstration affordable.
"""

from math import log2

from matplotlib import pyplot as plt

from claasp.primitives import ChaChaPermutation, Speck


def round_results(factory, input_name, rounds, samples, *, seed=9):
    """Measure each round prefix using identical seeded input samples."""
    return tuple(
        factory(number_of_rounds=round_number).analysis.avalanche(input_name, samples, seed=seed)
        for round_number in range(1, rounds + 1)
    )


def binary_entropy(probability):
    """Return Bernoulli entropy in bits, including the endpoint limits."""
    if probability in (0.0, 1.0):
        return 0.0
    return -probability * log2(probability) - (1 - probability) * log2(1 - probability)


def output_profile(result, *, entropy=False):
    """Average over flipped input bits, preserving each output-bit position.

    Entropy is computed for each probability before averaging, as in the
    entropy heatmap. Entropy of the average would hide deterministic flips.
    """
    return tuple(
        sum(binary_entropy(p) if entropy else p for p in column) / result.input_bit_count
        for column in zip(*result.probabilities, strict=True)
    )


def entropy_plot(results, label):
    """Show average bit-flip entropy by round and output bit."""
    figure, axis = plt.subplots(figsize=(9, 4), layout="constrained")
    image = axis.imshow(
        [output_profile(result, entropy=True) for result in results],
        origin="lower",
        aspect="auto",
        extent=(-0.5, results[0].output_bit_count - 0.5, 0.5, len(results) + 0.5),
        vmin=0,
        vmax=1,
        cmap="viridis",
    )
    axis.set_xlabel("Output bit (MSB first)")
    axis.set_ylabel("Rounds")
    axis.set_title(
        f"{label}: average avalanche entropy\nn={results[0].sample_count}, seed={results[0].seed}; empirical"
    )
    figure.colorbar(image, ax=axis, label="Mean binary entropy (bits)")
    return figure


def weight_plot(results, label):
    """Show a 3D mean flip-probability view."""
    figure = plt.figure(figsize=(10, 5), layout="constrained")
    axis = figure.add_subplot(projection="3d")
    for round_number, result in enumerate(results, start=1):
        axis.plot(
            range(result.output_bit_count),
            [round_number] * result.output_bit_count,
            output_profile(result),
            linewidth=0.8,
        )
    axis.set_xlabel("Output bit (MSB first)")
    axis.set_ylabel("Rounds")
    axis.set_zlabel("Mean flip probability")
    axis.set_zlim(0, 1)
    axis.set_title(
        f"{label}: avalanche weight\nn={results[0].sample_count}, seed={results[0].seed}; empirical"
    )
    return figure


def run_example(*, speck_rounds=22, speck_samples=16, chacha_rounds=5, chacha_samples=4):
    """Return the measured results and four figures without showing them."""
    # example-start
    speck = round_results(Speck, "plaintext", speck_rounds, speck_samples)
    key = round_results(Speck, "key", speck_rounds, speck_samples)
    chacha = round_results(ChaChaPermutation, "state", chacha_rounds, chacha_samples)
    figures = (
        entropy_plot(speck, "Speck32/64 — plaintext flips"),
        entropy_plot(key, "Speck32/64 — key flips"),
        weight_plot(speck, "Speck32/64 — plaintext flips"),
        weight_plot(chacha, "ChaCha permutation — state flips"),
    )
    # example-end
    return (speck, key, chacha), figures


if __name__ == "__main__":
    run_example()
    plt.show()
