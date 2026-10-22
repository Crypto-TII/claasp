"""Advanced ToyAES continuous-diffusion experiments, exercised in CI."""

from claasp.primitives import ToyAES


def run_example(*, samples=1024):
    """Retain results for perturbation, key-input and sampling comparisons."""
    primitive = ToyAES(word_size=3, state_size=3, number_of_rounds=12)
    result = primitive.analysis.continuous_diffusion("plaintext", samples, seed=9)
    smaller = primitive.analysis.continuous_diffusion(
        "plaintext", samples, seed=9, lambda_value=0.00001
    )
    key = primitive.analysis.continuous_diffusion("key", samples, seed=9)
    uniform = primitive.analysis.continuous_diffusion(
        "plaintext", samples, lambda_value=1.0, seed=9, sampling="uniform_near_pairs"
    )
    return result, smaller, key, uniform


def plot_views(result):
    """Return the summary, heatmap, and both 3D styles without displaying them."""
    return (
        result.plot(show=False),
        result.plot(view="heatmap", show=False),
        result.plot(view="3d", style="dots", show=False),
        result.plot(view="3d", style="planes", show=False),
    )


if __name__ == "__main__":
    results = run_example()
    plot_views(results[0])
    for index, result in enumerate(results):
        result.to_terminal()
        if index:
            result.plot(show=False)
    from matplotlib import pyplot

    pyplot.show()
