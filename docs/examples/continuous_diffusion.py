"""Advanced ToyAES continuous-diffusion experiments, exercised in CI."""

from claasp.primitives import ToyAES


def run_example(*, samples=64):
    """Retain results for perturbation, key-input and sampling comparisons."""
    primitive = ToyAES(word_size=3, state_size=3, number_of_rounds=8)
    result = primitive.analysis.continuous_diffusion("plaintext", samples, seed=9)
    smaller = primitive.analysis.continuous_diffusion(
        "plaintext", samples, seed=9, lambda_value=0.00001
    )
    key = primitive.analysis.continuous_diffusion("key", samples, seed=9)
    uniform = primitive.analysis.continuous_diffusion(
        "plaintext", samples, seed=9, sampling="uniform_near_pairs"
    )
    return result, smaller, key, uniform


if __name__ == "__main__":
    results = run_example()
    for result in results:
        result.to_terminal()
        result.plot()
