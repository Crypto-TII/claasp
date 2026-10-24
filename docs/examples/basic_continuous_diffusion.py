"""Minimal AES continuous-diffusion experiment, exercised in CI."""

from claasp.primitives import AES


def run_example():
    """Measure the continuous avalanche factor using the public defaults."""
    primitive = AES()
    return primitive.analysis.continuous_diffusion()


if __name__ == "__main__":
    result = run_example()
    result.to_terminal()
    result.plot()
