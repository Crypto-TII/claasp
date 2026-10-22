"""Minimal avalanche experiment; also executed in CI."""

from claasp.primitives import Speck


def run_example():
    """Measure Speck once and return its probability vectors."""
    primitive = Speck(number_of_rounds=7)
    return primitive.analysis.avalanche()


if __name__ == "__main__":
    result = run_example()
    result.to_terminal()
    result.plot()
