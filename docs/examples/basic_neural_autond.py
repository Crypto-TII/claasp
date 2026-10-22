"""Automated neural cryptanalysis: a small reproducible training example."""

from claasp.primitives import Speck


def run_example():
    """Train and return the retained analysis result."""
    primitive = Speck(number_of_rounds=3)
    return primitive.analysis.autond()


if __name__ == "__main__":
    result = run_example()
    result.to_terminal()
    result.plot()
