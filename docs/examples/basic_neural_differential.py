"""Neural differential distinguisher: a small reproducible training example."""

from claasp.primitives import Speck


def run_example():
    """Train and return the retained analysis result."""
    primitive = Speck(number_of_rounds=7)
    return primitive.analysis.neural_differential("plaintext", 0x400000, rounds="all")


if __name__ == "__main__":
    result = run_example()
    result.to_terminal()
    result.plot()
