"""Black-box neural distinguisher: a small reproducible training example."""

from claasp.primitives import Speck


def run_example():
    """Train and return the retained analysis result."""
    primitive = Speck(number_of_rounds=1)
    return primitive.analysis.neural_blackbox()


if __name__ == "__main__":
    result = run_example()
    result.to_terminal()
    result.plot()
