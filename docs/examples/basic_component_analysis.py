"""Discover repeated components and report default properties."""

from claasp.primitives import Present


def run_example():
    """Analyze the components of two-round PRESENT with core defaults."""
    primitive = Present(number_of_rounds=2)
    return primitive.analysis.component_analysis()


if __name__ == "__main__":
    run_example().to_terminal()
