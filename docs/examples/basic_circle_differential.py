"""Search the published four-bit circle-differential example and report it."""

from claasp.primitives import BitVectorSBox
from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace


def run_example():
    """Return the best concrete one-layer trail for input difference seven."""
    table = (0, 14, 11, 1, 7, 12, 9, 6, 13, 3, 4, 15, 2, 8, 10, 5)
    primitive = BitVectorSBox(4, table)
    operation = BinaryBibrace(4, ((0, 0, 8, 4),), (1,))
    return primitive.analysis.circle_differential(bibrace=operation, input_name="input").best_trail(
        7
    )


if __name__ == "__main__":
    result = run_example()
    result.to_terminal()
    result.plot()
