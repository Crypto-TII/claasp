"""Find and report an exact circle-linear S-box endpoint approximation."""

from claasp.primitives import BitVectorSBox
from claasp.primitives.block_ciphers.craft import CRAFT_SBOX
from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace


def run_example():
    """Search every nonzero endpoint-mask pair of the four-bit S-box."""
    primitive = BitVectorSBox(4, CRAFT_SBOX)
    return primitive.analysis.circle_linear(
        input_name="input", bibrace=BinaryBibrace.craft()
    ).best_approximation()


if __name__ == "__main__":
    result = run_example()
    result.to_terminal()
    result.plot()
