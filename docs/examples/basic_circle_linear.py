"""Search a restricted circle-linear trail and report its retained weights."""

from claasp.primitives import Craft
from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace


def run_example():
    """Search eight-round CRAFT within its validated perfect subgroup."""
    operation = BinaryBibrace(4, ((8, 0, 8, 5),), (5,))
    primitive = Craft(number_of_rounds=8)
    return primitive.analysis.find_lowest_weight_circle_linear_trail(
        bibrace=operation, fixed_inputs={"tweak": 0}
    )


if __name__ == "__main__":
    result = run_example()
    result.to_terminal()
    result.plot()
