"""Search a restricted circle-linear trail and report its retained weights."""

from claasp.primitives import Craft
from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace


def run_example():
    """Search eight-round CRAFT within its validated perfect subgroup."""
    primitive = Craft(number_of_rounds=8)
    return primitive.circle_linear_trail_model(bibrace=BinaryBibrace.craft()).search()


if __name__ == "__main__":
    result = run_example()
    result.to_terminal()
    result.plot()
