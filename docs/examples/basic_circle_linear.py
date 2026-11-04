"""Search a restricted circle-linear trail and report its retained weights."""

from claasp.primitives import Craft


def run_example():
    """Search eight-round CRAFT within its validated perfect subgroup."""
    primitive = Craft(number_of_rounds=8)
    return primitive.circle_linear_model().search()


if __name__ == "__main__":
    result = run_example()
    result.to_terminal()
    result.plot()
