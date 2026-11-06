"""Verify a concrete two-round SPECK32/64 circle-differential trail."""

from claasp.primitives import Speck
from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace


def run_example():
    """Estimate the prescribed trail probability from 4096 seeded input pairs."""
    primitive = Speck(number_of_rounds=2)
    operation = BinaryBibrace(4, ((0, 0, 8, 4),), (1,))
    return primitive.analysis.circle_differential(bibrace=operation).trail_probability(
        (0x80000000, 0x01000100, 0x01020502),
        fixed_inputs={"key": 0},
        samples=4096,
        seed=7,
    )


if __name__ == "__main__":
    trail = run_example()
    trail.to_terminal()
    trail.plot()
