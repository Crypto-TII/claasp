"""Search and report an exact three-round Heys linear characteristic."""

from claasp.primitives import Heys

primitive = Heys(number_of_rounds=3)
result = primitive.analysis.find_lowest_weight_xor_linear_trail()
result.to_terminal()
