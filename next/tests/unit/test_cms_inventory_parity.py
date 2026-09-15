"""Translate legacy CMS dispatch/bound checks into shared-model invariants."""

from claasp_next.primitives import Speck
from claasp_next.representations.constraints.cp.trails import SpeckDifferentialCPModel
from claasp_next.semantics import XOR_DIFFERENTIAL
from claasp_next.semantics.cryptanalysis import PropagationProblem


def test_full_speck_differential_dispatch_and_explicit_bound():
    primitive = Speck(number_of_rounds=22)
    loose = SpeckDifferentialCPModel(PropagationProblem(
        primitive, XOR_DIFFERENTIAL, maximum_weight=330,
    )).cp_model()
    bounded = SpeckDifferentialCPModel(PropagationProblem(
        primitive, XOR_DIFFERENTIAL, maximum_weight=1,
    )).cp_model()
    assert loose.declarations and loose.constraints
    assert sum(line.startswith("constraint modular_addition_xor_difference(")
               for line in loose.constraints) == 22
    assert loose.declarations == bounded.declarations
    assert loose.constraints[:-1] == bounded.constraints[:-1]
    assert loose.constraints[-1].endswith("<= 330;")
    assert bounded.constraints[-1].endswith("<= 1;")
