Impossible XOR differentials: verification
==========================================

An impossible-differential claim needs a contradiction justified by the
propagation model. Observing no successful sampled pair alone cannot prove
that a differential is impossible.

Characteristic validation
-------------------------

``WordImpossibleSATModel.decode_trail()`` checks the solver assignment,
validates the forward and backward truncated characteristics, and reconstructs
the contradictory middle boundary. The wordwise counterpart checks its own
boundary representation. This validates the supported model's contradiction;
it is not a general post-search API accepting arbitrary claims.

Concrete realizability is deliberately absent for a claimed impossible
endpoint: its assertion is that no qualifying pair exists. Model failure,
resource limits or an unknown solver status must not be interpreted as an
impossibility proof. V5 does not currently expose a general empirical endpoint
checker for this guide. See :doc:`advanced_impossible_differentials`.
