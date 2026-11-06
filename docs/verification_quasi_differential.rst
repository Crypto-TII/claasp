Quasi-differential analysis: verification
=========================================

Quasi-differential trails carry signed coefficients. Their sum can recover a
fixed-key endpoint differential probability when the enumeration is complete.
V5 does not expose a general concrete-pair realizability checker for an
arbitrary quasi-differential expansion.

Characteristic validation
-------------------------

Search and enumeration check the solver constraints, then call the SAT
model's ``decode()`` to independently recompute local signed coefficients
before returning a trail. This is
validation of the represented expansion; it does not make a signed trail
coefficient an ordinary differential probability.

Distinguisher probability/correlation evaluation
------------------------------------------------

``primitive.analysis.quasidifferential().estimate_fixed_key_probability()``
sums signed trails with the key-dependent phases. Despite its name, it is not
a Monte Carlo estimator: a complete unrestricted sum recovers the endpoint
probability. ``key=None`` averages over keys instead of selecting one key.
The public inputs are averaged according to the method's documented setting.

Inspect ``complete`` or call ``require_complete()`` before using
``probability`` as an exact result. A trail limit, solver limit or weight
restriction can leave the sum incomplete. The result preserves that status
rather than turning a partial signed sum into an exact probability.
See :doc:`advanced_quasi_differential` for the analysis context.
