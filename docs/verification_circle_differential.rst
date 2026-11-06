Circle-differential trails: verification
========================================

Circle differences describe concrete input pairs. Verification must retain
the chosen operations, observed boundaries and fixed inputs. The result stores
its boundary bases, counts, key/tweak values, sampling parameters when relevant,
and a witness pair when the full trail event is observed.

Characteristic validation
-------------------------

``CircleDifferentialTrail`` validates widths, matching boundary metadata and
nonincreasing prefix counts. Its conditional factors are derived from those
counts. This structural validation alone does not certify a user-constructed
result against a primitive. This module has no separate solver-witness or
standalone local-DDT characteristic checker. Recompute a supplied sequence
with ``trail_probability()`` to test it on actual executions.

Concrete trail realizability
----------------------------

The exact method enumerates all inputs and checks the supplied difference
sequence. Positive probability and a retained witness establish realizability
under those fixed inputs. Zero exact probability establishes impossibility
for those observations and fixed inputs.

.. doctest::

   >>> from claasp.primitives import BitVectorSBox
   >>> from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace
   >>> table = (0, 14, 11, 1, 7, 12, 9, 6, 13, 3, 4, 15, 2, 8, 10, 5)
   >>> operation = BinaryBibrace(4, ((0, 0, 8, 4),), (1,))
   >>> analysis = BitVectorSBox(4, table).analysis.circle_differential(bibrace=operation, input_name="input")
   >>> valid = analysis.trail_probability((7, 6))
   >>> valid.probability, valid.witness, valid.evidence.complete
   (Fraction(1, 1), (0, 7), True)
   >>> impossible = analysis.trail_probability((7, 0))
   >>> impossible.probability, impossible.witness
   (Fraction(0, 1), None)

Use the same ``boundaries`` and ``boundary_bases`` arguments as in the search
when checking custom observations. On larger domains,
``trail_probability(differences, samples=4096, seed=7, ...)`` samples the whole
prespecified trail event. A sampled witness still proves existence; zero hits
only gives a probability bound, not an impossibility proof.

Distinguisher probability evaluation
------------------------------------

``probability(a, b)`` measures the actual endpoint differential, including all
compatible internal trails. It does not substitute one trail's probability
for the endpoint probability.

.. doctest::

   >>> endpoint = analysis.probability(7, 6)
   >>> endpoint.hits, endpoint.trials, endpoint.probability
   (16, 16, Fraction(1, 1))
   >>> endpoint.to_terminal()
   ... # doctest: +SKIP
   >>> endpoint.plot(show=False)
   ... # doctest: +SKIP

All nonvarying inputs must be fixed explicitly. The following larger example
measures a prespecified differential with uniform sampling and replacement:

.. doctest::

   >>> from claasp.primitives import Craft
   >>> large = Craft(number_of_rounds=2).analysis.circle_differential(bibrace=operation)
   >>> estimate = large.estimate_probability(
   ...     7, 6, fixed_inputs={"key": 0, "tweak": 0}, samples=64, seed=7)
   >>> estimate.complete, estimate.trials, estimate.seed
   (False, 64, 7)
   >>> 0 <= estimate.lower <= float(estimate.probability) <= estimate.upper <= 1
   True
   >>> estimate.to_terminal()
   ... # doctest: +SKIP
   >>> estimate.plot(show=False)
   ... # doctest: +SKIP

The confidence interval is a conservative Hoeffding interval for a differential
chosen before sampling. It remains nonzero in width even when every sample
matches or none does. The reported standard error is a plug-in estimate, which
can be zero in those cases. Small samples cannot establish tiny probabilities.
Choosing the best-looking differential using those same samples would require
additional selection-aware uncertainty analysis; this API does not perform
that search. Results concern one fixed key and tweak, not an average over
random keys or a weak-key-class size.
