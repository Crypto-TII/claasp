XOR-linear trails: verification
===============================

V5 supports model-witness validation and actual endpoint correlation
evaluation. There is no general public linear-trail realizability checker;
a concrete input-pair test for a differential is not automatically meaningful
for a linear mask expansion.

Characteristic validation
-------------------------

``WordXorLinearSATModel`` and ``WordXorLinearSMTModel`` expose
``decode_characteristic()`` and ``check_characteristic()``. Their validators
check component mask relations, fanout, correlation signs, boundaries and
weight restrictions. The MILP and CP wrappers reuse this validation.

.. doctest::

   >>> from claasp.primitives import Xor
   >>> from claasp.representations.constraints.smt import WordXorLinearSMTModel
   >>> model = WordXorLinearSMTModel(Xor(word_bit_size=2), maximum_weight=0)
   >>> formula = model.smt_formula()
   >>> characteristic = model.decode_characteristic(dict.fromkeys(formula.variables, 1))
   >>> model.check_characteristic(characteristic)
   True
   >>> from dataclasses import replace
   >>> model.check_characteristic(replace(characteristic, output_mask=0))
   False

Distinguisher probability/correlation evaluation
------------------------------------------------

The general correlation evaluator also handles ordinary XOR-linear checks:
when no alternative basis is supplied, ``analysis.circle_linear()`` defaults
to ordinary XOR parities. Its name reflects the more general implementation,
not a requirement to select a nontrivial circle addition.

.. doctest::

   >>> from claasp.primitives import BitVectorSBox
   >>> analysis = BitVectorSBox(2, (0, 1, 2, 3)).analysis.circle_linear(input_name="input")
   >>> analysis.correlation(1, 1)
   Fraction(1, 1)
   >>> estimate = analysis.estimate_correlation(1, 1, samples=64, seed=7)
   >>> estimate.value, estimate.samples
   (1.0, 64)

For a keyed primitive, supply ``fixed_inputs`` covering the key and every
other input except the varying public input. ``correlation()`` enumerates
all inputs within its configured work limit; ``estimate_correlation()``
returns a seeded estimate with a confidence interval. Neither uses the
product of a selected trail's local correlations as an endpoint measurement.
For reporting and plotting, see :doc:`basic_circle_linear_correlations`;
for larger configurations, see :doc:`advanced_circle_linear`.
