XOR differential trails: verification
=====================================

Model validation and endpoint probability evaluation answer different questions;
see :doc:`trail_search_introduction`. V5 does not currently expose a general
concrete-pair realizability checker for an arbitrary supplied trail.

Characteristic validation
-------------------------

``WordXorDifferentialSATModel`` and ``WordXorDifferentialSMTModel`` expose
``decode_characteristic()`` and ``check_characteristic()``. The MILP and CP
wrappers delegate validation to the shared characteristic implementation.
A characteristic retains the semantic assignment needed to check wiring;
a pair of endpoint differences alone is not sufficient.

This small example needs no external solver:

.. doctest::

   >>> from claasp.primitives import Xor
   >>> from claasp.representations.constraints.smt import WordXorDifferentialSMTModel
   >>> model = WordXorDifferentialSMTModel(Xor(word_bit_size=2), maximum_weight=0)
   >>> formula = model.smt_formula()
   >>> witness = dict.fromkeys(formula.variables, 0)
   >>> characteristic = model.decode_characteristic(witness)
   >>> model.check_characteristic(characteristic)
   True
   >>> from dataclasses import replace
   >>> model.check_characteristic(replace(characteristic, output_difference=1))
   False

The checker recomputes component transitions and deterministic wiring, verifies
the boundaries and requested restrictions, and recounts the weights. Decoding
a SAT/SMT witness additionally checks the solver constraints. These checks do
not claim that multiplying local probabilities gives the exact probability
across the whole primitive.

Distinguisher probability/correlation evaluation
------------------------------------------------

V5 has no standalone general empirical XOR-differential checker corresponding
to the legacy sampling utilities. For supported binary components,
``primitive.analysis.quasidifferential().estimate_fixed_key_probability()``
can recover an endpoint differential probability by summing signed
quasi-differential trails. This is a model-based exact expansion when complete,
not a sampling experiment. Its completeness and weight restrictions must be
checked; a partial sum is not an exact endpoint probability.

See :doc:`verification_quasi_differential` and :doc:`advanced_quasi_differential`.
