XOR differential trails: verification
=====================================

Model validation and endpoint probability evaluation answer different questions;
see :doc:`trail_search_introduction`. Concrete boundary-sequence checking is
available through the circle-differential interface with XOR selected.

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

Concrete trail realizability
-----------------------------

``primitive.analysis.circle_differential().trail_probability(differences, ...)``
uses ordinary XOR when no alternative operation is supplied. It checks actual
input pairs at published round outputs, or at explicit ``boundaries`` selections.
Exact bounded enumeration proves existence or impossibility for those fixed
inputs and observations. Sampling can retain a concrete witness; zero sampled
hits do not prove impossibility. This interface does not automatically import
the component assignment in a solver characteristic. See
:doc:`verification_circle_differential` for layouts and sampling evidence.

Distinguisher probability/correlation evaluation
------------------------------------------------

``primitive.analysis.circle_differential().probability(a, b, ...)`` enumerates
the actual XOR endpoint probability on a bounded binary domain.
``estimate_probability(a, b, samples=..., seed=..., ...)`` provides uniform
sampling with a confidence interval on larger domains. Fix all other inputs,
including the key and tweak, explicitly. These measurements include all
compatible internal trails, rather than one selected characteristic.

For supported binary components,
``primitive.analysis.quasidifferential().estimate_fixed_key_probability()``
can recover an endpoint differential probability by summing signed
quasi-differential trails. This is a model-based exact expansion when complete,
not a sampling experiment. Its completeness and weight restrictions must be
checked; a partial sum is not an exact endpoint probability.

See :doc:`verification_quasi_differential` and :doc:`advanced_quasi_differential`.
