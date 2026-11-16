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

Fixing both linear endpoints
----------------------------

Use ``fixed_input_masks`` together with ``output_mask`` to constrain a
characteristic before solving or enumerating. Masks are ordinary packed
integers in MSB-first order; ``output_mask`` covers the complete graph output,
including selected outputs containing multiple units. ``None`` leaves the
output unrestricted, while ``0`` explicitly fixes every output-mask bit to zero.

The default query solver is Z3, which must be installed for this example.
For the identity S-box, equal input and output masks are feasible; unequal
masks are proved impossible:

.. doctest::

   >>> from claasp.primitives import BitVectorSBox
   >>> p = BitVectorSBox(3, (0b000, 0b001, 0b010, 0b011,
   ...                     0b100, 0b101, 0b110, 0b111))
   >>> trail = p.analysis.find_one_xor_linear_trail(
   ...     maximum_weight=0, fixed_input_masks={"input": 0b001},
   ...     output_mask=0b001)
   >>> trail.output_mask == 0b001
   True
   >>> p.analysis.find_one_xor_linear_trail(
   ...     maximum_weight=0, fixed_input_masks={"input": 0b001},
   ...     output_mask=0b010) is None
   True

The fixed-weight and bounded-enumeration query methods accept the same
``output_mask`` keyword, as do the direct Word SAT/SMT/MILP/CP linear models.
A finite enumeration limit can leave undiscovered characteristics; inspect
``complete`` or call ``require_complete()``. Neither one-trail search nor
enumeration alone measures the full linear hull. On keyed graphs, adding
``output_mask`` preserves the query's existing concrete-key defaults;
``fixed_inputs={"key": ...}`` still selects an explicit concrete key.

The minimum-weight convenience interfaces currently expose neither the
analogous differential output restriction nor this linear output restriction;
adding endpoint options to both optimization interfaces is a separate follow-up.

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
