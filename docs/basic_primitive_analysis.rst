Introduction to basic primitive analysis
========================================

Explore what CLAASP can reveal about a primitive through short, runnable
examples. Each basic analysis has an extended counterpart in
:doc:`advanced_primitive_analysis`.

Before you begin
----------------

Follow :doc:`getting_started`. The full installation includes the dependencies
for the analysis and reporting examples. Optional dependency selections are
explained there as well.

Structure of an analysis script
-------------------------------

The common structure is deliberately small:

#. Import and construct a primitive.
#. Run the analysis or build the object needed to answer the question.
#. Display or export the result.

For example:

.. code-block:: python

   from claasp.primitives import Speck

   primitive = Speck(number_of_rounds=7)
   result = primitive.analysis.avalanche()
   result.to_terminal()
   result.plot()

This is a common reading order, rather than a mandatory set of method calls.
Trail searches return trails; algebraic analyses can construct equation systems
and connection graphs; neural experiments can prepare data and train a model.
Export examples can end with a LaTeX table instead of a plot. Each uses the
reporting methods appropriate to its result.

Basic examples use defaults wherever practical and state only the inputs needed
to ask their question. Configuration, alternative reports, thresholds and
parameter comparisons belong in the matching advanced page. Runnable scripts
are exercised in CI; outputs and figures appear next to their generating calls.

Start with :doc:`basic_avalanche_analysis`, :doc:`basic_continuous_diffusion`,
:doc:`basic_component_analysis`, or :doc:`basic_neural_distinguishers`, then
follow the links to their corresponding advanced guides.
