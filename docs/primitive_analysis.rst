Introduction to primitive analysis
==================================

Explore what CLAASP can reveal about a primitive through short, runnable
examples, then investigate each topic in its accompanying advanced walkthrough.

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

Explore :doc:`component_analysis`, :doc:`diffusion_and_randomness`, or
:doc:`neural_distinguishers`. Each topic groups its introductory and advanced
walkthroughs together. :doc:`basic_algebraic_analysis` and
:doc:`basic_trail_search` are reserved for planned examples.

Exploring an analysis in depth
------------------------------

The introduction answers one question with a short script using defaults.
The matching advanced walkthrough explores parameters, measured quantities,
criteria and alternative reports. Keep the analysis result and reuse it for
reports, derived quantities, plots and exports wherever the analysis permits.

State sample counts and seeds for randomized experiments, solver limits for
searches, and training settings for neural experiments. Explain thresholds in
their actual units and distinguish empirical observations from exact results.
A graph or export task can follow this structure without inventing sampling
parameters or terminal reports.
