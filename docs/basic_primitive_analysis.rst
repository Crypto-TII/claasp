Introduction to basic primitive analysis
========================================

Explore what CLAASP can reveal about a primitive through short, runnable
examples. Each basic analysis has an extended counterpart in
:doc:`advanced_primitive_analysis`.

Before you begin
----------------

Follow :doc:`getting_started`. The full installation includes the dependencies
for numerical analysis, plotting, tables, and neural training. A selective
installation for the avalanche example is:

.. code-block:: console

   python -m pip install -e '.[analysis,presentation]'

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
or :doc:`basic_component_analysis`,
then follow its link to the corresponding advanced version.

Neural experiments
------------------

:doc:`basic_neural_blackbox`, :doc:`basic_neural_differential`, and
:doc:`basic_neural_autond` follow the same construct, analyze, report pattern.
The Getting started installation includes scikit-learn and plotting support.
The basic examples use a CPU multilayer perceptron. TensorFlow architectures
are explored in the advanced guides and require the ``ml-tensorflow`` extra.
Training retains empirical validation accuracy, rather than an exact
cryptographic property. Seeds make dataset generation and partitioning
repeatable; numerical training results can vary across library versions.
