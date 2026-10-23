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

Reading neural accuracy
~~~~~~~~~~~~~~~~~~~~~~~

Random guessing has an **expected** accuracy of 0.5 on balanced labels, not a
minimum measured accuracy. Finite validation samples and imperfect training
can put a score on either side of that line. With about 300 validation examples,
independent fair guesses have an accuracy standard deviation of approximately
``sqrt(0.5 * 0.5 / 300) = 0.029``. Scores such as 0.45 and 0.55 are therefore
plausible fluctuations around chance. This illustrates sampling noise; it is
not a significance test for adaptively trained models.

A classifier that consistently scores below chance on independent data could
be made useful by reversing its binary predictions: accuracy ``a`` becomes
``1 - a``. A single below-chance validation score does not establish that
repeatable effect. If inversion is chosen using validation data, confirm its
benefit on an untouched test set.

The conclusions in these guides apply to the trained model, data and budget,
and only to the tested rounds. Near-chance performance does not establish
that the primitive resists other models or cryptanalytic methods.
