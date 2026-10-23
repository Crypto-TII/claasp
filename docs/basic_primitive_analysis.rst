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
Training retains validation histories separately from independent final-model
tests. Seeds make datasets and partitions repeatable; numerical training
results can vary across library versions.

Reading neural accuracy
~~~~~~~~~~~~~~~~~~~~~~~

The neural facade evaluates each final model on 1,000 independently generated
test rows by default, after training. The test generator uses a separate
recorded seed, with fair random labels rather than fixing the label counts.
Black-box experiments reuse the same fixed key and other fixed inputs in both
training and testing. The test rows are never supplied to ``train`` or used
for epoch selection, difference search or AutoND scheduling.

CLAASP applies an **exact two-sided binomial test** of chance accuracy 0.5
using `SciPy binomtest <https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.binomtest.html>`_.
Both above- and below-chance results can be significant. The default 95%
family-wise confidence uses Bonferroni correction across the planned round
comparisons in that analysis; the terminal report records their number,
test counts, acceptance bands and adjusted p-values. The bands are discrete
null acceptance regions, not confidence intervals for the measured accuracy.
Increasing ``test_samples`` narrows them; testing more rounds widens them.
The confidence level is controlled by ``confidence``. Non-detection means
**no statistically significant distinguishing advantage was detected for this
trained model at this test budget**, not that no distinguisher exists.

Random guessing has expected accuracy 0.5, not a minimum measured accuracy.
Finite measurements can fall on either side. A classifier with repeatable
accuracy 0.40 becomes a 0.60-accuracy classifier after reversing its predictions.
The two-sided test accounts for inspecting both directions. If inversion is
chosen from these test results, confirm the inverted classifier's performance
on another untouched dataset before claiming its accuracy.

Each round's default test concerns only the final model, not the highest
validation score over epochs. Train and choose models using training and
validation data. Reusing test scores to tune architectures, differences or
hyperparameters invalidates their untouched-test interpretation. For a larger
predeclared comparison family, set ``comparisons`` to cover all tested models,
or reserve new independent data after model selection. The default correction
covers rounds within one call, not every experiment a user might try.

Custom drivers provide ``predict(dataset)`` alongside ``train`` to participate
in independent testing. ``test_samples=0`` explicitly requests validation-only
reporting and suppresses statistical conclusions. The low-level
``NeuralExperimentResult`` retains training validation histories only.
