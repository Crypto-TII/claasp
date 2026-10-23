Neural distinguishers
=====================

Train classifiers to distinguish primitive-generated examples from random
examples, or automate the search for a useful input difference. These guides
follow the common script structure in :doc:`primitive_analysis`.

.. toctree::
   :maxdepth: 2

   neural_blackbox
   neural_differential
   neural_autond

The Getting started installation includes scikit-learn and plotting support.
The basic examples use a CPU multilayer perceptron. TensorFlow architectures
are explored in the advanced guides and require the ``ml-tensorflow`` extra.
Training retains validation histories separately from independent final-model
tests. Seeds make datasets and partitions repeatable; numerical training
results can vary across library versions.

Reading neural accuracy
-----------------------

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
