Automating neural cryptanalysis: search and staged training
===========================================================

Start with :doc:`basic_neural_autond`. Automated neural cryptanalysis combines
an empirical difference search with training on reduced-round primitives.
Keep search samples and training samples separate in the report: the former
rank candidates by output-bit bias; the latter train a classifier.

Search and training budgets
---------------------------

The convenience workflow seeds its search with single-bit differences in the
selected inputs, then evolves candidates. The following explicitly states the
small demonstration budget. It does not reproduce a published round record:

.. literalinclude:: examples/advanced_neural_autond.py
   :language: python
   :start-at: from claasp
   :end-before: if __name__

.. plot::
   :context: reset
   :nofigs:
   :include-source: false

   import runpy

   run_example = runpy.run_path("examples/advanced_neural_autond.py")["run_example"]
   result = run_example()

.. code-block:: python

   result = run_example()
   result.to_terminal()

.. plot::
   :context:
   :nofigs:
   :include-source: false

   from io import StringIO
   from pathlib import Path

   output = StringIO()
   result.to_terminal(file=output)
   Path("_build").mkdir(exist_ok=True)
   Path("_build/advanced_neural_autond.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/advanced_neural_autond.txt
   :language: text

.. plot::
   :context: close-figs
   :include-source:

   result.plot()

Inspect candidate rankings with a CLAASP report:

.. code-block:: python

   result.difference_search.to_terminal()

.. plot::
   :context:
   :nofigs:
   :include-source: false

   output = StringIO()
   result.difference_search.to_terminal(file=output)
   Path("_build/neural_search_terminal.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/neural_search_terminal.txt
   :language: text

Use ``result.to_terminal(details=True)`` to inspect every retained epoch.

Candidate scores aggregate measured output-bit biases, weighted by round
number. A candidate's highest sampled round belongs to that bias measurement;
it is not a successful neural distinguisher round or an optimality certificate.
The retained candidates are ordered by score, with ``.best`` selecting the last.
The lower-level ``primitive.analysis.find_good_neural_input_difference`` accepts
explicit ``initial_candidates`` and separates search from training.

For the default scheduling mode, training starts at ``max(1, highest_sampled_round - 3)`` and includes the first
stage that fails the continuation rule. The convenience workflow uses
``0.5 + 5 / sqrt(n_validation)`` as a heuristic continuation threshold, with
the actual validation count. It checks whether any epoch lies at least
``5 / sqrt(n_validation)`` away from 0.5 in either direction. Repeated epochs and adaptive stage selection reuse validation
information, so this is not a calibrated significance test. An untouched test
set is needed for final evaluation. Small validation sets can put the threshold
above one; increase the sample budget rather than interpreting that as evidence
against a distinguisher.

Plot learning within each stage:

.. plot::
   :context: close-figs
   :include-source:

   result.plot(view="epochs")

TensorFlow architectures and curriculum training
------------------------------------------------

Install the optional framework in the active environment:

.. code-block:: console

   python -m pip install -e '.[ml-tensorflow]'

Select either real bundled architecture; these commands train models, rather
than merely choosing a label for the CPU MLP:

.. code-block:: python

   from claasp.drivers.neural import TensorFlowDistinguisherDriver

   primitive = Speck(number_of_rounds=3)
   driver = TensorFlowDistinguisherDriver(word_size=16, reuse_model=True)
   resnet = primitive.analysis.autond(
       architecture="gohr_resnet", driver=driver,
       samples=3000, epochs=1, seed=9,
   )
   dbitnet = primitive.analysis.neural_differential(
       "plaintext", 0x400000, architecture="dbitnet",
       samples=3000, epochs=1, seed=9,
   )

GohrResNet uses residual convolutional blocks; DBitNet uses dilated
convolutions. ``driver.model`` exposes the actual Keras model and
``driver.model.summary()`` prints its layers. With ``reuse_model=True``, the
TensorFlow driver retains weights across compatible stages. The default
scikit-learn driver trains a fresh MLP at each stage, so its stages are
independent training runs, rather than weight-transfer curriculum learning.
Use ``driver.reset()`` to start a fresh TensorFlow model.

For separate control of search, starting round and maximum round, use
``primitive.analysis.find_good_neural_input_difference``, then
``primitive.analysis.train_staged_neural_distinguisher`` with a
``NeuralExperiment`` and explicit driver. The lower-level staged API accepts
``significance_samples``; supply the actual validation count if using the same
heuristic above. Its raw result also has ``to_terminal()`` and ``plot()``.

Custom primitive implementations use the normal typed primitive graph and
round-reduction contracts. A custom framework adapter implements
``NeuralTrainingDriver.train(dataset, experiment)`` and returns
``NeuralExperimentResult``; framework tensors, devices and checkpoints belong
inside the driver. For facade-level independent checks, also implement
``predict(dataset)``; train-only adapters can request ``test_samples=0``.
No external repository or dynamic code execution is needed.

Download :download:`the script <examples/advanced_neural_autond.py>`.

To inspect the eventual approach to chance, use ``primitive.analysis.autond(rounds="all")``
as in the basic guide. This starts at round one and trains through the
primitive's configured final round without the early-stopping rule. The
reported curves retain all measurements and omit a stopping-threshold line.
The lower-level staged API offers ``stop_on_threshold=False`` for the same
purpose with explicit starting and maximum rounds. The ordinary AutoND call
continues to use its heuristic stopping rule.

Independent significance checks
-------------------------------

The facade also tests each final stage model on fresh rows from a separate
recorded seed. These scores never control the difference search, epoch choice,
weight-transfer schedule or continuation. The default test budget is 1,000
examples per stage, controlled with ``test_samples``; ``confidence`` defaults
to 0.95. The exact two-sided binomial check uses Bonferroni correction across
the primitive's planned round count, including rounds not reached by early
stopping. ``comparisons`` can enlarge that family. Both tails can provide
evidence, and the default plot shows independent tests and their chance band.
``result.plot(view="epochs")`` shows validation-only learning curves separately.
The five-sigma-style validation scheduling heuristic is not the significance
test used in ``result.tests``, ``result.to_terminal()`` or ``result.conclusion``.
See :doc:`basic_primitive_analysis` for statistical interpretation and test reuse.
