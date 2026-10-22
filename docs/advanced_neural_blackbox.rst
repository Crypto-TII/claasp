Black-box neural distinguishers: datasets and independent tests
===============================================================

The basic example is :doc:`basic_neural_blackbox`. A black-box dataset has
approximately balanced random labels: label one contains input/output pairs from the primitive;
label zero replaces the output with fresh uniformly random bits. Features
concatenate the varied input and the output. Other primitive inputs stay
fixed throughout the dataset. Set their values with ``fixed_inputs``;
omitted fixed inputs are generated from the dataset seed.

This is a supervised pair-classification experiment. Random negative outputs
are independently sampled for each row; they do not implement a consistent
random-function oracle for repeated inputs. A near-chance result means this
model did not find a distinction at the selected budget. It does not establish
pseudorandomness.

Independent testing
-------------------

Reserve testing rows before training. The driver splits only the development
rows into training and validation sets. Score the reserved rows after model
selection; do not tune parameters on that score. Here the key is explicitly
zero in both label classes:

.. literalinclude:: examples/advanced_neural_blackbox.py
   :language: python
   :start-at: from claasp
   :end-before: if __name__

.. plot::
   :context: reset
   :nofigs:
   :include-source: false

   import runpy

   run_example = runpy.run_path("examples/advanced_neural_blackbox.py")["run_example"]
   result, test_accuracy, digest = run_example()

.. code-block:: python

   result, test_accuracy, digest = run_example()
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
   Path("_build/advanced_neural_blackbox.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/advanced_neural_blackbox.txt
   :language: text

.. plot::
   :context: close-figs
   :include-source:

   result.plot()

Inspect the independent test score:

.. code-block:: python

   print(f"Independent test accuracy: {test_accuracy:.3f}")

.. plot::
   :context:
   :nofigs:
   :include-source: false

   Path("_build/neural_test_terminal.txt").write_text(
       f"Independent test accuracy: {test_accuracy:.3f}\n", encoding="utf-8"
   )

.. literalinclude:: _build/neural_test_terminal.txt
   :language: text

The returned ``test_accuracy`` is the reserved-set score; ``digest`` identifies
all rows and labels. ``deterministic_partition`` retains explicit sample
indices, and ``dataset_digest`` binds a run to its exact dataset. For persisted
experiments, ``NeuralRunProvenance.create`` records the digest, primitive
realization, seeds, driver version and scalar options; ``NeuralRun.validate_for``
checks the dataset and partition coverage. Store library versions alongside
these records. Exact training scores are not portable fixtures.

Change the sample count, network width, epochs or input selection in separate
experiments, while retaining an untouched test set. ``driver.model`` exposes
the fitted scikit-learn classifier for scoring or explicit export.

Download :download:`the script <examples/advanced_neural_blackbox.py>`.

Round comparisons
-----------------

Use ``rounds="all"`` to train a fresh default classifier at each round, as in
the basic guide. An increasing sequence such as ``rounds=(1, 3, 5, 7)`` selects
a subset up to the constructed primitive's round count. Every round uses the
same training budget and seeds. ``result.plot()`` then defaults to round number;
``result.plot(view="epochs")`` compares the retained learning curves. A custom
driver's ``reset()`` hook is called before each selected round when available;
other custom drivers must make their ``train`` call independent themselves.
