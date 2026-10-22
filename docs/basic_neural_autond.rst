Automated neural cryptanalysis
==============================

Search for an input difference and train distinguishers on successively larger reduced versions of a primitive. This short example uses a CPU multilayer perceptron and compares rounds one through seven, including rounds beyond the automatic early-stopping recommendation.

.. plot::
   :context: reset
   :nofigs:
   :include-source:

   from claasp.primitives import Speck

   primitive = Speck(number_of_rounds=7)
   result = primitive.analysis.autond(rounds="all")

Print the training settings and measured validation accuracy for every round:

.. code-block:: python

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
   Path("_build/neural_autond_terminal.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/neural_autond_terminal.txt
   :language: text

.. plot::
   :context:
   :include-source:

   result.plot()

The dashed 0.5 line is the chance accuracy for balanced labels. These are
held-out validation measurements used during training, rather than an
independent test or a security claim. This example uses 3,000 randomly labeled samples per round,
15 epochs, a 10% validation split, and seed 9. Reporting reuses the trained result.

``rounds="all"`` measures every round beyond the early-stopping rule. The
default plot shows final and peak validation accuracy against round number.
Accuracy near 0.5 means this model and budget no longer find a useful
distinction; small fluctuations around 0.5 are expected. The decline is
empirical and need not be monotonic or mark a security boundary.

Download :download:`the script <examples/basic_neural_autond.py>`.
Continue to :doc:`advanced_neural_autond` for experiment parameters and interpretation.

The all-round comparison starts at round one and continues after the usual
heuristic stopping point, so the later approach to chance stays visible.
Speck is practical at this demonstration budget. Larger primitives, training
sets, and neural networks require more time; this run does not reproduce a
published distinguisher record.
