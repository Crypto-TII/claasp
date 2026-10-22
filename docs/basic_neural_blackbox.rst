Black-box neural distinguisher
==============================

Can a classifier distinguish plaintext/output pairs from pairs whose output is uniformly random? Compare rounds one through seven with a fresh CPU classifier at each round.

.. plot::
   :context: reset
   :nofigs:
   :include-source:

   from claasp.primitives import Speck

   primitive = Speck(number_of_rounds=7)
   result = primitive.analysis.neural_blackbox(rounds="all", samples=30000)

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
   Path("_build/neural_blackbox_terminal.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/neural_blackbox_terminal.txt
   :language: text

.. plot::
   :context:
   :include-source:

   result.plot()

The dashed 0.5 line is the chance accuracy for balanced labels. These are
held-out validation measurements used during training, rather than an
independent test or a security claim. This example uses 30,000 randomly labeled samples per round,
15 epochs, a 10% validation split, and seed 9. Reporting reuses the trained result.

``rounds="all"`` measures every round instead of only the final round. The
default plot shows final and peak validation accuracy against round number.
Accuracy near 0.5 means this model and budget no longer find a useful
distinction; small fluctuations around 0.5 are expected. The decline is
empirical and need not be monotonic or mark a security boundary.

Download :download:`the script <examples/basic_neural_blackbox.py>`.
Continue to :doc:`advanced_neural_blackbox` for experiment parameters and interpretation.

The 30,000-sample budget lets this small model learn the one-round structure.
With the smaller default budget it was already near chance at round one.
