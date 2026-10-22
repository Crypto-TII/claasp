Black-box neural distinguisher
==============================

Can a classifier distinguish plaintext/output pairs from pairs whose output is uniformly random? This small training run illustrates the experiment; accuracy near 0.5 means that this model and training budget did not detect a useful distinction.

.. plot::
   :context: reset
   :nofigs:
   :include-source:

   from claasp.primitives import Speck

   primitive = Speck(number_of_rounds=1)
   result = primitive.analysis.neural_blackbox()

Print the training settings and measured validation accuracy:

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
independent test or a security claim. The defaults use 3,000 randomly labeled samples,
15 epochs, a 10% validation split, and seed 9. Reporting reuses the trained result.

Download :download:`the script <examples/basic_neural_blackbox.py>`.
Continue to :doc:`advanced_neural_blackbox` for experiment parameters and interpretation.
