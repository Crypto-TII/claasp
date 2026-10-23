Neural differential distinguisher
=================================

Train a classifier to distinguish output pairs produced with a chosen plaintext difference from output pairs produced with independent random inputs.

.. plot::
   :context: reset
   :nofigs:
   :include-source:

   from claasp.primitives import Speck

   primitive = Speck(number_of_rounds=7)
   result = primitive.analysis.neural_differential("plaintext", 0x400000, rounds="all")

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
   Path("_build/neural_differential_terminal.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/neural_differential_terminal.txt
   :language: text

.. plot::
   :context:
   :include-source:

   result.plot()

The dashed 0.5 line is the chance accuracy for balanced labels. These are
held-out validation measurements used during training, rather than an
independent test or a security claim. This example uses 3,000 randomly labeled samples per round,
15 epochs, a 10% validation split, and seed 9. Reporting reuses the trained result.

``rounds="all"`` measures every round instead of only the final round. The
default plot shows final and peak validation accuracy against round number.
Accuracy near 0.5 means this model and budget no longer find a useful
distinction; small fluctuations around 0.5 are expected. The decline is
empirical and need not be monotonic or mark a security boundary.

In this run, accuracy falls to about 55% at round five and fluctuates around
50% at rounds six and seven. From round six onward, up to the seven rounds
tested, this trained distinguisher no longer shows a useful advantage at this
model and training budget. This does not rule out other distinguishers.

The curve matches :doc:`basic_neural_autond` because AutoND finds the same
plaintext difference, ``0x400000``, supplied here. Both examples then use the
same datasets, seeds, classifier and training settings; AutoND adds the
automatic difference search.

Scores below 0.5 can occur: chance accuracy is an expectation, not a lower
bound on a finite measurement. See :doc:`basic_primitive_analysis` for how to
interpret validation noise and consistently below-chance predictions.

Download :download:`the script <examples/basic_neural_differential.py>`.
Continue to :doc:`advanced_neural_differential` for experiment parameters and interpretation.
