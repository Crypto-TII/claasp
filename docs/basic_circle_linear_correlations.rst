Circle-linear correlation evaluation
====================================

Which input/output checks have the strongest relationship across a small
S-box? Search its complete circle-linear approximation table, using the
CRAFT/Midori S-box and an explicitly constructed operation. The four-bit
addition is defined in :doc:`basic_circle_linear`; the advanced guide shows
how to select and compare other operations:

.. plot::
   :context: reset
   :nofigs:
   :include-source:

   from claasp.primitives import BitVectorSBox
   from claasp.primitives.block_ciphers.craft import CRAFT_SBOX
   from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace

   operation = BinaryBibrace(4, ((8, 0, 8, 5),), (5,))
   primitive = BitVectorSBox(4, CRAFT_SBOX)
   result = primitive.analysis.circle_linear(
       input_name="input", bibrace=operation
   ).best_approximation()

Print the selected mask labels and exact signed correlation:

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
   Path("_build/circle_correlation_basic_terminal.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/circle_correlation_basic_terminal.txt
   :language: text

Plot how often those two bit checks agree or disagree:

.. plot::
   :context: close-figs
   :include-source:

   result.plot()

The vertical axis is probability, from zero to one. Correlation is agreement
probability minus disagreement probability. A value of -1 means the checks
are always opposite; +1 means always equal. These probabilities are exact:
the analysis enumerates all sixteen S-box inputs. This is an endpoint
correlation, rather than one selected trail's contribution.

Plotting requires the ``presentation`` extra. ``result.plot(show=False)``
returns a figure, and ``result.plot(save_to="circle-correlation.png")`` saves
it. Both reporting calls reuse the computed result.

Download :download:`the script <examples/basic_circle_linear_correlations.py>`.
For characteristic reconstruction see :doc:`verification_circle_linear_characteristic`.
For a round-by-round trail search see :doc:`basic_circle_linear`.
For sampled correlations, confidence intervals, mathematical definitions and
larger configurations, continue to :doc:`advanced_circle_linear`.
