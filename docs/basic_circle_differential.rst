Circle-differential trails: basic
=================================

Find the strongest concrete one-layer trail for input difference seven through
an S-box. This small example is from Section 3.1 of Calderini, Civino and
Invernizzi's `Differential experiments using parallel alternative operations
<https://doi.org/10.1515/jmc-2023-0030>`_. It needs no solver.

The selected operation is
:math:`x\circ y=x\oplus y\oplus(x_3y_2\oplus x_2y_3)`:
the final one-bit term flips bit 0. Bits are numbered from the least significant
bit, starting at zero; multiplication of bits means AND. For example,
:math:`4\circ8=13`, whereas :math:`4\oplus8=12`.

.. plot::
   :context: reset
   :nofigs:
   :include-source:

   from claasp.primitives import BitVectorSBox
   from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace

   table = (0, 14, 11, 1, 7, 12, 9, 6, 13, 3, 4, 15, 2, 8, 10, 5)
   primitive = BitVectorSBox(4, table)
   operation = BinaryBibrace(4, ((0, 0, 8, 4),), (1,))
   result = primitive.analysis.find_lowest_weight_circle_differential_trail(
       bibrace=operation, input_name="input", input_difference=7
   )

Print the boundary differences and their probabilities:

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
   Path("_build/circle_differential_basic_terminal.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/circle_differential_basic_terminal.txt
   :language: text

All sixteen inputs give output difference six: the probability is one.
``find_lowest_weight_circle_differential_trail(input_difference=7, ...)``
exhaustively searches for the most probable concrete trail
with that input difference. Here there are only input and output boundaries.
The advanced guide shows round boundaries in a multiround graph.

Plot the conditional and cumulative weights:

.. plot::
   :context: close-figs
   :include-source:

   result.plot()

Weight is :math:`-\log_2(p)`: probability one has weight zero, so both lines
lie at zero in this example. Relative probabilities are conditioned on all
earlier boundary differences. Cumulative probability is the fraction of
inputs satisfying the whole prefix. These are measured execution counts,
rather than products of independently computed local DDT entries.

Plotting requires the ``presentation`` extra. ``result.plot(show=False)``
returns a figure without displaying it; ``result.plot(save_to="circle-differential.png")``
saves it. Reporting reuses the retained result without repeating the search.

Download :download:`the script <examples/basic_circle_differential.py>`.
Continue with :doc:`advanced_circle_differential` for operation selection,
DDTs and round trails, or :doc:`verification_circle_differential` for exact
and sampled probability evaluation.
