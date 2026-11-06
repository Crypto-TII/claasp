Circle-differential trails: basic
=================================

Verify and display a two-round circle-differential trail of SPECK32/64.
This example estimates the probability of specified input, round-one and
output differences using 4096 input pairs and a fixed key. It needs no solver.

.. plot::
   :context: reset
   :nofigs:
   :include-source:

   from claasp.primitives import Speck
   from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace

   primitive = Speck(number_of_rounds=2)
   operation = BinaryBibrace(4, ((0, 0, 8, 4),), (1,))
   trail = primitive.analysis.circle_differential(bibrace=operation).trail_probability(
       (0x80000000, 0x01000100, 0x01020502),
       fixed_inputs={"key": 0}, samples=4096, seed=7,
   )

The alternative addition acts independently on each four-bit cell:
:math:`x\circ y=x\oplus y\oplus(x_3y_2\oplus x_2y_3)`.
The final one-bit term flips bit 0; multiplication of bits means AND.
Cell bits are numbered from the least significant bit, starting at zero.
For example, :math:`4\circ8=13`. The seed makes the input pairs reproducible.

Print the resulting trail:

.. code-block:: python

   trail.to_terminal()

.. plot::
   :context:
   :nofigs:
   :include-source: false

   from io import StringIO
   from pathlib import Path

   output = StringIO()
   trail.to_terminal(file=output)
   Path("_build").mkdir(exist_ok=True)
   Path("_build/circle_differential_basic_terminal.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/circle_differential_basic_terminal.txt
   :language: text

The table shows each boundary difference, the estimated probability of the
next transition conditioned on the preceding trail, and the running probability
of satisfying the whole prefix. The final confidence interval describes the
uncertainty in the whole trail's probability under the supplied fixed key.

Plot the weight contributed by each round and its running total:

.. plot::
   :context: close-figs
   :include-source:

   trail.plot()

Boundary zero represents the input; the next two points are the round outputs.
Weight is :math:`-\log_2(p)` for estimated probability :math:`p`. The relative
line shows each round's conditional weight. The cumulative line adds those
weights, ending at the estimated total weight of this prescribed trail.

Plotting requires the ``presentation`` extra. Use ``trail.plot(show=False)``
to create a figure without displaying it, or
``trail.plot(save_to="circle-differential.png")`` to save it.
Use ``trail.to_terminal(details=True)`` to inspect the retained counts,
fixed inputs and sampling metadata. Reporting reuses the result.

Download :download:`the script <examples/basic_circle_differential.py>`.
The :doc:`advanced guide <advanced_circle_differential>` covers exact bounded
trail search and the published S-box example. Continue with
:doc:`verification_circle_differential` for probability evaluation and sampling
uncertainty.
