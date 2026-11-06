XOR differential trails: basic
==============================

Find and display an optimal 4-round XOR differential trail of SPECK32/64:

.. plot::
   :context: reset
   :nofigs:
   :include-source:

   from claasp.primitives import Speck

   primitive = Speck(number_of_rounds=4)
   trail = primitive.analysis.find_lowest_weight_xor_differential_trail()

The default single-key search uses Kissat, so the ``kissat`` executable
must be installed and on your ``PATH``.

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
   Path("_build/differential_trail_basic_terminal.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/differential_trail_basic_terminal.txt
   :language: text

Plot the weight contributed by each round and its running total:

.. plot::
   :context: close-figs
   :include-source:

   trail.plot()

The horizontal axis is the round number; round zero represents the input.
The vertical axis is weight in bits: :math:`-\log_2(p)` for probability
:math:`p`. The relative line shows each round's contribution and can rise
or fall. The cumulative line sums those contributions, so it never decreases;
its last point is the trail's total weight. A zero-weight round gives a
flat segment in the cumulative line.

Plotting requires the ``presentation`` extra. Use ``trail.plot(show=False)``
to create a figure without displaying it, or
``trail.plot(save_to="differential-trail.png")`` to save it.

Use ``trail.to_terminal(details=True)`` to inspect the search metadata and
the difference, probability and weight of each component.
