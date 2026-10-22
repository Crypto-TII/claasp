Avalanche tests
===============

How quickly does a one-bit input change spread through a primitive? CLAASP
measures output-bit flips at each published round boundary and at the final
output. The same result supports a compact terminal report, detailed matrices,
and three plot views.

Measure once
------------

.. code-block:: python

   from claasp.primitives import Speck

   speck = Speck(number_of_rounds=22)
   result = speck.analysis.avalanche("plaintext", 16, seed=9, threshold=0.01)

The input is varied by flipping each of its bits independently. Other inputs
are sampled too: this plaintext experiment samples random keys. A key-flip
experiment uses ``"key"`` instead. Bit positions use MSB-first packed order.
A single set of paired evaluations retains every published round output;
rendering does not rerun the analysis.

Basic and detailed terminal reports
-----------------------------------

.. code-block:: python

   result.to_terminal()
   result.to_terminal(details=True)

The basic view prints the primitive, input, sample count, seed, selected analysis
method, and evaluation method. The maximum SAC bias is explicitly labelled with
the final round number: it is the largest absolute deviation of a final-output
flip probability from one half, regardless of the selected display metric.

A table then gives, for every measured round:

* Minimum and maximum values, with their ``(input bit, output bit)`` positions.
* Average over all input/output-bit pairs.
* Whether every pair meets the stated empirical threshold.

Up to eight tied positions are printed, with the number of additional ties.
The detailed view adds the full input-bit by output-bit matrix for each round,
so the basic report remains manageable for large primitives. If a primitive
publishes only its final output, only that output is reported; missing round
boundaries are not reconstructed. Round labels exclude leading setup rounds
when the primitive declares a cryptographic round count, as AES does.

Choose the measurement and threshold
------------------------------------

The metrics are:

* ``"probability"``: the empirical output-flip probability, with target 0.5.
* ``"entropy"``: binary entropy :math:`h(p)=-p\log_2 p-(1-p)\log_2(1-p)`,
  with target 1. Endpoint probabilities have entropy zero.
* ``"weight"``: the legacy avalanche-weight name for the per-bit flip
  probability, with the same target and units as ``"probability"``.

Choose a default metric when measuring, or select a different metric when
rendering the existing probabilities:

.. code-block:: python

   result = speck.analysis.avalanche(
       "plaintext", 16, seed=9, metric="probability", threshold=0.01
   )
   result.to_terminal(metric="entropy")

``threshold`` is an absolute tolerance in the selected metric's units.
Probability and weight pass when **every input/output-bit pair** lies in
``[0.5 - threshold, 0.5 + threshold]``, clipped to ``[0, 1]``. Entropy passes
when every pair lies in ``[1 - threshold, 1]``. Endpoints are included.
For the default tolerance 0.01, these bands are ``[0.49, 0.51]`` and
``[0.99, 1]``, respectively. Changing the metric retains the numerical tolerance.

This is an empirical acceptance criterion, not a statistical confidence interval
or a proof of the strict avalanche criterion. Sixteen samples are intentionally
small and noisy: even well-diffused rounds may fail this tight band. Increase
the sample count for an actual experiment.

Choose a plot view
------------------

The default plot has rounds on the horizontal axis and the minimum, maximum,
average, and threshold bounds on the vertical axis:

.. code-block:: python

   result.plot()
   result.plot(view="summary", metric="entropy")

The 2D heatmap shows rounds versus output-bit positions. Each cell averages the
selected metric over flipped input bits:

.. code-block:: python

   result.plot(view="heatmap")
   result.plot(view="heatmap", metric="entropy")

The 3D view shows the same round/output-bit averages as opaque filled round
profiles. The faces use the values' color shades, and nearer profiles hide
profiles behind them:

.. code-block:: python

   result.plot(view="3d")
   result.plot(view="3d", metric="entropy")

No separate Matplotlib import is needed for these calls. All views can be
saved or created without displaying a window:

.. code-block:: python

   result.plot(view="summary", save_to="avalanche_summary.png")
   artifact = result.plot(view="3d", show=False, save_to="avalanche_3d.png")

The returned ``FigureArtifact`` contains the figure and plotted series. The
explicit ``MatplotlibPresentationDriver().avalanche_matrix(result)`` also remains
available for an input-bit by output-bit heatmap of the final output.

Read the colors and averages
----------------------------

Probability and weight use the full red-orange-yellow-dark-green palette toward
0.5, then reverse it toward 1. Equal deviations above and below 0.5 receive the
same color. Entropy uses red at zero and dark green at one. The ideal value uses
exactly the same dark green in all views.

Entropy is computed **before** averaging. Averaging deterministic zero and one
probabilities first would give a misleading entropy of one. Heatmap and 3D
averages can hide individual pair biases; the basic report and default plot
retain the pairwise extremes, and the empirical criterion checks every pair.

Runnable example
----------------

The following script produces the default Speck summary, plaintext/key entropy
heatmaps, and opaque 3D probability profiles for Speck and ChaCha:

.. literalinclude:: examples/avalanche.py
   :language: python
   :start-after: # example-start
   :end-before: # example-end
   :dedent: 4

Speck uses 22 rounds with 16 samples; ChaCha uses five rounds with four samples.
Increase ``speck_samples`` and ``chacha_samples`` in ``run_example()`` for a larger
experiment. ChaCha counts a complete column or diagonal round as one round.

.. plot:: examples/avalanche.py
   :alt: Speck minimum, maximum, average and threshold by round; two entropy heatmaps; opaque colored round profiles for Speck and ChaCha.

Download :download:`the complete Python script <examples/avalanche.py>` and run
it with ``python avalanche.py``. The same code generates these figures during
the documentation build and is exercised by CI with smaller seeded inputs.

See :doc:`statistical_testing` for dataset and statistical-testing interfaces,
and :doc:`displaying_results` for presentation and exports.
