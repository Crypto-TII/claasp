Avalanche tests
===============

How quickly does a one-bit input change spread through a primitive? This example
follows the :doc:`basic_primitive_analysis` script structure: configure, build,
measure once, then report and visualize the retained results.

Configure and measure
---------------------

Use seven rounds of Speck32/64 to focus on the development of diffusion. The
1,000 samples per flipped input bit give a less noisy picture than a tiny
smoke test, while keeping the demonstration practical.

.. plot::
   :context: reset
   :nofigs:
   :include-source:

   from claasp.primitives import Speck

   rounds = 7
   samples = 1000
   seed = 9
   threshold = 0.01

   primitive = Speck(number_of_rounds=rounds)
   result = primitive.analysis.avalanche(
       "plaintext", samples, seed=seed, threshold=threshold
   )

Each selected input bit is flipped independently. This plaintext experiment
also samples random keys. Bit positions follow MSB-first packed order. One set
of paired evaluations retains the published round outputs; reporting and
plotting do not rerun the analysis.

The evaluator currently uses scalar Python; sample count affects runtime.
On the development machine this seven-round plaintext analysis took about nine
seconds with 1,000 samples. This is an illustrative timing, not a runtime
promise for other machines.

Basic terminal report
---------------------

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
   Path("_build/avalanche_basic_terminal.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/avalanche_basic_terminal.txt
   :language: text

The basic table contains each round's minimum, maximum, average, and empirical
criterion decision. The SAC bias is explicitly labelled as a final-round
measurement. The method identifies the selected avalanche metric; the
evaluation method records how the probabilities were obtained.

For tied extrema positions and full input-bit by output-bit matrices, request
investigation details:

.. code-block:: python

   result.to_terminal(details=True)

Positions are ``(input bit, output bit)`` in MSB-first order. The detailed
report lists up to eight tied positions and states how many additional ties
exist. Its matrices permit inspection of all pairs. Missing round boundaries
are not reconstructed; leading setup rounds are excluded when the primitive
declares a cryptographic round count, as AES does.

Default round statistics plot
-----------------------------

The default view places rounds on the horizontal axis and the minimum,
maximum, average, and acceptance thresholds on the vertical axis:

.. plot::
   :context: close-figs
   :include-source:

   result.plot()

This view retains the extremes over every input/output-bit pair. An average
near one half can coexist with individual pair biases.

Probability heatmap
-------------------

Each cell is the mean flip probability over flipped input bits, for one round
and output-bit position:

.. plot::
   :context: close-figs
   :include-source:

   result.plot(view="heatmap")

Entropy heatmap
---------------

Select entropy without repeating the experiment:

.. plot::
   :context: close-figs
   :include-source:

   result.plot(view="heatmap", metric="entropy")

Binary entropy is :math:`h(p)=-p\log_2 p-(1-p)\log_2(1-p)`, with endpoint
values zero. It is computed **before** averaging over input bits. Averaging
probabilities of zero and one first would incorrectly suggest entropy one.

3D dots and round baselines
---------------------------

Small dots retain the output-bit and round axes. A faint line at height zero
marks the location of each round:

.. plot::
   :context: close-figs
   :include-source:

   result.plot(view="3d", style="dots")

The first rounds genuinely have lower mean flip probabilities: approximately
0.128, 0.324, and 0.392 for rounds 1, 2, and 3 in this experiment. The values
are not clipped; the vertical scale remains zero to one.

3D opaque round profiles
------------------------

Opaque profiles use the same data and colors as the dots. Each output-bit
strip matches the dot above it. Profiles are ordered back to front by round,
including when rotating the view, so a farther, taller plane cannot incorrectly
cover a nearer, shorter one:

.. plot::
   :context: close-figs
   :include-source:

   result.plot(view="3d", style="planes")

Both 3D styles also accept ``metric="entropy"``.

A key-flip experiment
---------------------

The same reporting structure applies when flipping key bits. Reuse the
primitive and sampling configuration, and retain the new analysis result:

.. plot::
   :context: close-figs
   :include-source:

   key_result = primitive.analysis.avalanche(
       "key", samples, seed=seed, threshold=threshold
   )
   key_result.plot(view="heatmap", metric="entropy")

ChaCha permutation
------------------

ChaCha has a 512-bit state. This demonstration uses five complete column or
diagonal rounds and four samples per flipped state bit to keep its cost small:

.. plot::
   :context: close-figs
   :include-source:

   from claasp.primitives import ChaChaPermutation

   chacha = ChaChaPermutation(number_of_rounds=5)
   chacha_result = chacha.analysis.avalanche("state", 4, seed=seed, threshold=threshold)
   chacha_result.plot(view="3d", style="dots")

The identical result can be shown as opaque profiles:

.. plot::
   :context: close-figs
   :include-source:

   chacha_result.plot(view="3d", style="planes")

Metrics, thresholds, and colors
-------------------------------

``metric="probability"`` uses per-bit flip probabilities, targeting 0.5.
``metric="entropy"`` targets entropy one. ``metric="weight"`` preserves the
legacy name for the per-bit probability, with the same units and target.
Select a metric at analysis time or pass ``metric="entropy"`` to
``to_terminal()`` or any plot view to render the retained probabilities.

``threshold`` is an absolute tolerance in the selected metric's units. The
empirical criterion requires **every input/output-bit pair** to lie within
``[0.5 - threshold, 0.5 + threshold]`` for probability/weight, or
``[1 - threshold, 1]`` for entropy, clipped to ``[0, 1]``. Bounds are inclusive.
The default tolerance 0.01 gives bands ``[0.49, 0.51]`` and ``[0.99, 1]``.
Changing the metric retains the numerical tolerance.

This criterion is not a statistical confidence interval or a security proof.
Sampling noise means even a well-diffused round can fail a tight tolerance;
increase the sample budget when investigating it. Heatmap and 3D averages may
hide individual biases, while the terminal report and default plot retain the
pairwise extremes.

Probability/weight colors run red-orange-yellow-dark-green toward 0.5, then
reverse toward one. Equal deviations from 0.5 have the same color. Entropy
runs from red at zero to the identical dark green at one.

Save or adapt the script
------------------------

All views can be saved, or created without opening a window:

.. code-block:: python

   result.plot(save_to="avalanche_summary.png")
   artifact = result.plot(view="3d", style="dots", show=False, save_to="avalanche_3d.png")

The returned ``FigureArtifact`` contains the figure and plotted series. The
explicit ``MatplotlibPresentationDriver().avalanche_matrix(result)`` remains
available for a final-output input-bit by output-bit heatmap.

Download :download:`the complete Python script <examples/avalanche.py>` and run
it with ``python avalanche.py``. It uses the same public calls and parameters
as this page; CI exercises it with smaller budgets. The displayed commands and
terminal output are also executed during documentation builds.

See :doc:`statistical_testing` for dataset/statistical-testing interfaces and
:doc:`displaying_results` for presentation and exports.
