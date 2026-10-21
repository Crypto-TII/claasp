Avalanche tests
===============

How quickly does a one-bit input change spread through a primitive? CLAASP can
estimate the probability that each output bit changes, then display how that
behavior develops over successive rounds.

This example includes Speck32/64 entropy plots and 3D avalanche weight views
for Speck and the ChaCha permutation.

Measure and display
-------------------

For a single round count, the analysis itself takes only a few lines:

.. code-block:: python

   from claasp.primitives import Speck

   result = Speck(number_of_rounds=22).analysis.avalanche("plaintext", 16, seed=9)
   result.to_terminal()
   result.plot()

``to_terminal()`` prints the measurement report; ``plot()`` displays the
probability heatmap. No separate Matplotlib import is needed. You can also save
the plot, or obtain its figure artifact without displaying it:

.. code-block:: python

   result.plot(save_to="speck_avalanche.png")
   artifact = result.plot(show=False)

Each matrix entry estimates the chance that one output bit flips when one
selected input bit is flipped. Bit positions follow MSB-first packed order.
Other inputs are sampled too: the plaintext experiment samples random keys,
while the key experiment samples random plaintexts.

To follow diffusion through the rounds, the downloadable example measures each
round prefix with the same seed and sample count. Its plotting helpers produce
the following views:

.. literalinclude:: examples/avalanche.py
   :language: python
   :start-after: # example-start
   :end-before: # example-end
   :dedent: 4

Speck uses 22 rounds, with 16 samples per flipped input bit. ChaCha uses five
v5 rounds, with four samples per flipped state bit. These deliberately small
sample counts make this a runnable demonstration. Increase ``speck_samples``
and ``chacha_samples`` in ``run_example()`` for an actual experiment.

Reading the plots
-----------------

The entropy heatmaps average the binary entropy
:math:`h(p)=-p\log_2 p-(1-p)\log_2(1-p)` over flipped input bits for each
output bit and round. Endpoint probabilities have entropy zero. Entropy near
one means observed flip probabilities near one half. The entropy is calculated
**before** averaging: averaging deterministic zero and one probabilities first
would give a misleading entropy of one.

The 3D views show the average flip probability over flipped input bits, retaining
the output-bit and round axes. The legacy name for this quantity is
*avalanche weight*. Values near one half are desirable, but averaging can hide
individual input/output-bit biases. Inspect the full probability matrix when
investigating those biases.

All plots are empirical estimates. Small samples are noisy and entropy estimates
are biased; these plots do not prove the strict avalanche criterion or establish
security. V5 ChaCha counts each complete column or diagonal round as one round;
the legacy implementation used a different round convention, so its five-round
picture should not be compared directly with this one.

.. plot:: examples/avalanche.py
   :alt: Speck plaintext and key entropy heatmaps, followed by 3D flip-probability views for Speck and ChaCha.

Run or adapt the example
------------------------

Download :download:`the complete Python script <examples/avalanche.py>` and run
it with ``python avalanche.py``. The same script generates the figures during
the HTML documentation build and is exercised by the presentation CI job.
CI uses fewer rounds and samples while checking the computations against direct
paired evaluations and verifying that every figure can be saved headlessly.

For the probability matrix and statistical-testing interfaces, see
:doc:`statistical_testing`. See :doc:`displaying_results` for result presentation
and :doc:`quick_analysis_scripts` for other short analysis examples.
