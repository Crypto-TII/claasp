Continuous diffusion tests: parameters and reporting
====================================================

Start with :doc:`basic_continuous_diffusion` for the short AES example.
Here we study an eight-round ToyAES with three-bit S-boxes and a 3-by-3-word
state: a 27-bit teaching primitive, distinct from standard AES.

Measure and report
-------------------

.. plot::
   :context: reset
   :nofigs:
   :include-source:

   from claasp.primitives import ToyAES

   primitive = ToyAES(word_size=3, state_size=3, number_of_rounds=8)
   result = primitive.analysis.continuous_diffusion(
       "plaintext", 64, lambda_value=0.001, seed=9, precision=80,
   )

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
   Path("_build/continuous_advanced_terminal.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/continuous_advanced_terminal.txt
   :language: text

.. plot::
   :context: close-figs
   :include-source:

   result.plot()

What is measured?
------------------

Continuous coordinates lie in [-1, 1], with Boolean zero represented by -1 and
Boolean one by +1. CLAASP propagates these coordinates through the graph's
continuous component rules. The result is a heuristic model: dependence between
internal values means these coordinates should not be read as exact
probabilities throughout the cipher.

For output vectors :math:`u,v` of width :math:`m`, each CAF sample is

.. math::

   \frac{1}{m}\sum_{j=0}^{m-1}|\operatorname{sgn}(u_j)-\operatorname{sgn}(v_j)|.

The reported CAF is its mean over sampled pairs. A sign reversal contributes
two, an unchanged sign zero, and a zero coordinate compared with a nonzero one
contributes one. Thus CAF lies in [0, 2], with one the independent random-sign
reference. It is distinct from the flip probabilities and statistical SAC
check in :doc:`advanced_avalanche_analysis`.

For the continuous model, signed distance, and CAF, see Coutinho, de Sousa
Júnior and Borges, `Continuous Diffusion Analysis (2020), Definitions 13–14
<https://doi.org/10.1109/ACCESS.2020.3005504>`_.

Per-output contribution vectors
--------------------------------

Each round also retains a CAF contribution vector, indexed by output bit in
MSB-first order:

.. math::

   c_{r,j}=\frac{1}{N}\sum_{k=1}^{N}
   |\operatorname{sgn}(u^{(k)}_{r,j})-\operatorname{sgn}(v^{(k)}_{r,j})|.

``result.vectors[round_index][output_bit]`` exposes these values. Averaging a
round's vector gives its CAF. In the default sampler, the input coordinate is
selected at random, so the vector averages over those choices. A full matrix
conditioned on each individual input coordinate would require an experiment
for each coordinate.

This is the per-output analogue of the averaged avalanche probability profiles.
Its units are signed-distance contributions in [0, 2]. Where neither output is
zero, half the contribution is the empirical sign-reversal probability. It is
not the probability of flipping a Boolean cipher output.

Use the same plot selections as the avalanche example. All views reuse the
retained experiment:

.. plot::
   :context: close-figs
   :include-source:

   result.plot(view="heatmap")

.. plot::
   :context: close-figs
   :include-source:

   result.plot(view="3d", style="dots")

.. plot::
   :context: close-figs
   :include-source:

   result.plot(view="3d", style="planes")

Heatmap and 3D colors use the same red-orange-yellow-dark-green shades as the
avalanche plots, with the random-sign reference at **one**. The scale runs from
zero to two. Dots include faint round baselines; opaque profiles use the same
value colors and camera-aware round ordering.

For per-output vectors in the terminal, request details:

.. code-block:: python

   result.to_terminal(details=True)

Sampling and perturbations
---------------------------

The default ``sampling="boolean_neighborhood"`` is a local experiment: choose
a random Boolean vector, select one coordinate uniformly, and move it inward
by a uniform amount between zero and ``lambda_value``. This keeps both inputs
inside the continuous domain. Other primitive inputs are sampled independently
at Boolean endpoints and held equal within each pair. No outward perturbation
or clipping is used.

A smaller perturbation can shift the rounds where sign changes become visible:

.. plot::
   :context: close-figs
   :include-source:

   smaller = primitive.analysis.continuous_diffusion(
       "plaintext", 64, lambda_value=0.00001, seed=9,
   )
   smaller.plot()

This changes the experiment, so it requires new evaluations. Changing only the
report or saving a figure reuses its retained result.

Uniform continuous pairs
-------------------------

Definition 14 (Continuous Avalanche Factor) in Coutinho, de Sousa Júnior and
Borges's `Continuous Diffusion Analysis (2020)
<https://doi.org/10.1109/ACCESS.2020.3005504>`_ uses continuous input pairs
conditioned on Euclidean distance at most lambda. Select uniform close-pair
sampling explicitly:

.. plot::
   :context: close-figs
   :include-source:

   uniform = primitive.analysis.continuous_diffusion(
       "plaintext", 64, seed=9, sampling="uniform_near_pairs",
   )
   uniform.plot()

CLAASP samples a displacement uniformly in the Euclidean ball, accepts it in
proportion to the overlapping cube volume, and samples the first point within
that overlap. This avoids an unbounded rejection search for close independent
points in a high-dimensional cube.

This distribution differs from the default Boolean-neighborhood experiment;
the estimates need not agree. In particular, zero observed sign changes with
a small perturbation and a limited budget do not establish absent diffusion.

Vary key coordinates
---------------------

.. plot::
   :context: close-figs
   :include-source:

   key_result = primitive.analysis.continuous_diffusion("key", 64, seed=9)
   key_result.plot()

Here the plaintext is shared within each pair and the continuous perturbation
is applied to the key. Each report records which input was varied.

Precision and reuse
--------------------

Deep-round continuous magnitudes can be far smaller than binary64 can retain.
The sampled experiment uses ``mpmath`` with a local precision context (80 decimal
digits by default). S-box propagation uses cached integer Walsh coefficients
to avoid subtracting nearly equal probability sums. This preserves small
magnitudes without changing global numerical settings. It remains a finite
precision computation; compare settings when investigating a result:

.. code-block:: python

   higher_precision = primitive.analysis.continuous_diffusion(
       "plaintext", 64, seed=9, precision=120,
   )
   print(result.factors)
   print(higher_precision.factors)

``result.samples`` retains the normalized signed-distance samples for each round;
``result.round_numbers`` identifies the published boundaries, and
``result.factors`` contains their means. Leading setup rounds are excluded.
``analysis.continuous_evaluate(inputs)`` remains available for direct binary64
propagation of user-supplied continuous inputs.

Save a plot or create it without displaying it:

.. code-block:: python

   result.plot(save_to="continuous_diffusion.png")
   artifact = result.plot(show=False)

Download :download:`the script <examples/continuous_diffusion.py>`.
Both this companion and the basic script are exercised in CI. Empirical CAF
values describe the specified model and sampling protocol, rather than proving
a primitive secure or satisfying an avalanche criterion.
