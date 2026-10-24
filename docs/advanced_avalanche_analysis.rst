Avalanche tests: parameters, metrics and criteria
=================================================

Start with :doc:`basic_avalanche_analysis` for the minimal Speck experiment.
Here we vary the experiment and inspect derived quantities and alternative
views. For the first-order diffusion and avalanche framework, see
`ACE-HoT (Bellini et al., 2023), Section 2 <https://eprint.iacr.org/2023/1352.pdf>`_.
The paper also studies higher-order tests; the commands here flip one input bit.

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

   primitive = Speck(number_of_rounds=rounds)
   result = primitive.analysis.avalanche(
       "plaintext", samples, seed=seed
   )

Each selected input bit is flipped independently. This plaintext experiment
also samples random keys. Bit positions follow MSB-first packed order. One set
of paired evaluations retains the published round outputs; reporting and
plotting do not rerun the analysis.

NumPy evaluates all samples in a batch in parallel by default. Work is split
into batches of at most 256 samples to bound execution-trace memory. Increasing
the sample count still increases runtime. ``engine="scalar"`` selects the
reference evaluator; ``result.method`` records NumPy, hybrid, or scalar execution.
Hybrid evaluation uses scalar component handlers for operations without a
vectorized implementation; Speck and ChaCha use vectorized word operations.

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
   Path("_build/avalanche_advanced_terminal.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/avalanche_advanced_terminal.txt
   :language: text

The basic table contains each round's minimum, maximum, average, and sample-dependent
SAC compatibility decision. The SAC bias is explicitly labelled as a final-round
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
       "key", samples, seed=seed
   )
   key_result.plot(view="heatmap", metric="entropy")

ChaCha permutation
------------------

ChaCha has a 512-bit state. This demonstration uses five complete column or
diagonal rounds and 100 samples per flipped state bit to keep its cost small:

.. plot::
   :context: close-figs
   :include-source:

   from claasp.primitives import ChaChaPermutation

   chacha = ChaChaPermutation(number_of_rounds=5)
   chacha_result = chacha.analysis.avalanche("state", 100, seed=seed)
   chacha_result.plot(view="3d", style="dots")

The identical result can be shown as opaque profiles:

.. plot::
   :context: close-figs
   :include-source:

   chacha_result.plot(view="3d", style="planes")

Metrics and criterion checks
----------------------------

Let :math:`p_{i,j}` be the observed probability that output bit :math:`j` flips
when input bit :math:`i` is flipped. ``result.vectors()`` retains these vectors
for every round and every flipped input bit. From the same experiment, compute:

.. code-block:: python

   probability_vectors = result.vectors()
   dependence_vectors = result.vectors("dependence")
   entropy_vectors = result.vectors("entropy")
   dependence = result.dependence()
   weight = result.weight()
   entropy = result.entropy()

The three aggregate results are indexed by round, then flipped input bit:

* Dependence counts output bits with an observed flip (:math:`p_{i,j}>0`).
* Weight sums :math:`p_{i,j}`, the expected output-difference Hamming weight.
* Entropy sums binary entropies :math:`h(p_{i,j})`, in bits. It is a sum of
  marginal entropies, rather than an estimate of joint output entropy.

For an :math:`n`-bit output, full diffusion targets dependence :math:`n`,
avalanche targets weight :math:`n/2`, and strict avalanche targets entropy
:math:`n`. Every flipped input bit must pass the chosen criterion.
These commands check all published rounds:

.. plot::
   :context:
   :nofigs:
   :include-source:

   checks = result.check_criteria(
       dependence_threshold=0,
       weight_threshold=0.32,
       entropy_threshold=0.32,
   )
   checks.to_terminal()

.. plot::
   :context:
   :nofigs:
   :include-source: false

   output = StringIO()
   checks.to_terminal(file=output)
   Path("_build/avalanche_criteria.txt").write_text(output.getvalue(), encoding="utf-8")

.. literalinclude:: _build/avalanche_criteria.txt
   :language: text

Criterion tolerances are **absolute totals**: dependence allows that many
missing output bits; weight allows that deviation from :math:`n/2`; entropy
allows that many bits below :math:`n`. For Speck's 32-bit output, 0.32 is one
percent of its width. Defaults are 0, 0.01 and 0.01 respectively. Bounds are
inclusive. The tolerance values are retained in every returned check.
``checks.to_terminal()`` formats the table inside CLAASP. Iterate over ``checks``
or access ``checks.rounds`` to inspect the underlying decisions.

Sample-dependent SAC check
~~~~~~~~~~~~~~~~~~~~~~~~~~

By default, the terminal report and summary plot check whether the measured
probabilities are statistically compatible with 0.5. Let :math:`N` be the
sample count, :math:`M` the total number of input/output-bit pairs across all
retained rounds, and :math:`\alpha=1-\text{confidence}`. The band is

.. math::

   [0.5-\epsilon, 0.5+\epsilon], \qquad
   \epsilon=\sqrt{\frac{\ln(2M/\alpha)}{2N}},

clipped to [0, 1]. This follows from the two-sided Hoeffding bound and a union
bound; see `these probability-bound notes <https://stanford.edu/~jduchi/projects/probability_bounds.pdf>`_.
Independent samples are required; independence between bit pairs or rounds is
not required. The correction covers all retained rounds together, rather than
only the pairs in one round.

With probability at least ``confidence``, the check will not flag any truly
unbiased pair among those comparisons. This controls false detections; it does
not give the probability that SAC is true. The bound is conservative.

The seven-round basic example has 1,000 samples and 7,168 comparisons, giving
approximately [0.421, 0.579]. Round 7 is consistent with 0.5; earlier rounds
contain detectable deviations. Larger sample budgets narrow the band, making
smaller biases detectable. If the band covers [0, 1], the report explicitly says
``inconclusive`` rather than reporting success.

Change confidence without choosing a fixed tolerance:

.. code-block:: python

   result = primitive.analysis.avalanche("plaintext", 1000, seed=9, confidence=0.99)

For entropy vectors, the same probability band is transformed through binary
entropy. This gives the same SAC decision. Dependence vectors instead report
whether flips were observed for every pair; they do not receive a statistical
SAC label.

A manually chosen per-bit tolerance remains available as an advanced option:

.. code-block:: python

   result = primitive.analysis.avalanche("plaintext", 1000, seed=9, threshold=0.01)

This overrides the statistical band: probability/weight use [0.49, 0.51], and
entropy uses [0.99, 1]. The report labels it ``Tolerance check`` and shows the
fixed tolerance. It does not adjust for sampling noise or multiple comparisons.
This reporting override is separate from the aggregate tolerances passed to
``check_criteria()`` above. An average of 0.5 alone cannot establish SAC.

``metric="weight"`` displays the probability contributions to expected weight;
use ``result.weight()`` for their sums. ``metric="dependence"`` displays the
observed dependence indicators. Either metric works in terminal and plot views.

No observed flip is evidence of insufficient sampling or absent dependence;
finite sampling cannot prove mathematical independence. All criterion decisions
are empirical, and tolerances are not statistical confidence intervals. Increase
the sample count to investigate failures or estimate uncertainty.

Probability/weight colors run red-orange-yellow-dark-green toward 0.5, then
reverse toward one. Entropy and dependence run from red at zero to the same
dark green at one. Entropy is computed before averaging across input flips.

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

See :doc:`basic_randomness_tests` for tests on primitive-generated datasets and
:doc:`displaying_results` for presentation and exports.
