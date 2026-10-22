Component analysis tests: properties and composite blocks
=========================================================

Start with :doc:`basic_component_analysis` for an automatic inventory. Here we
select a component, request properties by name and inspect its differential
table. The same commands work inside reusable composite blocks.
These calculations use exact finite tables and finite-field arithmetic;
there are no sample counts or random seeds.

Select a component
------------------

.. plot::
   :context: reset
   :nofigs:
   :include-source:

   from claasp.primitives import Present

   primitive = Present(number_of_rounds=2)
   sbox = primitive.analysis.component("sbox")

This selects the one distinct S-box operation. ``sbox.count`` is 34, including
its uses in the key schedule. Equivalent occurrences form one semantic group;
selection does not compute properties yet.

A selector must identify one group. For example, PRESENT contains both a
64-bit state permutation and an 80-bit key permutation. Select the state
permutation explicitly:

.. code-block:: python

   permutation = primitive.analysis.component("permutation", bit_size=64)

``bit_size`` is the total encoded output width. When several distinct groups
still match, use a zero-based ``index`` within the matching groups. CLAASP
raises an informative error for missing or ambiguous matches instead of
silently choosing the first. Use ``primitive.analysis.component_analysis().to_terminal()``
to inspect the inventory and parameter previews.

Inspect one S-box
-----------------

Request named properties and retain a reportable result:

.. plot::
   :context:
   :nofigs:
   :include-source:

   properties = sbox.properties(
       "differential_uniformity", "nonlinearity", "algebraic_degree", "balanced",
       "differential_branch_number", "linear_branch_number", "boomerang_uniformity",
   )

.. code-block:: python

   properties.to_terminal()

.. plot::
   :context:
   :nofigs:
   :include-source: false

   from io import StringIO
   from pathlib import Path

   def capture(result, name):
       output = StringIO()
       result.to_terminal(file=output)
       Path("_build").mkdir(exist_ok=True)
       Path("_build/" + name).write_text(output.getvalue(), encoding="utf-8")

   capture(properties, "component_sbox_terminal.txt")

.. literalinclude:: _build/component_sbox_terminal.txt
   :language: text

With no property names, ``sbox.properties()`` uses the same defaults as the
basic inventory. The lookup-table domain is inferred from the S-box type.

Differential uniformity is the maximum differential-distribution-table (DDT)
entry over nonzero input differences. Four means no such transition occurs
for more than four of the sixteen possible inputs: maximum probability 1/4.
Nonlinearity is the minimum distance of a nonzero output-mask Boolean function
from an affine function. Algebraic degree is the maximum coordinate ANF degree.
Balanced means all output values occur equally often; for this square table,
that also makes the S-box bijective.

Differential branch number minimizes the sum of active input and output bits
among possible nonzero-input XOR transitions. Linear branch number uses
nonzero output masks with nonzero Walsh correlation. The values need not
coincide. Boomerang uniformity is the maximum nontrivial
boomerang-connectivity-table entry; it is not a round-trail probability.

Plot the differential table
---------------------------

Compute and retain the exact DDT, then display it:

.. plot::
   :context: close-figs
   :include-source:

   ddt = sbox.ddt()
   ddt.plot()

CLAASP sets the axes, integer counts and color scale. The trivial zero-input
row is omitted by default so its count of sixteen does not obscure the
nontrivial transitions. Each retained row sums to sixteen. A zero cell is an
impossible transition; a count of four means probability 4/16.

To display probabilities instead of counts, reuse that result:

.. code-block:: python

   ddt.plot(scale="probability")

``ddt.plot(include_zero=True)`` includes the trivial row.
``ddt.to_terminal()`` prints the table and ``ddt.counts`` exposes the full
immutable matrix, including the zero row. Saving and headless rendering follow
the other analysis results:

.. code-block:: python

   ddt.plot(show=False, save_to="present_ddt.png")

Analyze a component inside a composite
--------------------------------------

``AESRound`` is a reusable composite definition. Its ``analyze()`` method
provides the same component-selection API:

.. plot::
   :context:
   :nofigs:
   :include-source:

   from claasp.composites import AESRound

   mix = AESRound().analyze().component("linear_map")
   linear = mix.properties("rank", "invertible", "differential_branch_number")

.. code-block:: python

   linear.to_terminal()

.. plot::
   :context:
   :nofigs:
   :include-source: false

   capture(linear, "component_linear_terminal.txt")

.. literalinclude:: _build/component_linear_terminal.txt
   :language: text

This MixColumns operation contains all four columns: a 16-by-16 matrix over
AES's byte field. Rank sixteen proves that **this linear operation** is
invertible. It does not test invertibility or branch number of the whole AES
round, which also includes substitution, permutation and a round-key input.
A function of both state and independent round key cannot be inverted uniquely
from its state output alone; fixed-key invertibility is a different question.

CLAASP infers the ``word_linear`` domain for a finite-field linear map, so
weights count nonzero field elements, here bytes. To inspect its binary rank,
request the bit domain explicitly:

.. code-block:: python

   mix.properties("rank", domain="bit_linear").to_terminal()

The binary rank is 128. Bit-domain branch weights would count bits rather than
bytes, so those branch numbers answer a different question.

Request a bounded search
-------------------------

The full 16-byte branch search exceeds the core enumeration budget. The
unavailable row above is neither zero nor a failed diffusion criterion.
Restrict the search to input vectors of weight one:

.. plot::
   :context:
   :nofigs:
   :include-source:

   bounded = mix.properties("differential_branch_number", maximum_input_weight=1)

.. code-block:: python

   bounded.to_terminal()

.. plot::
   :context:
   :nofigs:
   :include-source: false

   capture(bounded, "component_bounded_terminal.txt")

.. literalinclude:: _build/component_bounded_terminal.txt
   :language: text

An observed input/output weight sum of five proves that the minimum is **at
most five**. The search has not excluded a lower value among unsearched inputs.
The retained results preserve the bound and incomplete coverage; printing
never turns it into an exact answer.

For exact searches, ``maximum_vectors`` controls the branch-enumeration budget
and ``maximum_steps`` controls the matrix-order budget. These limits are
explicit parameters of ``properties()``; no solver is selected implicitly.

Prove the single-column result
------------------------------

``AESMixColumn`` provides the standard four-byte building block, including the
AES field and matrix. There is no need to construct a matrix or graph input:

.. plot::
   :context:
   :nofigs:
   :include-source:

   from claasp.composites import AESMixColumn

   column = AESMixColumn().analyze().component("linear_map")
   column_properties = column.properties(
       "rank", "invertible", "mds", "differential_branch_number", "linear_branch_number",
   )

.. code-block:: python

   column_properties.to_terminal()

.. plot::
   :context:
   :nofigs:
   :include-source: false

   capture(column_properties, "component_column_terminal.txt")

.. literalinclude:: _build/component_column_terminal.txt
   :language: text

All square minors of this matrix are nonsingular. This MDS proof establishes
the optimal four-byte differential branch number, five, without enumerating
all :math:`256^4-1` nonzero input vectors. The transpose is also MDS, giving
linear branch number five. The full MixColumns matrix is block diagonal with
four identical four-byte blocks, so its byte branch number is also five:
each active column contributes at least five, and one active column attains
five. The generic bounded search does not claim that structural proof
automatically.

Reporting and lower-level access
--------------------------------

``properties.to_terminal(details=True)`` adds semantic identities, graph
references, applicability and methods. ``properties.results`` retains the
typed property results for programmatic inspection. ``present(properties)``
and ``present(ddt)`` support report composition and export through
:doc:`displaying_results`. Reports and plots reuse stored results.

The grouped result from the basic page also supports ``to_terminal(details=True)``
for full indexed S-box tables, permutation mappings, constants and provenance.
Default inventory requests avoid unsupported operations, lookup tables larger
than 256 entries and modular additions wider than eight bits, whose exact
ANFs can grow very large. Explicit requests remain available.

Download :download:`the complete script <examples/component_analysis.py>`.
The typed ``PropertyRequest`` and optional-driver interfaces remain available
for integrations; see :doc:`component_properties`.
