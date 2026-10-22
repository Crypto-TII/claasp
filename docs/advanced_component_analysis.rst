Component analysis tests: properties and composite blocks
=========================================================

Start with :doc:`basic_component_analysis` for automatic discovery and reporting.
Here we select properties explicitly, inspect an S-box's differential table,
and analyze the linear diffusion operation inside a reusable AES round.
These calculations use exact finite tables and finite-field arithmetic; there
are no sample counts or random seeds.

Discover repeated operations
----------------------------

.. plot::
   :context: reset
   :nofigs:
   :include-source:

   from claasp.analysis import ComponentProperty, PropertyDomain, PropertyRequest
   from claasp.components import BitVectorSBox
   from claasp.primitives import Present

   primitive = Present(number_of_rounds=2)
   groups = primitive.analysis.component_groups(PropertyDomain.LOOKUP_TABLE)
   group = next(group for group in groups
                if isinstance(group.representative, BitVectorSBox))
   sbox = group.representative

``group.count`` is 34. Groups distinguish operation parameters and input/output
types, but ignore graph identifiers. The two permutation groups in the basic
report operate on different widths (64-bit state and 80-bit key). Passing a
domain to ``component_groups`` sets the grouping context; it does not filter
out operations that cannot be analyzed in that domain. Select the operation
type explicitly, as above.

Default discovery retains every operation in the inventory, but does not make
property requests for unsupported operations, lookup tables larger than 256
entries, or modular additions wider than eight bits. The latter can have very
large exact ANFs. Use explicit property requests when exploring such cases;
reporting never silently launches a solver or expands the analysis budget.

Inspect one S-box
-----------------

.. plot::
   :context:
   :nofigs:
   :include-source:

   sbox_results = primitive.analysis.component_properties(
       sbox,
       tuple(PropertyRequest(property_, PropertyDomain.LOOKUP_TABLE)
             for property_ in (
                 ComponentProperty.DIFFERENTIAL_UNIFORMITY,
                 ComponentProperty.NONLINEARITY,
                 ComponentProperty.ALGEBRAIC_DEGREE,
                 ComponentProperty.BALANCED,
                 ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER,
                 ComponentProperty.LINEAR_BRANCH_NUMBER,
                 ComponentProperty.BOOMERANG_UNIFORMITY,
             )),
   )

Use CLAASP's presentation layer to format the retained property results:

.. plot::
   :context:
   :nofigs:
   :include-source:

   from claasp.presentation import component_property_section, render_section

   print(render_section(component_property_section(sbox_results, details=False)))

.. plot::
   :context:
   :nofigs:
   :include-source: false

   from pathlib import Path

   Path("_build/component_sbox_terminal.txt").write_text(
       render_section(component_property_section(sbox_results, details=False)), encoding="utf-8")

.. literalinclude:: _build/component_sbox_terminal.txt
   :language: text

Differential uniformity is the maximum differential-distribution-table (DDT)
entry over nonzero input differences. Four means no such transition occurs
for more than four of the sixteen possible inputs: maximum probability 1/4.
Nonlinearity is the minimum distance of a nonzero output-mask Boolean function
from an affine function. Algebraic degree is the maximum coordinate ANF degree.
Balanced means all output values occur equally often; for this square table,
that also makes the S-box bijective.

Differential branch number minimizes the sum of active input and output bits
among possible nonzero-input XOR transitions. Linear branch number uses
nonzero output masks with nonzero Walsh correlation. These are different
questions, so the two values need not coincide. Boomerang uniformity is the
maximum nontrivial boomerang-connectivity-table entry; its value is not a
round-trail probability or an overall security score.

An exact differential heatmap
-----------------------------

The heatmap explains where the differential-uniformity value comes from.
The all-zero input-difference row is omitted because its trivial count of
sixteen would obscure the nontrivial transitions.

.. plot::
   :context: close-figs
   :include-source:

   from claasp.semantics.cryptanalysis import SBoxTransitionSemantics
   from matplotlib import pyplot as plt

   ddt = SBoxTransitionSemantics(sbox.table).difference_distribution_table()
   figure, axis = plt.subplots(figsize=(7, 4), layout="constrained")
   image = axis.imshow(ddt[1:], origin="lower", extent=(-0.5, 15.5, 0.5, 15.5),
                       interpolation="nearest", vmin=0, vmax=4, cmap="YlOrRd")
   axis.set(xlabel="Output XOR difference (decimal)",
            ylabel="Input XOR difference (decimal)",
            title="PRESENT S-box: exact differential counts")
   axis.set_xticks(range(16))
   axis.set_yticks(range(1, 16))
   figure.colorbar(image, ax=axis, label="Count out of 16 inputs", ticks=range(5))
   plt.show()

Each row sums to sixteen. A zero cell is an impossible transition; a cell with
count four has probability 4/16. Colors encode exact counts, rather than the
empirical probabilities used in avalanche plots.

Analyze a component inside a composite
--------------------------------------

``AESRound`` is a reusable composite definition. Its ``analyze()`` method
projects it to an ordinary primitive, so the same component APIs apply:

.. plot::
   :context:
   :nofigs:
   :include-source:

   from claasp.components import LinearMap
   from claasp.composites import AESRound

   round_analysis = AESRound().analyze()
   mix = next(item for item in round_analysis.primitive.graph.components
              if isinstance(item, LinearMap))
   linear_results = round_analysis.component_properties(
       mix,
       tuple(PropertyRequest(property_, PropertyDomain.WORD_LINEAR)
             for property_ in (
                 ComponentProperty.RANK,
                 ComponentProperty.INVERTIBLE,
                 ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER,
             )),
   )
   print(render_section(component_property_section(linear_results, details=False)))

.. plot::
   :context:
   :nofigs:
   :include-source: false

   Path("_build/component_linear_terminal.txt").write_text(
       render_section(component_property_section(linear_results, details=False)), encoding="utf-8")

.. literalinclude:: _build/component_linear_terminal.txt
   :language: text

This MixColumns operation contains all four columns: a 16-by-16 matrix over
AES's byte field. Rank sixteen proves that **this linear operation** is
invertible. It does not test invertibility or branch number of the whole AES
round, which also includes substitution, permutation and a round-key input.
A function of both state and independent round key cannot be inverted uniquely
from its state output alone; fixed-key invertibility is a different question.

``WORD_LINEAR`` counts nonzero field elements, here bytes. ``BIT_LINEAR`` would
expand the map into binary coordinates: rank would become 128 and branch
weights would count bits. Always state the domain when comparing properties.

A bounded search is not an exact answer
---------------------------------------

The full 16-byte branch search exceeds the core enumeration budget. The
unavailable row above is neither zero nor a failed diffusion criterion.
An explicit driver can search only input vectors of weight one:

.. plot::
   :context:
   :nofigs:
   :include-source:

   from claasp.drivers.analysis import BoundedBranchNumberDriver

   bounded = round_analysis.component_property(
       mix, ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER,
       PropertyDomain.WORD_LINEAR,
       driver=BoundedBranchNumberDriver(maximum_input_weight=1),
   )
   print(render_section(component_property_section((bounded,), details=False)))

.. plot::
   :context:
   :nofigs:
   :include-source: false

   Path("_build/component_bounded_terminal.txt").write_text(
       render_section(component_property_section((bounded,), details=False)), encoding="utf-8")

.. literalinclude:: _build/component_bounded_terminal.txt
   :language: text

An observed input/output weight sum of five proves that the minimum is **at
most five**. The driver has not excluded a lower value among unsearched inputs.
``bounded.claim`` and ``bounded.complete`` retain this distinction for code
consuming the result.

Prove the single-column result
------------------------------

Inspect the four-byte map separately. The byte field uses the AES polynomial
modulus ``0x11B``; using integer arithmetic or a different field would ask a
different question.

.. plot::
   :context:
   :nofigs:
   :include-source:

   from claasp.analysis import analyze_component_property
   from claasp.composites.aes import AES_FIELD
   from claasp.graph import UnitArray, UnitArrayType

   column = LinearMap(
       UnitArray("column", UnitArrayType(AES_FIELD, (4,))),
       ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2)),
   )
   column_results = tuple(
       analyze_component_property(column, PropertyRequest(property_, PropertyDomain.WORD_LINEAR))
       for property_ in (
           ComponentProperty.RANK,
           ComponentProperty.INVERTIBLE,
           ComponentProperty.MDS,
           ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER,
           ComponentProperty.LINEAR_BRANCH_NUMBER,
       )
   )
   print(render_section(component_property_section(column_results, details=False)))

.. plot::
   :context:
   :nofigs:
   :include-source: false

   Path("_build/component_column_terminal.txt").write_text(
       render_section(component_property_section(column_results, details=False)), encoding="utf-8")

.. literalinclude:: _build/component_column_terminal.txt
   :language: text

All square minors of this matrix are nonsingular. This MDS proof establishes
the optimal four-byte differential branch number, five, without enumerating
all :math:`256^4-1` nonzero input vectors. The transpose is also MDS, giving
linear branch number five. Since the full MixColumns matrix is block diagonal
with four identical four-byte blocks, its byte branch number is also five: each active
column contributes at least five, and one active column attains five.
The generic bounded driver does not claim that structural proof automatically.

Reporting and reuse
-------------------

``result.to_terminal(details=True)`` on the basic grouped result includes
semantic identities, graph references, applicability and analysis methods.
For explicitly selected property tuples, omit ``details=False`` from
``component_property_section`` to retain the same provenance columns. Reports
reuse computed values. ``present(result)`` and ``render_report`` support the
grouped result for report composition and exports; see
:doc:`displaying_results`.

Download :download:`the complete script <examples/component_analysis.py>`.
For supported domains, request options and optional solver drivers, see
:doc:`component_properties`.
