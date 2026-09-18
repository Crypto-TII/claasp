Component properties
====================

Component-property analysis answers small specification questions without
constructing a report or choosing a solver. Every request names both a
property and its mathematical domain. Every immutable result says whether its
value is exact, a proved bound, an empirical observation, or unavailable.

S-box properties
----------------

Select a semantic component from a primitive and ask through its analysis
facade. A graph id may be used for lookup, but it never becomes the analysis
identity.

.. doctest::

   >>> from claasp_next.analysis import ComponentProperty, PropertyDomain
   >>> from claasp_next.components import BitVectorSBox
   >>> from claasp_next.primitives import Present
   >>> present = Present(number_of_rounds=1)
   >>> sbox = next(item for item in present.components if isinstance(item, BitVectorSBox))
   >>> result = present.analyze().component_property(
   ...     sbox, ComponentProperty.DIFFERENTIAL_UNIFORMITY,
   ...     PropertyDomain.LOOKUP_TABLE)
   >>> result.value, result.claim.value, result.complete
   (4, 'exact', True)
   >>> result.provenance.realization == present.realization.name
   True

The same API reports applicability instead of inventing a value. Boomerang
uniformity, for example, requires a square bijective lookup table.

.. doctest::

   >>> from claasp_next.analysis import PropertyRequest, analyze_lookup_table
   >>> from claasp_next.components import LookupTable
   >>> rectangular = LookupTable((0, 1, 3, 7), 2, 3)
   >>> unavailable = analyze_lookup_table(rectangular, PropertyRequest(
   ...     ComponentProperty.BOOMERANG_UNIFORMITY, PropertyDomain.LOOKUP_TABLE))
   >>> unavailable.claim.value, unavailable.diagnostic.code.value
   ('unavailable', 'inapplicable_domain')

Binary and finite-field linear maps
-----------------------------------

Matrices are row-major. Differential branch analysis uses the declared map;
linear-mask branch analysis uses its transpose. A finite-field domain retains
its explicit polynomial modulus.

.. doctest::

   >>> from claasp_next.analysis import analyze_component_property
   >>> from claasp_next.components import LinearMap
   >>> from claasp_next.domains import Bit
   >>> from claasp_next.graph import Port, ValueType
   >>> binary = LinearMap(Port("x", ValueType(Bit(), (2,))), ((1, 0), (1, 1)))
   >>> rank = analyze_component_property(binary, PropertyRequest(
   ...     ComponentProperty.RANK, PropertyDomain.BIT_LINEAR))
   >>> rank.value, rank.claim.value
   (2, 'exact')

AES MixColumns uses a four-word matrix over its published byte field.

.. doctest::

   >>> from claasp_next.composites.aes import AES_FIELD
   >>> mix = LinearMap(Port("column", ValueType(AES_FIELD, (4,))),
   ...     ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2)))
   >>> mds = analyze_component_property(mix, PropertyRequest(
   ...     ComponentProperty.MDS, PropertyDomain.WORD_LINEAR))
   >>> branch = analyze_component_property(mix, PropertyRequest(
   ...     ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER,
   ...     PropertyDomain.WORD_LINEAR))
   >>> mds.value, branch.value
   (True, 5)

Explicit heavy or bounded computation
-------------------------------------

Core small calculations have no Sage or solver dependency. Larger searches
are requested by constructing a driver and passing the same typed request.
Bounded enumeration does not claim exactness unless coverage or a mathematical
lower bound proves it.

.. doctest::

   >>> from claasp_next.drivers.analysis import BoundedBranchNumberDriver
   >>> bounded = BoundedBranchNumberDriver(maximum_input_weight=1)
   >>> estimate = bounded.analyze(mix, PropertyRequest(
   ...     ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER,
   ...     PropertyDomain.WORD_LINEAR))
   >>> estimate.value, estimate.claim.value, estimate.complete
   (5, 'proved_upper_bound', False)
   >>> estimate.provenance.driver.name
   'bounded_branch_enumeration'

``MiniZincBranchNumberDriver`` is the corresponding optional exact binary
optimizer. Construct it explicitly with the desired solver, executable, and
timeout, then pass it to ``component_property(..., driver=driver)``. A missing
executable produces a typed ``driver_unavailable`` result; it is never a core
import requirement.

Presentation, tables, plots, and radar charts consume these results in a
separate layer and are intentionally absent from this API.
