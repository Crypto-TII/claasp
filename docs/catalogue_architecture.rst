Primitive catalogue architecture
================================

The checked-in migration inventory is the source of truth for catalogue
coverage. Its M10.9d closure gate requires all 145 behavioral source records
to resolve to importable v5 modules and every one of the 143 legacy primitive
test records to point at existing v5 evidence. The four reviewed helper
modules remain explicitly outside the behavioral catalogue.

Public export layer
-------------------

``claasp.primitives._catalogue_exports`` is a generated, Sage-independent
map from each official public class name to its module. The top-level package
and each semantic category expose those classes lazily. This keeps simple
imports cheap while making the full catalogue discoverable through
``__all__``. Ordinary primitive exports come from the legacy migration
inventory. ``migration/single_component_catalogue.json`` separately records
the one-to-one v5 base-component wrappers: several obsolete legacy fixtures
may be evidence for one modern component, while new v5 components may have no
legacy fixture. Alternate graphs belong to realization metadata rather than
new execution-engine types.

Primitive and input metadata
----------------------------

``Primitive.kind`` is a ``PrimitiveKind`` value describing the mathematical
interface: function, permutation, block function, block primitive, or tweakable
block primitive. It does not select an evaluator. ``PrimitiveInput`` keeps a
boundary's ``ValueType``, semantic role, and ``InputVisibility`` together.
Conventional ``key`` inputs default to secret; other inputs default to public.
Source can be explicit with ``public_input`` and ``secret_input``.

``Primitive.with_input_visibility`` makes a shallow metadata derivation. The
typed ports, components, rounds, scopes, output, and semantic results remain
the same. This is intentional: whether a key is known is a property of one
analysis scenario, not a different realization of the primitive.

Single-component fixtures obey the ordinary primitive contract. Each contains
one round and one semantic component. Bijective unary operations are marked as
permutations; non-bijective, nullary, and multi-input operations are functions.
S-box and linear-map fixtures determine this classification from their supplied
table or matrix rather than assuming the default example.

``Primitive.kind`` and the catalogue's ``bijectivity_obligation`` answer
different questions. The kind describes the whole public arity. The obligation
asks whether the designated data/state input of a named configuration is a
bijection when all other inputs are retained. Consequently XOR and modular
addition remain multi-input functions while carrying an inversion obligation;
identity, permutation, rotation, reversible default feedback, and the reviewed
toy block primitives carry one as well. Lossy shifts, Boolean AND/OR,
multiplication with a possibly zero auxiliary, constants, and Fancy do not.
This review does not promote arbitrary custom tables or matrices: each runtime
graph still derives its kind and inverse behavior from its actual semantics.

Each fixture has the same class and module name as its base component. Thus
``LinearMap`` handles both bit matrices and finite-field MixColumn-style
matrices, ``FeedbackRegister`` lives in ``feedback_register.py``, and the
catalogue includes v5 algebraic components such as ``Add`` and ``Power``.
Joins and bit/word conversions are typed bindings, not base components. Permutation-specific builders such
as Sigma and theta remain reusable constructors, not invented base-component
types. Every fixture class docstring is an executable minimal authoring example.

Their public constructors expose only canonical v5 parameters. In particular,
linear maps are row-major, permutation mappings directly select the source for
each output, directions are explicit strings, and feedback registers use typed
parameters. Legacy argument aliases, orientation conversions, nested FSR
descriptions, and ignored canonical-modulus arguments are deliberately absent.
Optional catalogue parameters use ``None`` to mean “select the documented
configuration”; an explicit zero round, step, or S-box count is invalid rather
than a hidden request for defaults.

Owned package layout
--------------------

A primitive that needs supporting data replaces ``name.py`` with this
same-import-path package:

.. code-block:: text

   name/
   ├── __init__.py
   ├── primitive.py
   ├── parameters.py       # when the primitive has vetted parameter sets
   └── data/
       ├── NOTICE.md       # provenance/license when required
       └── constants.dat   # vetted primitive-owned supporting data

Simple primitives remain ``name.py`` modules. Their constructors contain the
readable round function, key schedule, constants, and parameter validation and
emit ordinary typed v5 components. Migration-time source compilers remain in
the preserved v4 history rather than the release tree; all shipped Python is
reviewed source, not serialized graph data. Runtime construction imports
neither legacy CLAASP nor Sage.

``BitGraphPrimitive`` is a concise authoring facade for bit-oriented source.
It resolves temporary source/position references while a constructor runs and
immediately emits immutable typed components into the canonical ``Primitive``
DAG. It is not an evaluator, realization selector, or second graph model.

Poseidon is the parameter-catalogue reference: its package owns the typed
schema, BN254 data, upstream commit, reference result, and license notice.
``claasp.parameters`` contains only convenience re-exports.

AES is also a package because lookup and algebraic realizations share reusable
AES blocks. LowMC is a package because its reviewed parameter sets own sizeable
constant matrices. Families with alternate graphs use the same layout: the
canonical implementation stays in ``primitive.py`` and concise sibling names
such as ``sbox.py``, ``fsr.py``, or ``invertible.py`` identify the realization.
The canonical family import remains stable. Twofish and WARP need neither
alternate realizations nor data, so their implementations remain directly
visible in ``twofish.py`` and ``warp.py``.

The package layout is not itself a realization claim. The reviewed decisions
live in ``migration/realization_catalogue.json`` and are checked by
``tools/realization_closure.py --check``. DES with a 56-bit key boundary is a
different parameterization from parity-bearing DES; CustomAES and ToyAES are
different primitives from AES; PRINCEv2 is not a PRINCE realization. Empty
subclasses that reproduce an identical graph are historical aliases rather
than extra choices. Legacy-derived Simon, Simeck, and Gimli S-box forms have
``legacy_regression`` maturity and remain explicitly non-canonical; M10.9f
records that distinction in catalogue authenticity and query labels.

Discovery metadata and records
------------------------------

``claasp.catalogue`` is the public discovery boundary. Its packaged,
versioned ``data/catalogue.json`` joins the M10.9b classification, public
export map, typed input contract, component vocabulary, parameter sets,
realization descriptors, fixed evidence, and driver declarations. Runtime
queries read that committed resource. They never infer semantics from a
directory name, parse implementation syntax, or import every primitive.

``Catalogue`` materializes frozen ``PrimitiveRecord``, ``ComponentRecord``,
``RealizationRecord``, ``ParameterSetRecord``, ``RepresentationRecord``,
``AnalysisRecord``, and ``DriverRecord`` values.
Nested collections are tuples or frozensets, and parameter values are exposed
through a read-only mapping. The global ``catalogue`` instance is merely a
small convenience over the same immutable data:

.. doctest::

   >>> from claasp.catalogue import Catalogue, catalogue
   >>> Catalogue().primitive("Prince").name
   'Prince'
   >>> catalogue.primitive("PrinceV2").family
   'prince_v2'
   >>> catalogue.primitive("PrinceV2").name != catalogue.primitive("Prince").name
   True

The final comparison is deliberately about distinct primitive identities:
PRINCEv2 is not advertised as a PRINCE realization. Similarly, the
``noncanonical_legacy_regression`` authenticity value makes Simon, Simeck, and
Gimli S-box discovery explicit without claiming specification authenticity.

Driver records describe execution engines, solvers, renderers, and external
tools separately from graph realizations. Listing records performs no probe.
An explicit availability call uses ``shutil.which``, MiniZinc's solver list,
or ``importlib.util.find_spec`` and returns ``DriverAvailabilityRecord``. It
does not import Z3, scikit-learn, Sage, or another optional implementation.

Representation records are the edges between component semantics and drivers.
Their component and domain sets state reviewed support, not presence in a
module. ``Catalogue.representations(component=...)`` and
``Catalogue.components(representation=...)`` expose the two directions;
``Catalogue.drivers(representation=...)`` and
``Catalogue.representations(driver=...)`` do the same for consumers.
Analysis records then name the representation and driver requirements used to
answer ``Catalogue.analyses(primitive=...)`` conservatively. A component-scope
representation requires the named component to occur; a generic graph
representation requires every component and domain in the primitive graph to
be supported. Parameter-limited reviewed slices remain labelled rather than
being promoted to unrestricted family-wide support.

The ``component_properties`` representation is component-scoped. It advertises
only component classes with a typed analyzer and records core bounded support
and optional MiniZinc execution separately. The ``component_property``
analysis may therefore be visible for a mixed primitive such as AES without
claiming that every AES component supports every property or domain; the
runtime result remains the authority for applicability and evidence strength.

.. doctest::

   >>> sorted(item.name for item in catalogue.drivers(representation="component_properties"))
   ['component_bounded', 'component_minizinc']
   >>> "component_property" in {item.name for item in catalogue.analyses(primitive="AES")}
   True

Evidence and maintenance
------------------------

Before adding or changing a primitive, locate every assigned legacy test and
fixed observation. Compare semantic outputs through the v5 scalar evaluator
and independently compare scalar/batch execution; do not pin component names,
generated strings, or mutable insertion order. Keep official vectors,
legacy-regression observations, exact claims, bounds, heuristics, and empirical
claims separately labelled.

After changing classification or implementation metadata, regenerate the
inventory and public export map, run
``tools/generate_catalogue_metadata.py`` and
``tools/catalogue_closure.py --check``, then run
``tools/legacy_inventory.py --check-primitive-closure``. Build a wheel to
verify that ``catalogue/data/catalogue.json`` and primitive-owned resources are
present, and execute the complete dependency-free suite. The canonical v5
runtime remains Python 3.11+ and Sage-independent.
