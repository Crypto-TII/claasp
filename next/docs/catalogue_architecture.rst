Primitive catalogue architecture
================================

The checked-in migration inventory is the source of truth for catalogue
coverage. Its M10.9d closure gate requires all 145 behavioral source records
to resolve to importable v5 modules and every one of the 143 legacy primitive
test records to point at existing v5 evidence. The four reviewed helper
modules remain explicitly outside the behavioral catalogue.

Public export layer
-------------------

``claasp_next.primitives._catalogue_exports`` is a generated, Sage-independent
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

Each fixture has the same class and module name as its base component. Thus
``LinearMap`` handles both bit matrices and finite-field MixColumn-style
matrices, ``FeedbackRegister`` lives in ``feedback_register.py``, and the
catalogue includes v5 algebraic and conversion components such as ``Add``,
``Power``, ``PackBits``, and ``UnpackBits``. Permutation-specific builders such
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
emit ordinary typed v5 components. ``tools/compile_legacy_primitive_sources.py``
is a development-only source compiler used to bootstrap the mechanical parts
of migration; its checked-in output is reviewed Python source, not serialized
graph data. Runtime construction imports neither legacy CLAASP nor Sage.

``BitGraphPrimitive`` is a concise authoring facade for bit-oriented source.
It resolves temporary source/position references while a constructor runs and
immediately emits immutable typed components into the canonical ``Primitive``
DAG. It is not an evaluator, realization selector, or second graph model.

Poseidon is the parameter-catalogue reference: its package owns the typed
schema, BN254 data, upstream commit, reference result, and license notice.
``claasp_next.parameters`` contains only convenience re-exports.

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
``legacy_regression`` maturity and remain explicitly non-canonical; catalogue
authenticity/query labels still belong to M10.9f.

Evidence and maintenance
------------------------

Before adding or changing a primitive, locate every assigned legacy test and
fixed observation. Compare semantic outputs through the v5 scalar evaluator
and independently compare scalar/batch execution; do not pin component names,
generated strings, or mutable insertion order. Keep official vectors,
legacy-regression observations, exact claims, bounds, heuristics, and empirical
claims separately labelled.

After changing the catalogue, regenerate the inventory and public export map,
run ``tools/legacy_inventory.py --check-primitive-closure``, build a wheel to
verify owned resources, and execute the complete dependency-free suite. The
canonical v5 runtime remains Python 3.11+ and Sage-independent.
