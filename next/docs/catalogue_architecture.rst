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
``__all__``. There is one official class name per inventory record; alternate
graphs belong to realization metadata rather than new execution-engine types.

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
       ├── __init__.py
       ├── index.json      # audited constructor combinations, when generated
       └── v0.json.gz      # deterministic frozen typed-graph specification

The runtime loader uses :mod:`importlib.resources`, so installed wheels and
source checkouts behave identically. It imports neither legacy CLAASP nor Sage.
The compatibility image is used only by the development exporter to produce
reviewed migration artifacts. ``tools/colocate_primitive_data.py`` records the
one-time deterministic layout conversion; new exports write the owned layout
directly.

Poseidon is the parameter-catalogue reference: its package owns the typed
schema, BN254 data, upstream commit, reference result, and license notice.
``claasp_next.parameters`` contains only convenience re-exports.

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
