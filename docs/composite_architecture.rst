Composite graph architecture
============================

Composite graphs add hierarchy without creating a second execution model.
``CompositeDefinition`` is a frozen recipe containing typed boundary ports,
ordinary immutable leaf components, named outputs, nested-scope templates, and
small provenance records. ``CompositeInstance`` binds that recipe at one path
in a parent graph.

Lowering and identity
---------------------

``PrimitiveBuilder.add_composite`` validates every binding and copies the definition's
leaf nodes into the current round.  Leaf identifiers are deterministically
prefixed, for example ``round_1/sub_bytes/sbox_0``.  The primitive's component
sequence therefore remains the canonical DAG consumed by evaluators, models,
diagrams, and analyses.  The scope overlay records boundaries and membership;
it is not mutable connection state and it does not change component semantics.

Definitions may contain other definitions.  Nested instance paths survive
lowering and can be queried from either the primitive or their parent scope.

.. doctest::

   >>> from claasp import CompositeBuilder, PrimitiveBuilder, ArrayType
   >>> from claasp.components import Add
   >>> from claasp.domains import PrimeField
   >>> scalar = ArrayType(PrimeField(17), (1,))
   >>> child_builder = CompositeBuilder("Double", {"x": scalar})
   >>> child_builder.add_round()
   Round(number=0)
   >>> doubled = child_builder.add_component(Add((child_builder.input("x"), child_builder.input("x"))))
   >>> child_builder.set_output("output", doubled)
   >>> child = child_builder.build(provenance={"construction": "x + x"})
   >>> parent_builder = CompositeBuilder("DoubleTwice", {"x": scalar})
   >>> parent_builder.add_round()
   Round(number=0)
   >>> first = parent_builder.add_composite(child, {"x": parent_builder.input("x")}, scope_id="first")
   >>> second = parent_builder.add_composite(child, {"x": first.output()}, scope_id="second")
   >>> parent_builder.set_output("output", second.output())
   >>> parent = parent_builder.build()
   >>> graph_builder = PrimitiveBuilder("use_block", {"value": scalar})
   >>> graph_builder.add_round()
   Round(number=0)
   >>> block = graph_builder.add_composite(
   ...     parent, {"x": graph_builder.input("value")}, scope_id="block")
   >>> graph = graph_builder.build(block.output())
   >>> graph.evaluate(3)
   12
   >>> graph.graph.scope("block/second").component_ids
   ('block/second/add_0_0',)

Representation boundary
-----------------------

Composite definitions and instances expose ``as_primitive`` and ``analyze``
as projection conveniences.  They do not implement SAT, MILP, CP, polynomial,
or execution behavior.  A representation sees the projected ordinary graph
and either supports every leaf component or fails explicitly.  This preserves
one component dispatch contract and permits two representations of the same
mathematical block—for example expanded lookup S-boxes for Boolean constraints
or field inversion plus an affine map for algebraic AES studies.

Structural joins
----------------

Legacy CLAASP removed its public concatenate operation because component input
links already described an ordered concatenation. V5 selections deliberately
have one typed source, which makes ownership and modelling boundaries
unambiguous. ``PrimitiveBuilder.join`` and ``CompositeBuilder.join`` restore the
authoring convenience without presenting concatenation as a basic operation.
Passing several values to ``set_output`` uses the same path.

The canonical flat DAG records a multi-source join as an addressable typed
binding, separate from its semantic components. Execution traces, annotations,
diagrams, and constraint backends resolve the same ordered sources directly.
One-source joins are elided.

Round and primitive scopes
--------------------------

``primitive.graph.scopes`` lists all retained instances in construction order;
``primitive.graph.scope(path)`` selects one. ``round.scopes`` lists the instances
lowered in that round, including nested paths. A scope provides its bound
``inputs``, named ``outputs``, actual parent-graph ``components``, definition
``provenance``, and nested lookup. A primitive's separate ``provenance`` records
identity or derivation, which is why ``AES`` and ``CustomAES`` cannot silently
share a catalogue identity.

Editing remains outside this milestone: definitions and instances are frozen,
and graph transformations create a new graph rather than rewiring an existing
scope. M10.10 owns the general editor, inversion, traversal, splitting, and
compound-XOR transformations.
