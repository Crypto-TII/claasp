Transforming primitive graphs
==============================

Transformations consume an immutable typed primitive graph and return a new,
validated graph. The source primitive is never edited. Structural joins,
ordered views, ``PackBits``, and ``UnpackBits`` remain graph bindings; they do
not become semantic components or synthetic identities.

Complete inversion
------------------

A complete inverse takes the forward output plus every retained auxiliary
input. For a block primitive, the first input is recovered by default and the
key is retained:

.. doctest::

   >>> from claasp_next.primitives import Speck
   >>> source = Speck(number_of_rounds=2)
   >>> plaintext, key = 0x6574694c, 0x1918111009080100
   >>> ciphertext = source.evaluate(plaintext, key)
   >>> inverse = source.inverse().primitive
   >>> tuple(inverse.input_ports)
   ('output', 'key')
   >>> inverse.evaluate(ciphertext, key) == plaintext
   True

Only components with explicit inverse semantics are reversed. A non-bijective
operation fails with a typed ``information_loss`` diagnostic instead of
claiming an inverse.

Catalogue coverage and timing
-----------------------------

The reproducible `primitive inversion audit <primitive_inversion_audit.md>`_
constructs both a one-round instance, where the public constructor supports
one, and every official full-round configuration. It times graph construction
separately from semantic evaluation and verifies two deterministic round trips
for every successful inverse. The current checkpoint verifies every catalogue
configuration carrying a bijectivity obligation, including toy and
single-component primitives.

An obligation applies to the designated data/state input of a named catalogue
configuration, with all other inputs retained. Thus XOR, modular addition,
rotation, permutation, and identity fixtures have an obligation even though a
multi-input operation is not globally bijective in all of its inputs at once.
It does not classify every arbitrary constructor choice: a caller can still
provide a lossy lookup table, singular matrix, or non-reversible feedback
description outside the named catalogue configuration.

Some primitives use a reviewed equivalent graph that exposes the same
semantics in an inversion-friendly form; examples include compact linear maps
and triangular Boolean recurrences. Subterranean and ChiLow instead use
directly authored inverses from their published recurrences. These are not
solver shortcuts: the resulting typed graphs retain auxiliary inputs, preserve
the source realization identity, record a separate ``inverse_equivalent``
transformation, and are checked against evaluation of the public source graph.

Rows without a catalogue retained-input bijectivity obligation remain deliberately
qualified. A hash, stream-output function, or lossy component may report
``information_loss``, ``multiple_predecessors``, or a timeout without weakening
the complete-bijective-coverage claim.

Partial inversion and retained values
-------------------------------------

Partial inversion states both the target and the known graph boundaries. In
this example, the right operand is retained while the left operand is
recovered from an XOR output:

.. doctest::

   >>> from claasp_next import Primitive, ValueType, Word, partial_inverse
   >>> from claasp_next.components import Xor
   >>> graph = Primitive("mix", {
   ...     "left": ValueType(Word(8), (1,)),
   ...     "right": ValueType(Word(8), (1,)),
   ... })
   >>> _ = graph.add_round()
   >>> mixed = graph.add_component(Xor(graph.inputs()))
   >>> graph.set_output(mixed)
   >>> recovery = partial_inverse(
   ...     graph,
   ...     graph.input("left"),
   ...     known={"output": graph.output, "right": graph.input("right")},
   ... ).primitive
   >>> recovery.evaluate(0xA5, 0x3C)
   153

Known boundaries may also be intermediate selections. Equivalent recovered
wires are reused directly, without solver calls or identity placeholders.

Slicing and reducing rounds
---------------------------

``sliced`` keeps the dependency closure needed by an explicit output. Published
round states provide stable specification-level boundaries:

.. doctest::

   >>> source = Speck(number_of_rounds=3)
   >>> first_round = source.sliced(source.round_states[0]).primitive
   >>> first_round.evaluate(plaintext, key) == Speck(number_of_rounds=1).evaluate(plaintext, key)
   True
   >>> two_rounds = source.reduced_rounds(2).primitive
   >>> two_rounds.evaluate(plaintext, key) == Speck(number_of_rounds=2).evaluate(plaintext, key)
   True

For a middle slice, pass ``inputs={...}`` to name the new boundary selections.
The transformation validates complete logical units and reports a disconnected
dependency if a required unit is omitted.

Removing a key schedule
-----------------------

A key-schedule removal keeps round-key injection by default and exposes the
derived keys as secret ``round_key_*`` inputs. This is useful when a study
models round keys independently:

.. doctest::

   >>> source = Speck(number_of_rounds=2)
   >>> trace = source.evaluate_with_trace(plaintext, key)
   >>> from claasp_next.graph import as_selection
   >>> cache = {}
   >>> round_keys = tuple(
   ...     source.resolve_selection(as_selection(selection), trace.values, cache)
   ...     for selection in source.round_keys
   ... )
   >>> external = source.without_key_schedule().primitive
   >>> tuple(external.input_ports)
   ('plaintext', 'round_key_0', 'round_key_1')
   >>> external.evaluate(
   ...     plaintext=plaintext,
   ...     round_key_0=round_keys[0],
   ...     round_key_1=round_keys[1],
   ... ) == source.evaluate(plaintext, key)
   True

Passing ``keep_round_key_injection=False`` additionally bypasses recognized
zero-neutral injections. The result then describes the unkeyed round function;
unsupported injection semantics fail explicitly.

Paired XOR graphs
-----------------

Pairing retains two named composite scopes and publishes input, round, key, and
output differences. Shared inputs express a single-key experiment:

.. doctest::

   >>> paired = source.paired_xor(shared_inputs=("key",))
   >>> left, right = 0x6574694c, 0x6574694d
   >>> paired.primitive.evaluate(left, right, key) == (
   ...     source.evaluate(left, key) ^ source.evaluate(right, key)
   ... )
   True
   >>> (paired.left_scope.path, paired.right_scope.path)
   ('left', 'right')
