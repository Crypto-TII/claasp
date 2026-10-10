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

   >>> from claasp.primitives import Speck
   >>> source = Speck(number_of_rounds=2)
   >>> plaintext, key = 0x6574694c, 0x1918111009080100
   >>> ciphertext = source.evaluate(plaintext, key)
   >>> inverse = source.edit.inverse().primitive
   >>> tuple(inverse.graph.input_ports)
   ('output', 'key')
   >>> inverse.evaluate(ciphertext, key) == plaintext
   True

Only components with explicit inverse semantics are reversed. A non-bijective
operation fails with a typed ``information_loss`` diagnostic instead of
claiming an inverse.

When inversion is defined
-------------------------

Catalogue metadata identifies the data or state input that is expected to be
recoverable when all auxiliary inputs are retained. XOR, modular addition,
rotation, permutation, and identity operations can therefore be invertible
with respect to one designated input even though a multi-input operation is
not jointly invertible in all of its inputs.

This does not make every custom constructor choice reversible. A lossy lookup
table, singular matrix, hash, stream-output function, or non-reversible
feedback description reports a typed diagnostic such as
``information_loss`` or ``multiple_predecessors``.

Partial inversion and retained values
-------------------------------------

Partial inversion states both the target and the known graph boundaries. In
this example, the right operand is retained while the left operand is
recovered from an XOR output:

.. doctest::

   >>> from claasp import PrimitiveBuilder, ArrayType, partial_inverse
   >>> from claasp.components import Xor
   >>> from claasp.domains import Word
   >>> builder = PrimitiveBuilder("mix", {
   ...     "left": ArrayType(Word(8), (1,)),
   ...     "right": ArrayType(Word(8), (1,)),
   ... })
   >>> _ = builder.add_round()
   >>> mixed = builder.add_component(Xor(builder.inputs()))
   >>> graph = builder.build(mixed)
   >>> recovery = partial_inverse(
   ...     graph,
   ...     graph.graph.input("left"),
   ...     known={"output": graph.graph.output, "right": graph.graph.input("right")},
   ... ).primitive
   >>> recovery.evaluate(0xA5, 0x3C)
   153

Known boundaries may also be intermediate selections. Equivalent recovered
wires are reused directly, without solver calls or identity placeholders.

Slicing and reducing rounds
---------------------------

``edit.slice()`` keeps the dependency closure needed by an explicit output. Published
round states provide stable specification-level boundaries:

.. doctest::

   >>> source = Speck(number_of_rounds=3)
   >>> first_round = source.edit.slice(source.graph.round_outputs[0]).primitive
   >>> first_round.evaluate(plaintext, key) == Speck(number_of_rounds=1).evaluate(plaintext, key)
   True
   >>> two_rounds = source.edit.reduce_rounds(2).primitive
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
   >>> from claasp.graph import as_selection
   >>> cache = {}
   >>> round_keys = tuple(
   ...     source.graph.resolve_selection(as_selection(selection), trace.values, cache)
   ...     for selection in source.graph.round_keys
   ... )
   >>> external = source.edit.remove_key_schedule().primitive
   >>> tuple(external.graph.input_ports)
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

   >>> paired = source.edit.pair_xor(shared_inputs=("key",))
   >>> left, right = 0x6574694c, 0x6574694d
   >>> paired.primitive.evaluate(left, right, key) == (
   ...     source.evaluate(left, key) ^ source.evaluate(right, key)
   ... )
   True
   >>> (paired.left_scope.path, paired.right_scope.path)
   ('left', 'right')
