Removing a key schedule
=======================

.. doctest::

   >>> from claasp.primitives import Speck
   >>> source = Speck(number_of_rounds=2)
   >>> plaintext, key = 0x6574694c, 0x1918111009080100


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
   >>> tuple(external.graph.input_arrays)
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
