Serialization and generated source
==================================

CLAASP 5 can preserve a typed primitive graph as canonical JSON, restore it,
and compile it to deterministic source.  These are machine interfaces: report
JSON and Markdown remain presentation formats and are not accepted by the
serialization readers.

Canonical primitive JSON
------------------------

``serialize_primitive`` returns canonical UTF-8 bytes.  The schema and version
are explicit, and the digest is the SHA-256 digest of those exact bytes.

.. doctest::

   >>> from claasp_next import deserialize_primitive, primitive_digest, serialize_primitive
   >>> from claasp_next.primitives import Present
   >>> present = Present(number_of_rounds=1)
   >>> encoded = serialize_primitive(present)
   >>> b'"schema":"org.claasp.primitive"' in encoded and encoded.endswith(b"\n")
   True
   >>> restored = deserialize_primitive(encoded)
   >>> restored.evaluate(0, 0) == present.evaluate(0, 0)
   True
   >>> primitive_digest(restored) == primitive_digest(present)
   True

Readers validate the complete graph.  Unknown schemas or versions, duplicate
identities, dangling selections, type mismatches, cycles, and unregistered
domains or components raise ``SerializationError`` with a typed ``reason``.
Only versions registered by the installed library are accepted; there is no
implicit CLAASP 4 dictionary reader.

Execution traces and scalar evaluation results use separate schemas and are
bound to the exact primitive digest:

.. doctest::

   >>> from claasp_next import deserialize_evaluation_result, serialize_evaluation_result
   >>> result = present.evaluate_with_trace(0, 0)
   >>> saved = serialize_evaluation_result(result)
   >>> deserialize_evaluation_result(saved, present).output == result.output
   True

Deterministic Python source
---------------------------

Source compilation produces an immutable artifact; it does not write or run
anything.  File output and execution are separate, explicit operations.

.. doctest::

   >>> from claasp_next import compile_source, run_python_source
   >>> from claasp_next.primitives import Speck
   >>> speck = Speck(32, 64, number_of_rounds=1)
   >>> compilation = compile_source(speck, target="python")
   >>> compilation.is_ready
   True
   >>> run = run_python_source(
   ...     compilation.artifact, speck,
   ...     {"plaintext": 0x6574694C, "key": 0x1918111009080100})
   >>> run.status.value
   'success'
   >>> run.output == speck.evaluate_with_trace(
   ...     0x6574694C, 0x1918111009080100).output
   True

``write_source`` requires an existing parent, a language-matching extension,
and an explicit ``overwrite=True`` to replace a file.  Generated Python runs
in a temporary directory with a bounded timeout and an argument vector; its
result records source, realization, driver, command, runtime, and process
provenance.

Optional native compilation
---------------------------

The C target covers the declared fixed-width Bit/Word subset.  Unsupported
domains or components return a ``SourceCompilationResult`` with status
``unsupported`` and a typed diagnostic.  CUDA is not a release-scope backend.

Native compilation is opt-in and requires an installed ``cc``-compatible C11
compiler.  Call ``compile_native`` only after checking ``is_ready``; inspect
``NativeCompilationStatus.UNAVAILABLE`` rather than assuming a compiler is
present.  ``compile_native`` and ``run_compiled`` use separate temporary
directories, bounded timeouts, shell-free argument vectors, and allowlisted
options.  Never execute generated or compiled artifacts from an untrusted
primitive graph.

Diagrams are different artifacts
--------------------------------

``primitive.draw("ascii")`` and ``primitive.draw("tikz")`` are human-facing
views of the backend-neutral diagram IR.  Optional ``"pdf"`` rendering invokes
LaTeX explicitly.  Diagram text is not canonical graph serialization and
cannot be deserialized as a primitive.
