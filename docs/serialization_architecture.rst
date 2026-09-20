Serialization and source architecture
=====================================

The serialization boundary starts at the immutable typed graph.  A primitive
document uses schema ``org.claasp.primitive`` version 1 and canonical UTF-8
JSON: sorted object keys, compact separators, one trailing newline, canonical
integers, and graph-declaration order for arrays.  A version is readable only
when its schema/version decoder is explicitly registered.  New versions must
retain the old decoder or reject them with ``unknown_version``; readers never
guess or silently upgrade legacy dictionaries.

Graph encoding and validation
-----------------------------

The payload encodes primitive identity, kind, ordered input descriptors,
domains and shapes, rounds, components, ordered selections, bindings, output,
composite scopes, realization identity, and transformation provenance.
Deserialization constructs through the public graph invariants and then
checks identities, references, domains, widths, binding dependencies, scope
membership, and output compatibility.  The domain and component registries
are closed.  To extend them, add an encoder/decoder pair, a stable name, strict
field validation, round-trip and malformed-input evidence, and only then
register the pair.  Never import a type named by input data.

Execution traces and evaluation results have their own schema identifiers.
They carry the primitive digest and exact realization/transformation/driver
provenance, and validate values against the supplied graph.  Unsupported
analysis results and annotations fail with ``unsupported_artifact``.  This is
deliberately independent of the M10.14 presentation export, whose job is
human-facing interchange rather than graph reconstruction.

Source compilers and drivers
----------------------------

The source compiler boundary is pure::

   Primitive -> SourceCompilationResult(SourceArtifact | diagnostic)

The artifact contains language, stable source text and digest, primitive
digest, compiler identity, realization identity, and a predictable basename.
Python source embeds canonical graph bytes and delegates semantics to the
registered scalar evaluator.  C source is self-contained C11 for its declared
Bit/Word subset and reports unsupported types or components before invoking a
toolchain.  The legacy shared C/header ABI is not installed.

Writing, compiling, and execution belong to drivers, not compilers.  Drivers
require explicit safe paths, reject implicit overwrites and unapproved compiler
options, never use a shell, run in fresh temporary directories, impose bounded
timeouts, and preserve stdout, stderr, return status, command, tool version,
runtime, source/binary digests, and result provenance.  Generated code is an
execution boundary: callers must not compile or run untrusted graphs.

Diagram ownership
-----------------

The diagram compiler consumes the same graph but emits a separate IR containing
nodes, routed edges, logical selections, rounds, and optional annotations.
ASCII and TikZ are deterministic serializers of that IR; TikZ escapes labels.
PDF rendering alone belongs to the optional LaTeX driver.  Diagram serializers
must not become graph persistence or analysis backends.

Capability declarations for primitive serialization, execution-artifact
serialization, Python/C source, ASCII/TikZ, native execution, and optional PDF
rendering live in the generated catalogue rather than being inferred from
imports.
