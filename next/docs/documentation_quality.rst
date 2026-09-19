Public API documentation and quality policy
===========================================

Authority and scope
-------------------

The public API is derived mechanically. A module is public when it defines an
``__all__`` value, including a value assembled dynamically from committed
catalogue metadata. Every name in that value is a public qualified export.
Repeated exports are retained as aliases of one canonical Python object rather
than silently discarded.

For every exported class the audit also includes its constructor, public
methods, properties, dataclass fields, enum members, and user-facing members
inherited from another ``claasp_next`` class. Leading-underscore implementation
members are private, apart from the constructor. A module without ``__all__``
does not create a new public surface merely because its filename lacks a leading
underscore; an object defined there is nevertheless public when another module
exports it. This rule keeps private helpers private while covering root and
subpackage re-exports, aliases, lazy exports, and generated primitive exports.

Docstring convention
--------------------

Public module, class, function, method, and property docstrings use a concise
imperative or descriptive summary followed by a meaningful behavioral
contract. Longer contracts use these sections, in this order when applicable:
``Parameters``, ``Returns``, ``Raises``, ``Applicability``, ``Provenance``,
``Side effects``, ``Optional dependencies``, and ``EXAMPLES::``. Sections that
do not apply are omitted; empty boilerplate is not acceptable.

Parameter and return sections describe mathematical meaning, accepted shapes,
ordering, and immutability rather than repeating annotations. ``Raises`` names
publicly observable validation failures. Applicability and provenance qualify
cryptanalytic evidence. Side effects identify process execution and explicit
file output. Optional dependencies name packages or executables and state when
they are imported or invoked.

Every public class and user-facing callable has a small executable example in
the docstring visible through ``help(...)``. Examples use ordinary Python
``>>>`` prompts inside ``EXAMPLES::``; Sage prompts are forbidden. An example
demonstrates behavior, validation, or a typed result rather than construction
alone. Output must be deterministic across locale, platform, hash order,
temporary paths, timestamps, and memory layout. Ordinary doctests do not use a
network, shell, compiler, LaTeX, solver, statistical executable, ML framework,
arbitrary code execution, current-directory writes, or persistent files.

Reviewed exceptions
-------------------

An example exception is permitted only for an abstract protocol, an external
executable, an unsafe execution boundary, or an environment-owned interaction.
The committed machine authority records the exact qualified API, category,
reason, owner, and fixed evidence. It rejects duplicate or stale names, missing
rationales/evidence, broad module exemptions, and exceptions on APIs which
already contain executable examples. Missing documentation, migration history,
or implementation difficulty is never an exception.

Quality tools and boundaries
----------------------------

Ruff is the single formatter and linter because its formatter and integrated
rules avoid overlapping tools. Mypy is the single static type checker. Exact
versions live in the ``quality`` dependency group in ``pyproject.toml``.
Quality checks cover ``src/claasp_next``, ``tests``, ``tools``, and
``docs/conf.py``; they do not reformat the legacy v4 tree. Generated build
directories, caches, reports, wheel staging directories, and primitive-owned
data are explicit non-source artifacts rather than silent per-tool exclusions.

The M10.16a baseline records 394 v5 Python source files, 123 modules declaring
``__all__``, 1,179 resolved qualified exports, 671 distinct exported objects,
and 1,224 canonical public class members. The initial audit found 530 members
without docstrings, only seven member-level ``EXAMPLES::`` sections, 663 Sage
prompts in v5 source docstrings, 701 findings under the proposed broad Ruff
rule set, 470 files needing Ruff formatting, and 370 default-mypy diagnostics
in ``src/claasp_next``. These are adoption measurements, not accepted permanent
exclusions. Each later slice must reduce its owned findings and the closure gate
must reject regression or stale baseline entries.

The dependency-free core-import boundary remains unchanged: quality and
documentation collection must not import Sage, NumPy, pandas, Matplotlib,
scikit-learn, solver libraries, or compiler/toolchain bindings. Optional
drivers import optional packages only when explicitly invoked.
