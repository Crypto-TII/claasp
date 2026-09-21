# CLAASP v5: main changes

CLAASP v5 replaces the Sage-bound, mutable, implicitly bit-oriented v4 design
with a dependency-free typed core for describing, evaluating, transforming,
and analysing symmetric cryptographic primitives.

The main changes are:

- **Typed immutable graphs.** Wires carry shaped Bit, Word, binary-extension-
  field, or prime-field values. Components, ports, selections, rounds,
  composites, metadata, and provenance are immutable and validated.
- **Primitive-oriented API and catalogue.** Generic “cipher” terminology was
  replaced by primitive categories and deterministic discovery across 142
  migrated primitives and their retained realizations.
- **Separated semantics and backends.** Concrete execution and cryptanalytic
  meanings are independent of SAT, SMT, MILP, CP, polynomial, native-source,
  diagram, and presentation representations.
- **Typed analyses and results.** Trails, bounds, diagnostics, annotations,
  traces, evidence, and driver results carry explicit applicability and
  provenance instead of mutable backend dictionaries.
- **Safe external boundaries.** Optional solvers, statistical programs,
  compilers, LaTeX, NumPy, pandas, Matplotlib, and scikit-learn are isolated
  behind lazy drivers or adapters; importing the core requires none of them.
- **Canonical artifacts.** Primitive graphs and execution results have
  versioned deterministic serialization. Python and bounded C source can be
  generated reproducibly and executed through shell-free isolated drivers.
- **Transformations and presentation.** Inversion, slicing, editing, paired
  transformations, diagrams, tables, terminal/Markdown/CSV/JSON exports, and
  optional plotting consume immutable typed data without recomputation.
- **Release engineering.** The public API is mechanically enumerated and
  documented; executable examples, Ruff formatting/linting, mypy regression
  control, Sphinx builds, packaging audits, migration closure, and pinned
  multi-architecture Docker validation are CI gates.

The migration is not presented as automatic behavioral compatibility. The
complete generated comparison in `../final_migration_audit.md` records every
legacy source/test item and every shipped v5 artifact, including direct
migrations, splits, consolidations, removals, inapplicable package markers,
and genuinely new v5 modules with reasons.
