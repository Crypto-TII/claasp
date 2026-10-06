# CLAASP v5: main changes

CLAASP v5 is a major redesign of the library. It keeps the main purpose of
CLAASP—describing and analysing symmetric cryptographic constructions—but
makes the internal model more general, modular, and easier to extend.

The main changes are:

- **State types other than bits.** In older CLAASP versions, the graph was
  essentially bit-based. In v5, a state can contain bits, fixed-size words,
  binary-extension-field elements, or prime-field elements. This allows a
  primitive to be described using the data type that naturally matches its
  specification.
- **Ports make graph wiring explicit.** A `Port` is a named, typed source of
  data, such as a primitive input or a component output. A `Selection` chooses
  an ordered set of logical units from that port. A connection is made when
  such a selection is used by another component or as the primitive output; it
  is a relationship, not a separate public object. Structural operations such
  as joining, viewing, packing, or unpacking values are recorded as
  `ValueBinding` objects. They can create new ports, but they are not presented
  as cryptographic operations. This distinction keeps data sources, wiring,
  and operations clear in every representation of the graph.
- **“Cipher” was refactored into “primitive.”** The generic term "cipher"
  has been replaced with the more accurate cryptographic "primitive",
  referring to fixed input and fixed output length functions. The main graph
  class is now `Primitive`, and the catalogue partitions primitives based on
  whether they are keyed, bijective or not, and whether they accept parameters.
  Precisely there are unkeyed permutations, unkeyed functions, keyed block
  ciphers, keyed block functions, tweakable keyed block ciphers, and tweakable
  keyed block functions. Names such as AES, Speck, ChaCha, etc. no longer need
  an artificial `Cipher` suffix.
- **Realizations are explicit.** CLAASP already contained cases where the same
  primitive had several implementations—for example a word implementation and
  an S-box implementation. V5 calls these *realizations*. They are grouped
  under one public primitive family instead of appearing as unrelated
  primitives. A realization records how the primitive is implemented and when
  it is applicable, while preserving the identity of the primitive itself.
- **Responsibilities are better separated.** The main packages now have clear
  jobs:

  - `domains` defines the kinds of values carried by a state;
  - `graph` defines primitives, ports, selections, structural bindings,
    rounds, and metadata;
  - `components` defines operations such as XOR, modular addition, S-boxes,
    linear maps, and permutations;
  - `primitives` contains concrete primitive specifications;
  - `semantics` defines what values, differences, masks, and transitions
    mean;
  - `representations` translates those meanings into executable operations,
    SAT, SMT, MILP, CP, polynomial systems, generated source, or diagrams;
  - `drivers` runs interpreters, solvers, compilers, and external tools;
  - `analysis` coordinates analyses and returns typed results;
  - `transformations` creates changed graphs without modifying the original;
  - `presentation` formats results without recomputing them.

  In particular, a component no longer contains SAT, SMT, MILP, CP, or code-
  generation methods. It only describes the operation. Representation-specific
  constraints and code live in the corresponding representation package. This
  makes components reusable and lets a backend change without changing every
  component class.
- **AO primitives were introduced.** V5 includes native prime-field support
  and initial arithmetization-oriented primitives, including MiMC and Poseidon.
  Dedicated AO analysis modules are intentionally still to be designed and
  implemented; adding them is one of the next validation steps for the new
  architecture.
- **The Docker environment is much lighter.** The release image uses ordinary
  Python and does not contain SageMath. Optional solvers and tools are still
  available, but they are installed independently of the core library. The
  current canonical images are approximately 640–652 MB.
- **Graphs and results are safer to exchange.** Primitive graphs and execution
  results have versioned, deterministic serialization. CLAASP can also generate
  deterministic Python and bounded C source and run it through isolated
  drivers.
- **Analyses return clearer results.** Trails, bounds, diagnostics, traces,
  annotations, and provenance use explicit result objects rather than loosely
  structured mutable dictionaries.
- **Optional dependencies stay optional.** Solvers, statistical programs,
  compilers, LaTeX, NumPy, pandas, Matplotlib, and scikit-learn are loaded only
  by the adapters that need them. Importing the core does not require them.
- **Transformations and output were reorganized.** Inversion, slicing, graph
  editing, diagrams, tables, JSON, CSV, Markdown, terminal output, and optional
  plots work from the same typed data without changing the primitive or
  repeating an analysis.
- **Documentation was greatly improved.** The user and developer guides now
  explain the architecture, public API, primitive authoring, representations,
  optional tools, and contribution workflow. Public classes and functions also
  include small executable examples, so the documentation shows how the
  library behaves and is checked against the code.
- **Documentation and quality checks are automatic.** The public API,
  examples, formatting, linting, typing baseline, documentation builds,
  package contents, migration records, and multi-architecture release
  environment all have automated checks.

The migration does not assume that every old API should be reproduced exactly.
The complete comparison in `audits/final_migration_audit.md` lists every legacy
source and test record and every shipped v5 artifact. It shows what moved
directly, what was split or combined, what was removed, and what is new, with a
reason for each decision.
