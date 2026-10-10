# Legacy constraint-backend parity: executable trail-search audit

The earlier migration term “superseded” describes replacement of legacy
backend-shaped mutable classes by typed graphs, shared semantics, and immutable
constraint representations. It does **not** establish public optimizer or
component-catalogue parity by itself.

The public optimizer now uses capability-based dispatch. Exact optimization is
available for `Bit`, `Word`, and `BinaryExtensionField` graphs composed from
fixed rotations and shifts, XOR/addition in linear domains, identity,
constants, two-input modular addition/subtraction, two-input AND/OR, NOT,
permutations, binary/finite-field linear maps, affine binary maps, and lookup
tables whose nonzero DDT or LAT counts give integral exact weights. The
optimizer finds a feasible
characteristic, minimizes its integer weight by binary search, proves the
immediately lower bound UNSAT, decodes the assignment, and independently checks
the graph characteristic. The same exact Boolean relation is consumable through
the SAT, SMT, MILP, and CP public backends; solver-specific integration tests
exercise MiniSat, Z3, GLPK, and MiniZinc. Specialized dependency-free PRESENT
and Speck paths remain explicit optional implementations.

The executable catalogue matrix is
[`data/trail-search-capability-matrix.json`](data/trail-search-capability-matrix.json).
It covers all 142 public primitive exports using a reduced graph where the
constructor permits one and a vetted/default graph otherwise. The current
machine-generated result has 102 primitives supporting both kinds, five more
supporting differential search, and one more supporting linear search: 210 of
284 primitive/kind cells. The matrix is regenerated and compared in the test
suite. Focused tests materialize and solve Word, Bit, and binary-field models,
including Simon, Simeck, CHAM, Speck, SPARX, Threefish, ChaCha, Salsa, Ascon,
PRESENT, and one-round AES. The AES differential optimum is 6 and is decoded
and checked from the exact field/S-box graph.

The remaining 74 cells are recorded as `unsupported` with the first exact
reason. They are not called migrated optimizer capabilities. They fall into
these categories:

- non-power-of-two DDT/LAT counts have non-integral `-log2` weights. Legacy
  SAT/SMT rejected these tables too; legacy MILP used configurable decimal
  rounding. That approximation is not an exact optimum proof and v5 does not
  silently relabel it as one;
- variable shifts/rotations, modular/IDEA/general multiplication, powers, and
  feedback registers do not have an exact legacy generic XOR transition model;
- legacy component code explicitly assumed two operands for modular addition
  and AND/OR. Catalogue graphs containing three-to-five operand nodes are
  rejected instead of applying that invalid binary assumption;
- two TinyJambu word/FSR catalogue graphs have no declared primitive output and
  therefore cannot define a public trail boundary.

This distinction matters: legacy CLAASP exposed many backend classes, but that
did not make every catalogue graph an executable or exact model. The v5 public
optimizer now covers the full generic exact component set that those legacy
models actually supported, including the previously hidden Bit and finite-field
cases. Unsupported rows describe genuine semantic or legacy-model limits, not
family-name dispatcher bugs.
