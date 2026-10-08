# Legacy constraint-backend parity: trail-search correction

The earlier migration term “superseded” describes replacement of legacy
backend-shaped mutable classes by typed graphs, shared semantics, and immutable
constraint representations. It does **not** establish public optimizer or
component-catalogue parity by itself.

The public optimizer now uses capability-based dispatch. Exact SAT optimization
is available for Word graphs composed from fixed rotations and shifts, XOR,
identity, constants, two-input modular addition/subtraction, two-input AND/OR,
NOT, and logical-unit permutations. The optimizer finds a feasible
characteristic, minimizes its integer weight by binary search, proves the
immediately lower bound UNSAT, decodes the assignment, and independently checks
the graph characteristic. Specialized dependency-free PRESENT and Speck paths
remain explicit optional implementations.

The executable catalogue matrix is
[`data/trail-search-capability-matrix.json`](data/trail-search-capability-matrix.json).
It covers every public primitive export using its default graph or a one-round
configuration when the constructor exposes `number_of_rounds`. The matrix is
regenerated and compared in the test suite; representative Simon, Simeck, CHAM,
Speck, SPARX, Threefish, ChaCha, and Salsa graphs also construct both exact CNF
models in focused tests.

Remaining gaps are semantic, not dispatch restrictions:

- bit-vector and finite-field S-box graphs need weighted exact whole-graph SAT
  composition in the generic optimizer; PRESENT's reviewed dependency-free
  slice does not imply generic S-box coverage;
- `LinearMap` over bit vectors or finite fields needs domain-specific mask and
  difference lowering, while modular word maps are not automatically
  XOR-linear;
- variable shifts/rotations, modular multiplication, IDEA multiplication,
  feedback registers, and other catalogue operations lack exact weighted XOR
  transition models;
- a few catalogue constructors cannot form the chosen reduced/default graph;
  their precise constructor failures are recorded rather than mislabeled as
  exact search support.

Consequently, the migration has representation parity for the listed Word
slice and public optimizer parity for graphs made entirely from that slice. It
does not claim complete legacy catalogue parity.
