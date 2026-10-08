# Constraint-model provenance audit

## Scope and inventory

This ledger audits the structured `ConstraintModelProvenance` declarations in
CLAASP 5. It is separate from the legacy-backend recovery inventory: recovery
answers whether a strategy is represented, while this ledger answers whether
the exact shipped constraints correspond to a primary source.

The baseline after PR #630 contained 129 declarations on 126 public model
classes: 9 `VERIFIED`, 80 `N/A`, and 40 `TBD`. Repository-wide discovery also
found nine public CP constraint generators without any declaration; the old
component-only coverage test did not inspect trail, query, or lowering models.
The family audits will close those gaps before the final coverage gate is made
repository-wide.

After the modular-addition audit below there are 130 declarations on 127
classes: 10 `VERIFIED`, 79 `N/A`, and 41 `TBD`. The additional declaration
closes the missing provenance on `SpeckProbabilisticTruncatedCPModel`; the
status movement is `ModularAddNWindowSATModel` from `N/A` to `VERIFIED`.

## Modular addition, subtraction, and truncated variants

The audit compared the current implementation with legacy CLAASP commit
`3aacc2758059de85682a9c6d0eda2cd75940e747`, the recovery branches recorded in
the legacy-backend inventory, their introducing commits, comments,
documentation, bibliography, and tests. The modular-add boomerang automaton is
reserved for the boomerang/BCT family audit.

| Models | Status | Evidence and correspondence |
|---|---|---|
| `ModularAddDifferentialSATModel`, `ModularAddDifferentialSMTModel` | `VERIFIED` | Lipmaa--Moriai, *Efficient Algorithms for Computing Differential Properties of Addition*, <https://eprint.iacr.org/2001/001>, Section 4, Algorithm 2 and Theorem 1. The LSB parity, adjacent-bit support condition, and unary not-all-equal weight encode the paper's exact support and probability exponent. Legacy helpers explicitly name the Lipmaa--Moriai construction. |
| `ModularAddLinearSATModel`, `ModularAddLinearSMTModel`, `ModularAddLinearMILPModel` | `VERIFIED` | Liu--Wang--Rijmen, *Automatic Search of Linear Trails in ARX with Applications to SPECK and Chaskey*, DOI `10.1007/978-3-319-39555-5_26`, Section 3.1, Proposition 1 and Equation (1). The mask recurrence, two support inequalities, and unary objective are direct SAT, SMT, and MILP forms of that result. PR #630 repaired the MILP bit-zero support and first parity quotient before this status was retained. |
| `ModularAddNWindowSATModel` | `VERIFIED` | Bellini--Gérault--Grados--Peyrin, *The Window Heuristic: Automating Differential Trail Search in ARX Ciphers with Partial Linearization Trade-offs*, DOI `10.1007/978-3-031-88661-4_1`, Section 3.1, Definitions 1 and 2, and Section 3.2. The parity clauses define the carry-difference bits, the run clauses prohibit `window_size + 1` consecutive active carries, and the conjunction indicators identify the paper's full windows. |
| Functional and native-XOR modular add/subtract SAT models | `N/A` | Direct ripple-carry or ripple-borrow circuits generated from full-adder or full-subtractor truth functions; native XOR changes only the parity record. |
| Deterministic-truncated add SAT plus CP/SMT translations, and deterministic-truncated subtract SAT | `N/A` | Recovered finite paired-carry or paired-borrow Boolean relations with exhaustive semantic parity; CP and SMT preserve those clauses literally. No published construction is needed for the direct relation. |
| `SpeckARXWindowDifferentialCPModel` | `N/A` | Direct graph composition of the exact transition model with an explicit per-round window bound; it introduces no different constraint construction. |
| Counter-based probabilistic-truncated modular add in CP and SAT, plus the Speck CP and SAT compositions | `TBD` | The legacy counter/zero-run recurrence and costs `100, 41, 19, 9, 4, 0` have no attribution or derivation in the searched legacy sources. Biryukov et al., ePrint 2021/1194, Sections 3--4 and 6, was inspected and rejected: its dependency-conditioned truncation rules do not implement CLAASP's general ternary carry-choice cost relation. |
| Look-ahead semi-deterministic modular add SAT and the Speck SAT, MILP, and CP compositions | `TBD` | The pinned window 0--3 templates and three-bit cost code have no primary-source attribution or derivation in legacy source, documentation, bibliography, tests, or introducing history. |

Wallén's modular-add linear analysis (DOI
`10.1007/978-3-540-39887-5_20`) was inspected but is not attached to the current
linear models. The implementation uses Liu--Wang--Rijmen's explicit Equation
(1), rather than Wallén's recursive carry-correlation construction.

### Unresolved-search record

For the two `TBD` constructions, the search covered the primary legacy
snapshot, `origin/recover/sat-probabilistic-truncated`,
`origin/recover/sat-probabilistic-trails`,
`origin/recover/sat-semi-deterministic-trails`,
`origin/recover/cp-semi-differential-linear`, and the corresponding current
tests and benchmark records. The CP counter relation entered in commit
`7a3cb5475f4103425251173bd814c3217bcef8bc`; the SAT look-ahead templates trace
to commit `cbc559de6c919db0fa15d513fb36ab21f04d46f5`. Neither history contains a
paper, DOI, URL, or derivation. Searches for the exact cost sequence and
predicate terminology found no primary source matching the implemented
constraints, so both families remain `TBD`.
