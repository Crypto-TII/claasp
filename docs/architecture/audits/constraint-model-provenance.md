# Constraint-model provenance audit

## Scope and inventory

This ledger audits the structured `ConstraintModelProvenance` declarations in
CLAASP 5. It is separate from the legacy-backend recovery inventory: recovery
answers whether a strategy is represented, while this ledger answers whether
the exact shipped constraints correspond to a primary source.

The corrected baseline after PR #630 contained 128 declarations on 125 public
model classes: 9 `VERIFIED`, 79 `N/A`, and 40 `TBD`. Repository-wide discovery also
found nine public CP constraint generators without any declaration; the old
component-only coverage test did not inspect trail, query, or lowering models.
The family audits will close those gaps before the final coverage gate is made
repository-wide.

After the modular-addition audit below there are 129 declarations on 126
classes: 10 `VERIFIED`, 78 `N/A`, and 41 `TBD`. The additional declaration
closes the missing provenance on `SpeckProbabilisticTruncatedCPModel`; the
status movement is `ModularAddNWindowSATModel` from `N/A` to `VERIFIED`.

After the S-box and linear-layer MILP audit there are still 129 declarations
on 126 classes: 21 `VERIFIED`, 78 `N/A`, and 30 `TBD`. Eleven declarations
were matched to primary sources, while three generic finite-relation or
forbidden-assignment encodings moved from `TBD` to `N/A`.

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

## S-box and linear-layer MILP alternatives

This audit covered legacy commit `3aacc275`, the recovery commits for small
S-box facets, large-S-box Espresso tables, undisturbed bits, wordwise
relations, and bitwise XOR, plus their comments, tests, bibliography, and
introducing history. Bundled inequality systems are independently checked
against every DDT, LAT, or four-state input point when loaded.

| Models | Status | Evidence and correspondence |
|---|---|---|
| Differential S-box convex-hull and greedy MILP models | `VERIFIED` | Sun et al., *Towards Finding the Best Characteristics of Some Bit-oriented Block Ciphers and Automatic Enumeration of (Related-key) Differential and Linear Characteristics with Predefined Properties*, <https://eprint.iacr.org/2014/747>, Section 3, Fact 1 and Algorithm 1, and Section 5, Equation (6). The implementation constructs an H-representation for each nonzero DDT-count class and greedily selects the facet excluding the most remaining invalid Boolean points; selectors carry the class weight into the objective. |
| Differential S-box minimum-facet MILP model | `VERIFIED` | Sasaki--Todo, *New Algorithm for Modeling S-box in MILP Based Differential and Division Trail Search*, DOI `10.1007/978-3-319-69284-5_11`, Section 3. One binary variable selects each candidate facet, each invalid point has a covering constraint, and the objective minimizes selected facets. |
| Differential S-box Espresso MILP model | `VERIFIED` | Abdelkhalek--Sasaki--Todo--Tolba--Youssef, *MILP Modeling for (Large) S-boxes to Optimize Probability of Differential Characteristics*, DOI `10.13154/tosc.v2017.i4.99-129`, Sections 3.1--3.2 and Section 4.1, Definition 1. CLAASP separates the DDT by nonzero count, stores Espresso-minimized product-of-sums clauses, selects one count class conditionally, and applies its logarithmic weight. |
| Signed-LAT convex-hull, greedy, minimum, and Espresso MILP models | `TBD` | The legacy code mechanically substitutes signed LAT-count classes. Sun et al. establish linear-mask convex-hull support, Sasaki--Todo establish differential/division facet reduction, and Abdelkhalek et al. state linear applicability, but none of the inspected constructions specifies CLAASP's complete signed-count selectors and absolute-correlation objective. |
| One-hot DDT/LAT S-box models and both undisturbed-bit S-box models | `N/A` | The relations are enumerated directly from the supplied S-box. The compact undisturbed model merely applies generic Espresso minimization to Boolean projections of that exhaustive finite relation; the cited undisturbed-bit literature supplies the concept, not this encoding. |
| Wordwise XOR and dense-MDS component models, including their Espresso variants, and the SAT/CP/MILP deterministic wordwise graph models | `VERIFIED` | Sun--Gerault--Wang--Wang, *On the Usage of Deterministic (Related-Key) Truncated Differentials and Multidimensional Linear Approximations for SPN Ciphers*, DOI `10.13154/tosc.v2020.i3.262-287`, Section 2.1, Lemmas 1--4, Section 3.1, and Section 3.2, Models 1--5. The four `Z/N/N*/U` states, value-bearing XOR cases, bijective S-box mapping, and dense-MDS propagation match the published relations; one-hot and Espresso forms encode the same checked rows. |
| Parity-quotient XOR, impossible-point XOR, and the conservative wordwise impossible boundary | `N/A` | These are direct algebraic, generic forbidden-assignment, or finite selector encodings. The four wordwise contradiction pairs are intentionally weaker than the value-sensitive miss-in-the-middle construction in Sun et al. and are not attributed to it. |

### Unresolved-search record

For the four signed-LAT alternatives, the search inspected legacy generators
and cached systems, recovery and introducing history, Sun et al. ePrint
2014/747 including Appendix A, Sasaki--Todo's Section 3, Abdelkhalek et al.
Sections 3--4, and Sun--Wang's 2023 SAT treatment. These sources support the
individual ideas or a different backend, but no primary source was found for
the implemented combination of signed Walsh-count classes, class selectors,
and absolute-correlation objective. The four declarations therefore remain
`TBD` rather than inheriting a citation by analogy.
