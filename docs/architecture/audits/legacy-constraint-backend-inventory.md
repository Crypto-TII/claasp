# Legacy constraint-backend recovery inventory

## Purpose and scope

This inventory preserves the constraint-generation work in legacy CLAASP and
identifies deliberate recovery work for CLAASP 5. It is not a claim that the v5
migration is incomplete, that a legacy formulation is faster, or that every
legacy result is correct. Those questions require parity tests and comparable
benchmarks.

The primary legacy snapshot is `origin/develop` at
`3aacc2758059de85682a9c6d0eda2cd75940e747` (2026-10-05). The CLAASP 5
comparison is `docs/v5-user-guide-and-trail-reporting` at
`2a0773ce8020839987d30595f57aad7766666043` (2026-10-07). Unmerged legacy
branches are inventoried separately because they are preservation evidence,
not established behavior.

The classifications used below are:

- **Covered**: v5 has the same essential constraint capability. Exact formula
  identity and performance are not implied.
- **Partial**: v5 preserves some semantics or representative models but not the
  generic legacy backend strategy or its full component coverage.
- **Recover**: preserve the legacy method as an explicitly named alternative,
  subject to license, provenance, parity, and benchmark gates.
- **Inspect**: retain the evidence, but establish correctness and usefulness
  before accepting it as a recovery candidate.
- **Do not port wrapper**: retain useful predicates or fixtures, but not the
  mutable orchestration, solver parsing, generated filenames, or incidental
  output format of the legacy class.

## Backend search-model inventory

Every public legacy backend model class is accounted for below. Base container
classes are listed because their solver coupling must not leak back into the v5
representation layer.

### MiniZinc and CP

| Legacy class | Model kind | v5 coverage | Disposition |
|---|---|---|---|
| `MznModel` and `MiniZincModelParts` | Backend container, solver invocation, parsing, weight constraints | `cp.model.MiniZincModel` plus the MiniZinc driver | Covered; do not port wrapper |
| `MznCipherModel` | Functional component execution | CNF-to-MiniZinc lowering for constants, structural wiring, XOR/add/multiply over GF(2), AND, OR, NOT, fixed and variable shifts/rotations, modular addition/subtraction/power-of-two multiplication, and bit-vector S-boxes | Partial; IDEA and explicit non-power-of-two multiplication are extensions because legacy exposes no functional backend encoding |
| `MznCipherModelARXOptimized` | Functional ARX construction | Portable Boolean lowering | Inspect; its legacy builder can omit modular addition, so do not port the class as an optimization |
| `MznXorDifferentialModel` | Exact XOR-differential trail search | Local/native models plus portable generic `WordDifferentialCPModel` | Covered for the reviewed Word graph subset; continue component coverage |
| `MznXorDifferentialModelARXOptimized` | ARX XOR-differential search with per-round n-window pruning | `SpeckARXWindowDifferentialCPModel` over the exact Speck CP formulation | Recovered for reviewed Speck32/64 slices as an opt-in heuristic |
| `MznXorDifferentialNumberOfActiveSboxesModel` | First-step active-S-box bound | `PresentActiveSBoxesCPModel` over exact DDT tables | Recovered for reviewed PRESENT slices; continue generic component coverage |
| `MznXorDifferentialFixingNumberOfActiveSboxesModel` | Two-step active-S-box then exact-weight search | `PresentFixedActiveSBoxesCPModel` over exact DDT tables | Both stages recovered for reviewed PRESENT slices; continue generic component coverage |
| `MznXorLinearModel` | Exact XOR-linear trail search | Local/native models plus portable generic `WordLinearCPModel` | Covered for the reviewed Word graph subset; continue component coverage |
| `MznDeterministicTruncatedXorDifferentialModel` | Bitwise deterministic truncated propagation and search | Local paired-carry and generic Word-graph CP models plus the specialized Speck model | Covered for the reviewed Word graph subset; retain specialized models |
| `MznDeterministicTruncatedXorDifferentialModelARXOptimized` | Incomplete ARX deterministic-truncated wrapper | Complete `WordDeterministicTruncatedCPModel` and specialized `SpeckTruncatedCPModel` | Reviewed removal: legacy dispatch accepted only ROTATE/SHIFT and skipped modular addition/XOR, so it contains no distinct complete formulation to recover |
| `MznWordwiseDeterministicTruncatedXorDifferentialModel` | Wordwise deterministic truncated search | `WordwiseDifferenceCPModel` and shared semantics | Partial; recover generic graph assembly |
| `MznSemiDeterministicTruncatedXorDifferentialModel` | Semi-deterministic truncated search | Portable `SpeckSemiDeterministicTruncatedCPModel` with typed decoding | Recovered for reviewed Speck32/64 slices; continue component coverage |
| `MznImpossibleXorDifferentialModel` | Impossible differential, extensions, automatic and chosen boundaries | `WordImpossibleCPModel` plus native reviewed Speck and Simon models | Generic reversible Word-graph assembly recovered; continue unsupported components and automatic-boundary heuristics |
| `MznHybridImpossibleXorDifferentialModel` | Hybrid improbable/impossible search | No equivalent backend strategy | Recover after soundness review |
| `MznDifferentialLinearModel` | Differential-linear composition | Portable deterministic and semi-deterministic CP models with typed decoding | Recovered for reviewed Speck round slices; continue component coverage |
| `MznDifferentialLinearContinuousModel` | Continuous, approximate differential-linear optimization | `SpeckContinuousHeuristicCPModel` plus dependency-free semantics and fixed evidence | Fixed-input nonlinear propagation recovered with heuristic-only results; optimization and broader component dispatch remain pending |
| `MznBoomerangModelARXOptimized` | ARX boomerang search with a MiniZinc BCT switch | Exact local switches plus `ModularAddBoomerangTrailCPModel` top/switch/bottom composition | Generic caller-supplied Word graphs and the legacy upper-plus-lower objective recovered; automatic graph partitioning and S-box-switch assembly remain |

### MILP

| Legacy class | Model kind | v5 coverage | Disposition |
|---|---|---|---|
| `MilpModel` | Sage MILP container, solver selection, parsing | Solver-independent `MILPModel` plus explicit drivers | Covered; do not port wrapper |
| `MilpCipherModel` | Functional execution | Exact CNF-to-MILP Boolean graph model | Covered for the v5 Boolean subset; do not recover the incomplete legacy wrapper |
| `MilpXorDifferentialModel` | Weighted XOR-differential trail search | Local/native models plus portable generic `WordDifferentialMILPModel` | Covered for the reviewed Word graph subset; continue component coverage |
| `MilpXorLinearModel` | Weighted XOR-linear trail search | Local/native models plus portable generic `WordLinearMILPModel` | Covered for the reviewed Word graph subset; continue component coverage |
| `MilpXorDifferentialNumberOfActiveSboxesModel` | Active-S-box objective and fixed-activity weight search | `PresentActiveSBoxesMILPModel` and `PresentFixedActiveSBoxesMILPModel` over the exact two-round DDT formulation | Both stages recovered for reviewed PRESENT slices; continue generic component coverage |
| `MilpWordwiseBranchNumberNumberOfActiveSboxesModel` | Wordwise branch-number activity bound | `WordwiseBranchNumberActiveSBoxesMILPModel` with typed decoding | Recovered for supported bijective S-box, XOR, wiring, and invertible linear-map graphs; retain lower-bound labeling |
| `MilpBitwiseDeterministicTruncatedXorDifferentialModel` | Bitwise deterministic truncated search | `WordDeterministicTruncatedMILPModel` over the generic reviewed Word graph | Covered for the reviewed Word graph subset; continue component coverage |
| `MilpWordwiseDeterministicTruncatedXorDifferentialModel` | Wordwise deterministic truncated search | Finite-relation infrastructure and shared semantics | Partial; recover generic assembly |
| `MilpBitwiseImpossibleXorDifferentialModel` | Bitwise impossible differential | `WordImpossibleMILPModel` with transformed forward/backward graphs and a Speck compatibility specialization | Generic reversible Word-graph assembly recovered; continue unsupported components and automatic-boundary heuristics |
| `MilpWordwiseImpossibleXorDifferentialModel` | Wordwise impossible differential | Typed four-state semantics and exact `WordwiseImpossibleBoundaryMILPModel` selector | Middle incompatibility relation recovered and benchmarked; whole-graph four-state propagation remains |
| `MilpMonomialPredictionModel` | Gurobi monomial prediction, division-property bounds, degree, superpoly, and key-coefficient searches | Portable graph models, `MonomialDegreeMILPModel`, `CubeMonomialFeasibilityMILPModel`, bounded exact `CubeSuperpolyQuery`, and optional non-default Gurobi optimal-solution pools | Partial; degree, cube feasibility, bounded exact parity, and solver-pool infrastructure are recovered; scalable pool-to-polynomial reconstruction still requires a reviewed projection/parity strategy |

### SAT and CryptoMiniSat

| Legacy class | Model kind | v5 coverage | Disposition |
|---|---|---|---|
| `SatModel` | CNF container, solver selection, parsing, weight constraints | `CNFFormula`, exporters, and explicit SAT drivers | Covered; do not port wrapper |
| `SatCipherModel` | Functional execution | Exact `BooleanCNFModel` for constants, structural wiring, XOR/add/multiply over GF(2), AND, OR, NOT, fixed and variable shifts/rotations, modular addition/subtraction/power-of-two multiplication, and bit-vector S-boxes | Covered for established functional encodings; IDEA's legacy methods are explicit stubs, while non-power-of-two multiplication is a v5 extension |
| `CmsSatCipherModel` | Functional execution using native XOR clauses | `BooleanNativeXorSATModel` plus extended-DIMACS export | Recovered for the reviewed Boolean graph subset and benchmarked against ordinary CNF |
| `SatXorDifferentialModel` | Exact weighted XOR-differential search and n-window heuristic | `WordDifferentialSATModel` plus opt-in `NWindowSATStrategy` | Generic assembly and dependency-free uniform/per-round/per-component n-window strategy recovered |
| `CmsSatXorDifferentialModel` | XOR-differential search with native XOR clauses | `WordDifferentialNativeXorSATModel` | Recovered for the typed Word graph subset and benchmarked against ordinary CNF |
| `SatXorLinearModel` | Exact weighted XOR-linear search | `WordLinearSATModel` | Recovered for the typed Word graph subset; continue component coverage separately |
| `CmsSatXorLinearModel` | XOR-linear search with native XOR clauses | `WordLinearNativeXorSATModel` | Recovered for the typed Word graph subset and benchmarked against ordinary CNF |
| `SatBitwiseDeterministicTruncatedXorDifferentialModel` | Bitwise deterministic truncated search | Recovered local `ModularAddDeterministicTruncatedSATModel` and whole-graph `WordDeterministicTruncatedSATModel` | ARX/structural Word subset recovered; continue remaining components |
| `CmsSatDeterministicTruncatedXorDifferentialModel` | Deterministic truncated search; legacy wrapper reused ordinary SAT unchanged | `WordDeterministicTruncatedNativeXorSATModel` recovers a verified native-parity alternative while retaining ordinary CNF | Recovered and benchmarked against ordinary CNF |
| `SatTruncatedXorDifferentialModel` | Truncated-model base and fixed-value handling | Shared semantic types | Covered as semantics; do not port the base wrapper |
| `SatSemiDeterministicTruncatedXorDifferentialModel` | Semi-deterministic truncated search | `ModularAddSemiDeterministicTruncatedSATModel` and `SpeckSemiDeterministicTruncatedSATModel` | Recovered for reviewed windows and Speck32/64 slices; literature correspondence remains unaudited |
| `SatProbabilisticXorTruncatedDifferentialModel` | Probabilistic truncated search | `ProbabilisticTruncatedModularAddSATModel` and `SpeckProbabilisticTruncatedSATModel` | Recovered for reviewed modular-add and Speck32/64 slices |
| `SatBitwiseImpossibleXorDifferentialModel` | Bitwise impossible differential | `WordImpossibleSATModel`, local `ImpossibleBoundarySATModel`, and the reviewed Speck specialization | Generic reversible Word-graph split-round search recovered; continue unsupported components and automatic-boundary heuristics |
| `SatDifferentialLinearModel` | Differential-linear SAT search | Deterministic- and semi-deterministic-middle whole-graph SAT models with typed decoding | Recovered for reviewed Speck round slices; continue component coverage |
| `SharedDifferencePairedInputDifferentialModel` | Two differential characteristics with a shared input difference and modular-add output exclusions | `SharedDifferencePairedWordDifferentialSATModel` with typed paired result | Recovered and benchmarked; literature interpretation remains TBD |
| `SharedDifferencePairedInputDifferentialLinearModel` | Paired-input differential-linear search | `SharedDifferencePairedWordDifferentialLinearSATModel` with typed paired prefix and linear suffix | Recovered and benchmarked; interpretation and boundary provenance remain TBD |

### SMT

| Legacy class | Model kind | v5 coverage | Disposition |
|---|---|---|---|
| `SmtModel` | SMT-LIB container, solver invocation, parsing, weight constraints | `SMTFormula`, exporter, and explicit drivers | Covered; do not port wrapper |
| `SmtCipherModel` | Functional execution | CNF-derived `BooleanSMTModel` for constants, structural wiring, XOR/add/multiply over GF(2), AND, OR, NOT, fixed and variable shifts/rotations, modular addition/subtraction/power-of-two multiplication, and bit-vector S-boxes | Covered for established functional encodings; IDEA's legacy methods are explicit stubs, while non-power-of-two multiplication is a v5 extension |
| `SmtXorDifferentialModel` | Weighted XOR-differential search | Local S-box/modular-add encodings and generic word-differential composition | Reviewed Word subset covered with exact SAT-formula parity and independent Z3 decoding; continue unsupported components |
| `SmtXorLinearModel` | Weighted XOR-linear search | Local S-box/modular-add encodings and generic word-linear composition | Reviewed Word subset covered with exact SAT-formula parity and independent Z3 decoding; continue unsupported components |
| `SmtDeterministicTruncatedXorDifferentialModel` | Deterministic truncated search | Local modular-add and generic Word-graph SMT strategies | Covered by the recovered paired-carry Boolean relation and typed independent decoding |

### Algebraic and adjacent models

| Legacy class | Model kind | v5 coverage | Disposition |
|---|---|---|---|
| `AlgebraicModel` | Sage Boolean-polynomial system construction and algebraic-security probes | Dependency-free Boolean/prime-field polynomial representations, exporters, and typed algebraic analysis | Covered in architecture; inventory individual missing analyses before recovering any Sage-specific strategy |

## Legacy component-encoding surface

The following matrix is derived from the public constraint methods defined by
or inherited by each component class in the legacy snapshot. It records API
surface, not correctness or solver support. A blank means that no component
method exists for that backend.

Codes: `F` functional, `D` XOR differential, `L` XOR linear, `A` active-S-box
or first-step abstraction, `BDT` bitwise deterministic truncated, `WDT`
wordwise deterministic truncated, `SDT` semi-deterministic truncated, `HDT`
hybrid deterministic truncated, `UDT` undisturbed-bit truncated, `C`
continuous, and `I` inverse structural constraints. `CMS` denotes the legacy
CryptoMiniSat/native-XOR path rather than a separate mathematical semantics.

| Legacy component | CP | MILP | SAT | CMS | SMT |
|---|---|---|---|---|---|
| `And` | BDT, D, F, L, WDT | BDT, D, L | BDT, D, F, L | D, F, L | D, F, L |
| `CipherOutput` | A, BDT, C, D, F, L, SDT, WDT | A, BDT, D, F, L, WDT | BDT, D, F, L, SDT | D, F, L | D, F, L |
| `Constant` | A, BDT, C, D, F, L, SDT, WDT | A, BDT, D, L, WDT | BDT, D, F, L, SDT | D, F, L | D, F, L |
| `Fsr` | — | — | — | — | — |
| `IdeaModmul` | BDT, C, D, F, L, SDT, WDT | BDT, D, L | BDT, D, F, L, SDT | D, F, L | D, F, L |
| `IntermediateOutput` | A, BDT, C, D, F, L, SDT, WDT | A, BDT, D, F, L, WDT | BDT, D, F, L, SDT | D, F, L | D, F, L |
| `LinearLayer` | BDT, D, F, L, SDT, WDT | A, BDT, D, F, L, WDT | BDT, D, F, L | D, F, L | D, F, L |
| `MixColumn` | A, BDT, D, F, L, SDT, WDT | A, BDT, D, F, L, WDT | BDT, D, F, L | D, F, L | D, F, L |
| `ModAdd` | BDT, C, D, F, L, SDT, WDT | BDT, D, L | BDT, D, F, L, SDT | D, F, L | D, F, L |
| `ModMul` | BDT, C, D, L, SDT, WDT | BDT, D, L | BDT, D, L, SDT | D, L | D, L |
| `ModSub` | BDT, C, D, F, L, SDT, WDT | BDT, D, L | BDT, D, F, L, SDT | D, F, L | D, F, L |
| `Modular` | BDT, C, D, L, SDT, WDT | BDT, D, L | BDT, D, L, SDT | D, L | D, L |
| `MultiInputNonlinearLogicalOperator` | BDT, D, WDT | D, L | BDT, D, L | D, F, L | D, L |
| `Not` | A, BDT, D, F, L, SDT, WDT | A, BDT, D, F, L | BDT, D, F, L | D, F, L | D, F, L |
| `Or` | BDT, D, F, L, WDT | D, L | BDT, D, F, L | D, F, L | D, F, L |
| `Permutation` | A, BDT, D, F, L, SDT, WDT | A, BDT, D, F, L, WDT | BDT, D, F, L, SDT | D, F, L | D, F, L |
| `Reverse` | BDT, D, F, L, SDT, WDT | A, BDT, D, F, L, WDT | BDT, D, F, L | D, F, L | D, F, L |
| `Rotate` | A, BDT, C, D, F, I, L, SDT, WDT | A, BDT, D, F, L, WDT | BDT, D, F, L, SDT | D, F, L | D, F, L |
| `Sbox` | A, BDT, D, F, HDT, L, SDT, WDT | A, BDT, D, L, UDT, WDT | BDT, D, F, L | D, F, L | D, F, L |
| `Shift` | A, BDT, D, F, I, L, SDT, WDT | BDT, D, F, L, WDT | BDT, D, F, L | D, F, L | D, F, L |
| `ShiftRows` | A, BDT, C, D, F, I, L, SDT, WDT | A, BDT, D, F, L, WDT | BDT, D, F, L, SDT | D, F, L | D, F, L |
| `Sigma` | BDT, D, F, L, SDT, WDT | A, BDT, D, F, L, WDT | BDT, D, F, L | D, F, L | D, F, L |
| `ThetaGaston` | BDT, D, F, L, SDT, WDT | A, BDT, D, F, L, WDT | BDT, D, F, L | D, F, L | D, F, L |
| `ThetaKeccak` | BDT, D, F, L, SDT, WDT | A, BDT, D, F, L, WDT | BDT, D, F, L | D, F, L | D, F, L |
| `ThetaXoodoo` | BDT, D, F, L, SDT, WDT | A, BDT, D, F, L, WDT | BDT, D, F, L | D, F, L | D, F, L |
| `VariableRotate` | — | — | — | — | — |
| `VariableShift` | D, F | — | F | F | F |
| `WordPermutation` | A, BDT, D, F, L, SDT, WDT | A, BDT, D, F, L, WDT | BDT, D, F, L, SDT | D, F, L | D, F, L |
| `Xor` | A, BDT, C, D, F, HDT, L, SDT, WDT | A, BDT, D, F, L, WDT | BDT, D, F, L, SDT | D, F, L | D, F, L |

Inheritance explains repeated rows: for example, `Reverse`, `Sigma`, and the
theta components inherit linear-layer encodings. Recovery tests must prove
that an inherited method actually supports the derived component; method
presence alone is insufficient. `Fsr` and `VariableRotate` have no legacy
component constraint methods in the audited snapshot and therefore are not
lost backend implementations.

The current v5 local component models cover a much smaller but explicit set:

- functional SAT for constants, identity/permutation/fixed and variable
  shift/rotation wiring, XOR/add, bitwise AND/OR/NOT, modular
  addition/subtraction/power-of-two multiplication, and bit-vector S-boxes;
  SMT, CP, and functional MILP reuse this supported CNF subset;
- XOR-differential and XOR-linear S-box relations in SMT and MILP, plus the
  XOR-differential S-box and BCT relations in CP;
- XOR-differential and XOR-linear modular addition in SMT, XOR-linear modular
  addition in MILP, and probabilistic-truncated modular addition in CP; and
- complete trail assembly for reviewed PRESENT, Speck, Simon, wordwise, and
  monomial slices rather than generic coverage of the legacy component matrix.

Consequently, a v5 semantic type or representative trail fixture is not enough
to classify a legacy backend formulation as covered.

## Encoding generators and search machinery

These legacy utilities materially change formulations and must be preserved as
strategy candidates, not copied into shared semantics:

| Legacy machinery | Purpose | Disposition |
|---|---|---|
| Small-S-box convex hull plus greedy or MILP inequality reduction | Differential and linear S-box MILP | Recover as explicit alternatives to one-hot rows |
| Large-S-box Espresso product-of-sums | Differential and linear 4--8-bit S-box MILP | Recover behind an optional Espresso tool boundary |
| AND convex hull and reduced inequalities | Differential and linear Boolean MILP | Recovered as explicit compact alternatives with exhaustive one-bit parity |
| Impossible-point XOR inequalities and matrix-specific caches | Functional and linear-layer MILP | Inspect against direct CNF-to-MILP before recovery |
| Wordwise XOR and truncated-MDS Espresso relations | Wordwise truncated MILP | Recover without mutable package-tree pickle caches |
| Undisturbed-bit S-box Espresso relations | Bitwise truncated S-box MILP | Recover |
| SAT n-window clauses and per-round/per-component controls | Modular-add differential search heuristic | Recover as a switchable heuristic, never as changed semantics |
| MiniZinc word-operation predicates | CP differential, linear, truncated, and ARX searches | Recover per operation with independent exhaustive tests |
| MiniZinc BCT predicates | ARX boomerang switch | Recover with exact switch-semantics tests |
| MiniZinc continuous predicates | Approximate differential-linear search | Inspect; preserve heuristic labeling and numerical tolerances |

Generated pickle caches, temporary LP files, solver logs, and generated model
filenames are not recovery targets. Reproducible generators and cache formats,
if still useful, must live outside the installed package tree.

## Unmerged legacy-branch evidence

The following remote branches contain constraint work beyond the primary
snapshot. They must not be deleted or silently folded into a recovery PR. Each
needs a focused correctness, provenance, license, and test review before its
methods can be called established.

| Branch and audited tip | Additional or changed work | Initial classification |
|---|---|---|
| `SharedTruncatedDifferencePairedInputDifferentialLinearModel` at `34d010b7` | Shared-truncated paired-input differential-linear SAT model and tests | Inspect; WIP commit |
| `adding_boomerang_checker` at `d3362018` | Empirical boomerang checker and model-test changes | Inspect as validation tooling |
| `feat/add_alternative_impossible_differential_model` at `e6b1d281` | Alternative impossible models for CP, MILP, SAT, CMS, and SMT | High-priority archaeology before impossible-model recovery |
| `feat/cp_impossible_wordwise` at `e5e35864` | Wordwise CP impossible model and component changes | Inspect alongside the preceding branch |
| `feature/quasidifferential-implementation` at `a1d08125` | SMT quasidifferential model plus component encodings | Inventory as a distinct semantic family before porting |
| `fix_sat_differential_linear_model` at `af85330e` | Corrections around SAT differential-linear support | Compare with `origin/develop` before using it as an oracle |
| `hadipour_boomerang_model` at `0c95dd6e` | Hadipour model; BCT, EBCT, LBCT, and UBCT predicates and evaluators | High-priority boomerang archaeology; verify exact paper-to-code correspondence |
| `mzn_differential_linear_cleaning_code` at `b055080a` | Differential-linear and semi-deterministic MiniZinc cleanup | Compare before CP recovery |
| `refactor/milp_bounded_trail_search` at `b398555f` | Bounded MILP differential and linear search changes | Benchmark candidate |
| `modc_basic_trail_search` at `b169b1d7` | Monomial-prediction changes and tests | Compare before Gurobi capability recovery |

Branch tips are evidence locators, not stable public references. A recovery PR
must record the exact commit it uses.

## Recovery comparison matrix

This is the shared planning matrix that later recovery PRs must update. A
source ending in `components/*` means the graph-wide class dispatches to
component methods as part of the formulation. `Pending` means that the present
inventory found and classified the implementation but did not validate or
benchmark it.

| Strategy family | Legacy source | v5 baseline | Optional dependencies | Parity | Benchmark |
|---|---|---|---|---|---|
| Functional component models | `cp/mzn_models/mzn_cipher_model.py`, `milp/milp_models/milp_cipher_model.py`, `sat/sat_models/sat_cipher_model.py`, `smt/smt_models/smt_cipher_model.py`, `components/*` | `BooleanCNFModel` and derived SMT/CP/MILP forms | MiniSat, Z3, MiniZinc/Chuffed, and GLPK | OR, NOT, fixed and variable shifts/rotations, exact sequential ripple-borrow subtraction, GF(2) multiplication, and power-of-two modular multiplication join the existing subset; exhaustive small-width tests and one composed graph validate the relations | [Cross-backend functional word components](data/functional_word_components_benchmark.json); IDEA and explicit non-power-of-two modular multiplication remain v5 extension work because their legacy backend methods are absent or explicit stubs |
| CP XOR differential | `cp/mzn_models/mzn_xor_differential_model.py`, `components/*` | Local CP S-box plus portable generic `WordDifferentialCPModel` | MiniZinc and selected CP/MIP solver | Exact ToySpeck fixed-weight witness decoded and independently rechecked under Chuffed | [Portable generic Word trails](data/cp_word_trail_benchmark.json) |
| CP ARX optimized differential | `cp/mzn_models/mzn_xor_differential_model_arx_optimized.py`, `components/modular_component.py` | Exact `SpeckDifferentialCPModel` plus opt-in `SpeckARXWindowDifferentialCPModel` | MiniZinc and selected solver | Legacy-disabled window equals the exact baseline; a three-bit per-round window solves and independently decodes under Chuffed | [Exact versus n-window Speck](data/cp_arx_window_benchmark.json) |
| CP active-S-box/two-step search | `cp/mzn_models/mzn_xor_differential_number_of_active_sboxes_model.py`, `mzn_xor_differential_trail_search_fixing_number_of_active_sboxes_model.py` | Exact two-stage PRESENT activity then fixed-activity weight optimization | MiniZinc and selected solver | Chuffed proves two active S-boxes then weight four; decoded DDT trails recheck independently | [Activity](data/cp_active_sboxes_benchmark.json) and [fixed activity](data/cp_fixed_active_sboxes_benchmark.json); generic component coverage pending |
| CP XOR linear | `cp/mzn_models/mzn_xor_linear_model.py`, `components/*` | Local S-box model plus portable generic `WordLinearCPModel` | MiniZinc and selected solver | Exact ToySpeck bounded-weight witness decoded and independently rechecked under Chuffed | [Portable generic Word trails](data/cp_word_trail_benchmark.json) |
| CP truncated/impossible | `cp/mzn_models/mzn_*truncated*.py`, `mzn_*impossible*.py`, `components/*` | Generic deterministic-truncated Word graph assembly plus Speck semi-deterministic, Speck/Simon/wordwise/impossible CP slices | MiniZinc and selected solver | Paired-carry and look-ahead-window clauses inherit exhaustive SAT parity; reviewed trails solve under Chuffed with independent typed decoding | [Generic deterministic-truncated benchmark](data/cp_deterministic_truncated_benchmark.json) and [Speck semi-deterministic benchmark](data/cp_semi_deterministic_truncated_benchmark.json); remaining impossible variants pending |
| CP differential-linear | `cp/mzn_models/mzn_differential_linear_model.py`, `mzn_differential_linear_continuous_model.py`, `minizinc_utils/mzn_continuous_predicates.py` | Portable deterministic- and semi-deterministic-middle CP models plus fixed-input continuous Speck heuristic | MiniZinc; Chuffed for discrete models and Gecode float propagation in the release image | Discrete compositions decode independently; continuous numerical candidates are tolerance-checked against independent Python propagation and never carry proof status | [Deterministic middle](data/cp_differential_linear_benchmark.json), [semi-deterministic middle](data/cp_semi_differential_linear_benchmark.json), and [continuous heuristic](data/cp_continuous_speck_benchmark.json) |
| CP boomerang | `cp/mzn_models/mzn_boomerang_model_arx_optimized.py`, `minizinc_utils/mzn_bct_predicates.py` | Exact local S-box BCT and modular-add carry/borrow models plus generic modular-add top/switch/bottom composition | MiniZinc/Chuffed | Local feasibility matches all 4,096 three-bit switch tuples; the composed model namespaces two exact Word trails, links both switch boundaries, and independently decodes every part | [Local modular-add switch](data/cp_modadd_boomerang_benchmark.json) and [complete composed trail](data/cp_boomerang_trail_benchmark.json); automatic partitioning and S-box-switch assembly pending |
| CP ARX boomerang | `cp/mzn_models/mzn_boomerang_model_arx_optimized.py`, `minizinc_utils/mzn_bct_predicates.py` | `ModularAddBoomerangTrailCPModel` and local `SBoxBoomerangCPModel` | MiniZinc and selected solver | Generic modular-add composition covered; S-box-switch graph composition pending | [Complete composed trail](data/cp_boomerang_trail_benchmark.json) |
| MILP small-S-box convex hull/reduced inequalities | `milp/utils/generate_sbox_inequalities_for_trail_search.py`, `components/sbox_component.py` at `3aacc275` | One-hot `SBoxTransitionMILPModel` remains default; explicit full-hull, greedy, and minimum alternatives | cddlib 0.94m exact-GMP and GLPK 5.0 for offline generation; no runtime generator dependency; selected MILP solver | Complete for all 256 PRESENT input/output pairs under differential and signed-linear semantics for all three strategies; generated bundle is reproduced by the pinned toolchain | [Canonical GLPK Docker benchmark](data/sbox_milp_strategy_benchmark.json): ten runs of each recovered strategy and one-hot baseline |
| MILP large-S-box Espresso | `milp/utils/generate_inequalities_for_large_sboxes.py`, `components/sbox_component.py` at `3aacc275` | One-hot `SBoxTransitionMILPModel` remains default; explicit differential and signed-linear Espresso alternatives | Espresso 2.3 for offline generation only; no runtime Espresso dependency; selected MILP solver | Complete for all 65,536 AES input/output pairs under differential and signed-linear semantics | [Canonical GLPK Docker benchmark](data/aes_sbox_milp_strategy_benchmark.json): five runs of each Espresso strategy and one-hot baseline |
| MILP bitwise AND | `milp/utils/generate_inequalities_for_and_operation_2_input_bits.py`, `components/multi_input_non_linear_logical_operator_component.py` at `3aacc275` | Portable `BitwiseAndOneHotMILPModel`; explicit recovered differential and linear reduced-inequality alternatives | GLPK or another selected MILP solver; generation is dependency-free | Complete exhaustive one-bit support, weight, sign, and solver parity for portable and recovered formulations | [Canonical GLPK Docker benchmark](data/milp_bitwise_and_benchmark.json): ten comparable 32-bit runs per semantics and strategy |
| Generic MILP differential/linear | `milp/milp_models/milp_xor_differential_model.py`, `milp_xor_linear_model.py`, `components/*` | Portable generic differential, linear, and deterministic- or semi-deterministic-middle differential-linear models | GLPK or selected MILP solver; legacy specialized paths used Sage | Exact ToySpeck trails and both Speck32/64-3 compositions decode and independently recheck under GLPK | [Portable generic Word trails](data/milp_word_trail_benchmark.json), [deterministic composition](data/milp_differential_linear_benchmark.json), and [semi-deterministic composition](data/milp_semi_differential_linear_benchmark.json) |
| MILP activity/truncated/impossible | `milp/milp_models/milp_*active_sboxes*.py`, `milp_*truncated*.py`, `milp_*impossible*.py`, `milp/utils/*truncated*.py` | Exact PRESENT activity/weight optimization, generic wordwise branch-number bounds, deterministic/semi-deterministic truncated trails, generic Word impossible assembly, exact four-state middle selector, and truncated AND strategies | GLPK or selected MILP solver; legacy specialized paths used Sage | Activity optima and typed truncated/impossible witnesses decode and recheck under GLPK; the preserved reduced-AES middle fixture selects exactly one legacy-compatible contradiction | [Exact activity](data/milp_active_sboxes_benchmark.json), [fixed activity](data/milp_fixed_active_sboxes_benchmark.json), [wordwise activity](data/milp_wordwise_activity_benchmark.json), [impossible Speck](data/milp_impossible_trail_benchmark.json), [wordwise middle](data/milp_wordwise_impossible_benchmark.json), [deterministic-truncated](data/milp_deterministic_truncated_benchmark.json), [semi-deterministic](data/milp_semi_deterministic_truncated_benchmark.json), and [AND](data/milp_truncated_and_benchmark.json); whole-graph four-state propagation pending |
| MILP monomial queries | `milp/milp_models/Gurobi/monomial_prediction.py` | Portable graph reachability, degree maximization, fixed-cube feasibility, bounded exact cube-superpoly parity oracle, and optional bounded Gurobi optimal-solution pools; Gurobi remains non-default | GLPK or selected MILP solver for graph queries; exact subspace evaluation is dependency-free; optional licensed Gurobi for pools | One-round Simon degree-two witness and feasible/infeasible cubes decode under GLPK; exhaustive evaluation and a Boolean Möbius transform recover the exact reviewed cube coefficient and key-variable ANF; an API test double validates pool configuration and assignment checks | [Degree, cube, and exact parity queries](data/milp_monomial_queries_benchmark.json); scalable pool-to-polynomial projection/parity remains separate reviewed work |
| SAT differential/linear | `sat/sat_models/sat_xor_differential_model.py`, `sat_xor_linear_model.py`, `sat/utils/n_window_heuristic_helper.py`, `components/*` | Exact local S-box and modular-add models, `WordDifferentialSATModel`, `WordLinearSATModel`, and opt-in `NWindowSATStrategy` | MiniSat, Kissat, or CryptoMiniSat; n-window generation is pure Python | Complete exhaustive local parity, four-bit n-window definition parity, exact toy-Speck differential/linear counts, and independently rechecked decoded trails | [Canonical SAT benchmark](data/sat_trail_assembly_benchmark.json) and [n-window comparison](data/sat_n_window_benchmark.json), each with ten runs under all three canonical SAT solvers |
| CryptoMiniSat native XOR | `sat/cms_models/*.py`, `components/*` at `3aacc275` | Typed mixed CNF/native-XOR container, functional graph lowering, differential, linear, and deterministic-truncated Word trail alternatives, ordinary-CNF expansion oracle, extended-DIMACS exporter, and public solver driver | CryptoMiniSat 5.11.15 for solving; generation and validation are dependency-free | Functional Speck-1/Simon-1 and complete toy-Speck differential, linear, and deterministic-truncated formulas expand exactly to ordinary CNF; native enumeration preserves differential/linear counts and truncated witnesses pass independent checks | [Functional](data/native_xor_formulation_benchmark.json), [differential/linear trail](data/native_xor_trail_benchmark.json), and [deterministic-truncated trail](data/native_xor_truncated_trail_benchmark.json) comparisons |
| SAT truncated/impossible | `sat/sat_models/sat_*truncated*.py`, `sat_bitwise_impossible_xor_differential_model.py`, `sat/utils/utils.py::incompatibility`, `components/*` at `3aacc275` | Typed semantics, reviewed CP slices, recovered local deterministic-truncated modular-add, modular-subtract, impossible-boundary, counter-based probabilistic modular-add, and generated semi-deterministic window relations, `WordDeterministicTruncatedSATModel` for forward/inverse ARX/structural Word graphs, transformed-graph `SpeckImpossibleSATModel`, and bounded portable and recovered-window Speck trail assembly | MiniSat, Kissat, or CryptoMiniSat | Exhaustive two-bit deterministic and probabilistic modular-add parity, pinned-hash recovery and exact clause-order checks for semi-deterministic windows 0–3, exhaustive modular-subtract parity, and exhaustive incompatibility indicators; whole-graph impossible and bounded portable/recovered-window Speck witnesses under all three solvers | [Deterministic-truncated](data/sat_truncated_trail_benchmark.json), [whole-graph impossible](data/sat_impossible_trail_benchmark.json), [probabilistic-truncated](data/sat_probabilistic_trail_benchmark.json), [local semi-deterministic](data/sat_semi_deterministic_modadd_benchmark.json), and [whole-graph semi-deterministic](data/sat_semi_deterministic_trail_benchmark.json) benchmarks |
| SAT differential-linear/paired input | `sat/sat_models/sat_differential_linear_model.py`, `sat_shared_difference_paired_input_*.py` | Recovered typed connectors, deterministic- and semi-deterministic-middle whole-graph assembly, shared-difference paired differential characteristics, and the paired-input differential-linear composition | MiniSat, Kissat, or CryptoMiniSat | Complete connector truth tables and independently decoded fixtures; the semi-deterministic and paired differential-linear formulas pass MiniSat/Kissat while the larger paired fixed-weight formula exceeds 30 seconds under CryptoMiniSat 5.11.15 | [Boundary](data/sat_differential_linear_boundary_benchmark.json), [whole-graph](data/sat_differential_linear_trail_benchmark.json), [semi-deterministic middle](data/sat_semi_deterministic_differential_linear_benchmark.json), [paired characteristic](data/sat_shared_difference_paired_benchmark.json), and [paired differential-linear](data/sat_shared_difference_paired_differential_linear_benchmark.json) comparisons |
| SMT differential/linear | `smt/smt_models/smt_xor_differential_model.py`, `smt_xor_linear_model.py`, `components/*` | Local and word-level v5 SMT models | Z3, Yices, or MathSAT driver | Generic Word formulas are byte-for-byte identical to the SAT Boolean formulas; fixed-weight differential and bounded-weight linear ToySpeck trails solve under Z3 and decode independently | [Canonical Z3 Docker benchmark](data/smt_word_trail_benchmark.json); legacy components outside the reviewed Word subset remain pending |
| SMT deterministic truncated | `smt/smt_models/smt_deterministic_truncated_xor_differential_model.py`, `components/*` | `ModularAddDeterministicTruncatedSMTModel` and `WordDeterministicTruncatedSMTModel` | Z3 4.8.12 in the canonical image; Boolean construction is dependency-free | Paired-carry clauses inherit exhaustive SAT parity; accepted/rejected local and ToySpeck graph fixtures pass under Z3 with independent typed decoding | [Canonical Z3 Docker benchmark](data/smt_deterministic_truncated_benchmark.json): ten runs of the same ToySpeck-2 fixture used by the SAT comparison |
| MILP monomial/division property | `milp/milp_models/Gurobi/monomial_prediction.py` | Portable monomial transition, PRESENT, and Boolean graph models | Gurobi; legacy code also imports Sage | Pending for shared capabilities | Pending |
| Algebraic polynomial construction | `algebraic/algebraic_model.py`, `algebraic/constraints.py` | Dependency-free polynomial representations and exporters | Sage for the legacy model | Pending for analyses beyond construction | Pending |

Paths in this matrix are relative to `claasp/cipher_modules/models/` unless
they start with `components/`, which is relative to `claasp/`.

## Recovery and benchmark order

1. **S-box MILP strategy PRs.** The first slice recovers four-bit full-hull,
   greedy, and minimum-cardinality inequality strategies alongside the portable
   one-hot baseline for differential and signed-linear propagation. The
   immediately following slice recovers large-S-box Espresso strategies and
   adds eight-bit parity and benchmark coverage.
2. **SAT/CMS and modular-add strategy PRs.** The first slice restores explicit
   local S-box and modular-add XOR-differential and XOR-linear SAT models with
   exhaustive small-domain parity. The second slice restores typed native-XOR
   functional output and its extended-DIMACS exporter. Following slices recover
   generic trail assembly and the separately switchable n-window heuristic,
   then add solver-time benchmarks when CryptoMiniSat is available.
3. **Linear-layer and truncated-model PRs.** Recover bitwise/wordwise,
   deterministic/semi-deterministic, branch-number, undisturbed-bit, and
   impossible formulations across MILP, SAT, SMT, and CP in component-sized
   slices.
4. **Differential-linear and boomerang PRs.** Review the unmerged branches,
   recover exact models separately from continuous heuristics, and verify every
   switch construction before attaching literature provenance.
5. **Monomial/division-property PRs.** Preserve the legacy Gurobi-only degree,
   superpoly, and key-coefficient searches as optional strategies while keeping
   the portable monomial models as the baseline.

No recovery PR may switch a default. For each strategy, compare the same
primitive, round count, boundary conditions, objective, solver/version,
settings, hardware, and timeout. Record construction time, variables,
clauses/constraints, solve time, peak memory, result validity, and
optimality/timeout status. The first benchmark set should include at least a
4-bit S-box, an 8-bit S-box, PRESENT, an AES-like S-box/linear-layer workload,
and a small Speck instance. Larger cipher workloads follow only after exhaustive
small-instance parity succeeds.

## Acceptance gate for each recovered strategy

- Verify source license, authorship, and the exact legacy commit before copying
  code, tables, or generated inequalities.
- Give the formulation an explicit strategy name; do not overload a portable
  model name with solver-specific behavior.
- Test the accepted relation exhaustively where its domain is small and against
  an independent semantic oracle elsewhere.
- Preserve sign, probability/correlation scale, truncation alphabet, bit order,
  boundary meaning, and optimization objective explicitly.
- Keep optional Sage, Gurobi, Espresso, MiniZinc, and solver integrations out of
  dependency-free core imports.
- Add a row to the benchmark matrix. “Better” requires reproducible evidence;
  smaller formulation size alone is not sufficient.
- Retain the portable baseline and make any later default-policy change in a
  separate reviewed PR.
