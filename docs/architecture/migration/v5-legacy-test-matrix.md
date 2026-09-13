# CLAASP v5 legacy regression matrix

This living matrix maps legacy behavior to v5 semantic tests. “Ported” runs
natively against `claasp_next`; “superseded” tests the same requirement with a
new representation; “deferred” names the milestone that must resolve it.
Internal identifiers are not compatibility requirements unless an external
format relies on them.

## Reference ciphers

| Legacy test | Semantic assertions and provenance | Disposition | v5 coverage |
| --- | --- | --- | --- |
| `aes_block_cipher_test.py::test_aes128_block_cipher` | Four AES-128 vectors from NIST SP 800-38A F.1.1; sizes; 10 algorithmic rounds; `Nk=4`, `Nr=10` | Ported | `test_legacy_cipher_parity.py` AES vector/configuration tests; v5 additionally models initial AddRoundKey as graph round zero |
| `aes_block_cipher_test.py::test_aes192_block_cipher` | Four AES-192 vectors from NIST SP 800-38A F.1.3; sizes; 12 rounds; `Nk=6`, `Nr=12` | Ported | Same parameterized tests |
| `aes_block_cipher_test.py::test_aes256_block_cipher` | Four AES-256 vectors from NIST SP 800-38A F.1.5; sizes; 14 rounds; `Nk=8`, `Nr=14` | Ported | Same parameterized tests |
| AES configuration-list and invalid-key tests | Three FIPS configurations; reject 512-bit key | Ported | Configuration and invalid-size tests; catalogue retained |
| `present_block_cipher_test.py::test_present_block_cipher` | Default/reduced rounds; family; exact 80-/128-bit vectors; scalar/vectorized agreement | Ported | PRESENT parity tests, designers' vectors, and batch agreement |
| Same PRESENT test | Serialized cipher IDs and exact component IDs | Deferred to M10.8 | Component kinds and round placement tested without freezing legacy IDs |
| Same PRESENT test | `type == 'block_cipher'` | Superseded | Typed `Cipher`, keyed inputs, and fixed output type |
| Same PRESENT test | Embedded-reference comparison | Ported deterministically | Independent integer transcription checked for both key sizes and multiple reduced-round inputs |
| `speck_block_cipher_test.py::test_speck_block_cipher` | Default/reduced configuration; family; exact Speck32/64 and Speck64/96 vectors; scalar/vectorized agreement | Ported | Speck parity and batch-agreement tests |
| Same Speck test | Serialized cipher IDs and exact component IDs | Deferred to M10.8 | First-round rotation semantics tested without freezing legacy IDs |
| Same Speck test | `type == 'block_cipher'` | Superseded | Typed `Cipher`, block/key/output sizes, and word domain |

Legacy paths above are under `tests/unit/ciphers/block_ciphers/`; v5 paths are
under `next/tests/unit/`.

## SAT cipher evaluation and recovery

| Legacy test | Semantic assertions and provenance | Disposition | v5 coverage |
| --- | --- | --- | --- |
| `sat/sat_models/sat_cipher_model_test.py::test_find_missing_bits` | MiniSat completes fully fixed Speck32/64 inputs to the official 22-round ciphertext `0xa86842f2`; legacy CLAASP regression backed by the Speck designers' vector | Ported semantically | Scalar/CNF witness parity covers the full graph; `test_word_level_sat_recovers_a_reduced_speck_key` exercises actual MiniSat inversion and independently re-evaluates the recovered key |
| `sat/cms_models/cms_cipher_model_test.py::test_find_missing_bits` | Same Speck result through CryptoMiniSat's XOR-aware model | Superseded for cipher semantics | Solver-independent CNF plus the MiniSat adapter reproduces the semantic requirement; a future CryptoMiniSat adapter may preserve native XOR performance without changing the graph API |
| `sat/sat_model_test.py::test_solve` | Unconstrained TEA/Simon models are satisfiable and expose internal assignments | Deferred | TEA and Simon have not yet been migrated to the v5 typed graph |
| `sat/sat_model_test.py::test_solver_names` | Runtime catalogue of bundled and external solver metadata | Superseded | Explicit lightweight adapters replace Sage's solver registry; backend and executable are recorded in every `AnalysisResult` |
| `sat/sat_model_test.py::test_fix_variables_value_constraints` (cipher-model portions) | Equal/not-equal constraints, including graph-to-graph values, and contradictory constraints becoming UNSAT | Ported | `test_analysis_constraints.py` exhaustively verifies graph-level `FixedValue`, `Equal`, and `NotEqual`; backend variable names are deliberately hidden |
| Legacy repeated-solution helpers | Enumerate models while excluding earlier assignments | Ported | `test_solution_enumeration_blocks_projected_values_and_honors_limit` verifies projection-based blocking, exhaustion, and limits |

The v5 recovery integration pins the external CI package version for MiniSat
and validates a returned key by evaluating the cipher, rather than trusting
SAT status alone. The reduced-round key is a feasibility witness, not a claim
of uniqueness or an optimum.

## Differential and linear trails

| Legacy test | Semantic assertions and provenance | Disposition | v5 coverage |
| --- | --- | --- | --- |
| SAT/SMT `*_xor_differential_model_test.py` Speck32/64 five-round optimum | Minimum XOR-differential weight 9, repeated across legacy SAT and SMT backends | Scheduled for M10.3c | M10.3a first defines backend-neutral exact transition and trail weights; the eventual solver witness must be independently checked |
| SAT/SMT `*_xor_linear_model_test.py` reduced Speck fixtures | Four-round optimum weight 3 and three-round feasible weight 7 | Scheduled for M10.3c | Same shared semantics and independent-check requirement |
| S-box differential/linear component behavior used throughout legacy trail models | DDT probability and signed LAT correlation derived exhaustively from the lookup table | Ported in M10.3a | `test_trail_semantics.py` checks exact PRESENT transitions, impossible transitions, signs, weights, and trail aggregation |
| `milp/milp_models/milp_xor_differential_model_test.py::test_find_lowest_weight_xor_differential_trail` PRESENT case | Two-round PRESENT minimum XOR-differential weight 4; legacy CLAASP regression | Ported in M10.3b | `test_spn_trail_search.py` reproduces weight 4, meets an explicit lower bound, and independently checks every S-box transition and permutation boundary |
| Same legacy MILP test, Speck32/64 case | Two-round Speck minimum XOR-differential weight 1, both with and without the legacy window heuristic | Ported in M10.3c | `test_arx_trail_search.py` reproduces the weight-1 optimum from input difference `0x00400000`; exact carry-pair counting and a separate ARX wiring checker validate the witness |
| `sat_bitwise_deterministic_truncated_xor_differential_model_test.py::test_find_one_bitwise_deterministic_truncated_xor_differential_trail` first Speck case | Fixed 32-bit input pattern propagates after round one to `????100000000000????100000000011` | Ported in M10.3d | `test_truncated_differences.py` reproduces the exact string with paired-carry reachability rather than encoded SAT variables |
| Bitwise impossible model component contradictions | An exact input/output difference pair with no component transition proves local incompatibility | Initial slice ported in M10.3d | The graph facade exhaustively refutes PRESENT S-box transition `1 -> 1` and accepts `1 -> 3`; multi-round Simon/Ascon fixtures remain deferred until those primitives migrate |
| Disabled PRESENT case in `milp_xor_linear_model_test.py::test_find_lowest_weight_xor_linear_trail` | Three-round PRESENT input mask `0x0d00000000000000` was preserved with expected weight 4 but disabled in legacy | Restored semantically in M10.3e | `test_spn_trail_search.py` finds a weight-4 characteristic, retains LAT signs, and independently checks every transition and permutation boundary; it does not depend on the disabled input-mask hint |
| SAT/CMS/MILP `*_xor_linear_model_test.py::test_find_lowest_weight_xor_linear_trail` Speck case | Four-round Speck32/64 minimum weight 3, repeated across legacy backends | Ported in M10.3f | `test_arx_trail_search.py` restores masks `0x40b010c1 -> 0x2c102010`, exact per-addition weights `2+0+0+1`, signed correlations, and independent backward wiring checks; the fixture was regenerated with legacy `SatXorLinearModel` and MiniSat 2.2.1 |

## SMT models

| Legacy test | Semantic assertions and provenance | Disposition | v5 coverage |
| --- | --- | --- | --- |
| `smt/smt_models/smt_cipher_model_test.py::test_find_missing_bits` | Z3 completes fixed official Speck32/64 plaintext/key to `0xa86842f2` | Ported in M10.4a | `test_z3_integration.py` solves the full 22-round typed graph through SMT-LIB and independently evaluates the ciphertext |
| Legacy SMT solver syntax and internal variable strings | Exact generated assertions and backend identifier | Superseded | Stable graph-derived names, portable `SMTFormula`, deterministic SMT-LIB, and explicit `Z3Solver`; representation tests avoid freezing incidental legacy syntax |
| SMT XOR-differential/linear S-box transition constraints | Feasible DDT/LAT entries are accepted; impossible entries make a fixed model UNSAT | Ported in M10.4b1 | Exhaustive unit comparison covers the entire PRESENT DDT and selected signed LAT projection; real Z3 proves `1 -> 3` SAT and `1 -> 1` UNSAT |
| Cross-backend two-round PRESENT differential optimum | Legacy MILP establishes minimum weight 4; shared trail semantics must agree across encodings | Ported to SMT in M10.4b2 | Real Z3 proves the complete weighted SMT model UNSAT at bound 3 and SAT at bound 4; the extracted 32-transition trail is independently checked |

## Analysis and tooling inventory

These discovered suites receive row-level entries when their M10 increment
starts:

- SAT and CryptoMiniSat differential, linear, truncated, impossible,
  differential-linear, and paired-input models under
  `tests/unit/cipher_modules/models/sat/` and `tests/benchmark/`.
- SMT cipher, XOR-differential, and XOR-linear models under
  `tests/unit/cipher_modules/models/smt/`.
- MILP cipher, trail, truncated, impossible, branch-number, active-S-box, and
  monomial-prediction models under `tests/unit/cipher_modules/models/milp/`.
- CP/MiniZinc cipher, ARX-optimized, trail, truncated, impossible, boomerang,
  and differential-linear models under `tests/unit/cipher_modules/models/cp/`.
- Avalanche behavior in `tests/unit/cipher_modules/avalanche_tests_test.py`.
- Graph, serialization, code generation, diagrams, transformations, and
  compilers, classified during M10.8.

Each cryptanalytic row must say whether its expected result is an optimum,
feasibility witness, or bound; record publication or legacy origin and solver
version; and name the independent semantic checker used by v5.
