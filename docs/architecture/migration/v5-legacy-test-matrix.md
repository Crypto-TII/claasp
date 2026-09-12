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
