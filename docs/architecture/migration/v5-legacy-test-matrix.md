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

## Analysis and tooling inventory

These discovered suites receive row-level entries when their M10 increment
starts:

- SAT and CryptoMiniSat cipher, differential, linear, truncated, impossible,
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
