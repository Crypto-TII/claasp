# CLAASP v5 legacy regression matrix

This living matrix maps legacy behavior to v5 semantic tests. “Ported” runs
natively against `claasp_next`; “superseded” tests the same requirement with a
new representation; “deferred” names the milestone that must resolve it.
Internal identifiers are not compatibility requirements unless an external
format relies on them.

Legacy paths and class names in this document are evidence locators, not v5
taxonomy decisions. The M10.7 machine-readable inventory records each
catalogue entry's official name, fixed-length category, proposed v5
module/class names, and any higher-level hash, MAC, or stream construction from
which its primitive is extracted. M10.9a landed the generic graph abstraction
and catalogue package rename (``Cipher``/``ciphers`` to ``Primitive``/
``primitives``, plus official catalogue class names such as ``AES`` and
``Speck``); M10.9b–M10.9d apply the remaining taxonomy decisions on top of
that renamed v5 API. Legacy CLAASP 4 paths and class names below (for example
`claasp.cipher_modules...` or `SpeckBlockCipher`) remain correct as historical
citations into the legacy oracle and are not part of the v5 API surface.

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
| `stream_ciphers/trivium_stream_cipher_test.py::test_trivium_stream_cipher_test_vector` | 256 keystream bits `0xdf07fd64…854d97b3` for the all-zero 80-bit key and IV after 1152 initialization clocks; unlike the Gurobi suite this legacy test executes, so it is a genuine oracle | Ported | `test_trivium.py` reproduces the value on the typed graph and adds five published eSTREAM 80/80 vectors, scalar/batch parity, the 288-bit state boundary, and reduced instances checked against an independently written transcription of the specification pseudocode |
| Same Trivium test | `type == 'stream_cipher'` and a keystream-length parameter | Superseded | `stream_ciphers` is not a v5 category. The fixed-length primitive extracted from the construction is the keyed map from the public 80-bit IV to the first `keystream_bit_size` keystream bits, classified as `block_functions` in agreement with the M10.7 inventory entry for the legacy module; M10.9b confirms it against the final catalogue invariants |

Legacy paths above are under `tests/unit/ciphers/`; v5 paths are under
`next/tests/unit/`.

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
| SAT/SMT `*_xor_differential_model_test.py` Speck32/64 five-round optimum | Minimum XOR-differential weight 9, repeated across legacy SAT and SMT backends | Ported in M10.6d2 and completed in M10.8d | Chuffed proves bound 8 UNSAT and bound 9 SAT through shared CP semantics; the five-addition witness is independently recounted. Exhaustive bounded enumeration terminates normally and preserves the SMT suite's exact count of 28 distinct trails with weights 9 through 10 |
| SAT/SMT `*_xor_linear_model_test.py` reduced Speck fixtures | Four-round optimum weight 3, three-round optimum weight 1 and feasible weight 7, plus eight Speck8/16 trails with weight at most 2 | Partially ported in M10.3f and M10.8d | The four-round optimum and exact masks are independently checked. Graph-wired Z3 composition preserves three-round optimum 1 and feasible weight 7. Only toy Speck8/16 nonzero-key-mask enumeration remains prerequisite-gated rather than treating backend-specific result dictionaries as evidence |
| S-box differential/linear component behavior used throughout legacy trail models | DDT probability and signed LAT correlation derived exhaustively from the lookup table | Ported in M10.3a | `test_trail_semantics.py` checks exact PRESENT transitions, impossible transitions, signs, weights, and trail aggregation |
| `milp/milp_models/milp_xor_differential_model_test.py::test_find_lowest_weight_xor_differential_trail` PRESENT case | Two-round PRESENT minimum XOR-differential weight 4; legacy CLAASP regression | Ported in M10.3b | `test_spn_trail_search.py` reproduces weight 4, meets an explicit lower bound, and independently checks every S-box transition and permutation boundary |
| Same legacy MILP test, Speck32/64 case | Two-round Speck minimum XOR-differential weight 1, both with and without the legacy window heuristic | Ported in M10.3c | `test_arx_trail_search.py` reproduces the weight-1 optimum from input difference `0x00400000`; exact carry-pair counting and a separate ARX wiring checker validate the witness |
| `sat_bitwise_deterministic_truncated_xor_differential_model_test.py::test_find_one_bitwise_deterministic_truncated_xor_differential_trail` first Speck case | Fixed 32-bit input pattern propagates after round one to `????100000000000????100000000011` | Ported in M10.3d | `test_truncated_differences.py` reproduces the exact string with paired-carry reachability rather than encoded SAT variables |
| Bitwise impossible model component contradictions | An exact input/output difference pair with no component transition proves local incompatibility | Initial slice ported in M10.3d | The graph facade exhaustively refutes PRESENT S-box transition `1 -> 1` and accepts `1 -> 3`; multi-round Simon/Ascon fixtures remain deferred until those primitives migrate |
| Disabled PRESENT case in `milp_xor_linear_model_test.py::test_find_lowest_weight_xor_linear_trail` | Three-round PRESENT input mask `0x0d00000000000000` was preserved with expected weight 4 but disabled in legacy | Restored semantically in M10.3e | `test_spn_trail_search.py` finds a weight-4 characteristic, retains LAT signs, and independently checks every transition and permutation boundary; it does not depend on the disabled input-mask hint |
| SAT/CMS/MILP `*_xor_linear_model_test.py::test_find_lowest_weight_xor_linear_trail` Speck case | Four-round Speck32/64 minimum weight 3, repeated across legacy backends | Ported in M10.3f | `test_arx_trail_search.py` restores masks `0x40b010c1 -> 0x2c102010`, exact per-addition weights `2+0+0+1`, signed correlations, and independent backward wiring checks; the fixture was regenerated with legacy `SatXorLinearModel` and MiniSat 2.2.1 |

## CryptoMiniSat model subclasses

All four non-marker CMS source modules and all four test modules are explicitly
classified in the machine inventory. Backend-specific subclasses are superseded
by shared representations and separate drivers; no CryptoMiniSat execution or
complete component catalogue is claimed by this architectural replacement.

| Legacy test under `sat/cms_models/` | Preserved assertion | Disposition | v5 evidence |
| --- | --- | --- | --- |
| `cms_cipher_model_test.py` | Full Speck32/64-22 plaintext/key completes to `0xA86842F2` | Ported in M10.8d | Existing `test_z3_integration.py` solves the complete graph and checks concrete evaluation |
| `cms_xor_linear_model_test.py` | Speck32/64-4 optimum weight 3 | Ported in M10.8d | `test_speck_trail_enumeration.py` proves bound 2 UNSAT and bound 3 SAT, independently recounting correlations and mask wiring |
| `cms_xor_differential_model_test.py` | Supported dispatch produces constraints and variables; weight configuration affects construction | Superseded in M10.8d | `test_cms_inventory_parity.py` checks all 22 addition relations are present, immutable declarations/wiring are preserved, and the requested bound is explicit rather than requiring more mutable strings |
| `cms_deterministic_truncated_xor_differential_model_test.py` | Construction smoke test with no assertion | Superseded in M10.8d | `test_truncated_differences.py` checks sound modular-add output bits and fixed Speck truncated propagation; the legacy CMS class itself delegates to ordinary SAT and warns it has no CMS advantage |

## SMT models

| Legacy test | Semantic assertions and provenance | Disposition | v5 coverage |
| --- | --- | --- | --- |
| `smt/smt_models/smt_cipher_model_test.py::test_find_missing_bits` | Z3 completes fixed official Speck32/64 plaintext/key to `0xa86842f2` | Ported in M10.4a | `test_z3_integration.py` solves the full 22-round typed graph through SMT-LIB and independently evaluates the ciphertext |
| Legacy SMT solver syntax and internal variable strings | Exact generated assertions and backend identifier | Superseded | Stable graph-derived names, portable `SMTFormula`, deterministic SMT-LIB, and explicit `Z3Solver`; representation tests avoid freezing incidental legacy syntax |
| SMT XOR-differential/linear S-box transition constraints | Feasible DDT/LAT entries are accepted; impossible entries make a fixed model UNSAT | Ported in M10.4b1 | Exhaustive unit comparison covers the entire PRESENT DDT and selected signed LAT projection; real Z3 proves `1 -> 3` SAT and `1 -> 1` UNSAT |
| Cross-backend two-round PRESENT differential optimum | Legacy MILP establishes minimum weight 4; shared trail semantics must agree across encodings | Ported to SMT in M10.4b2 | Real Z3 proves the complete weighted SMT model UNSAT at bound 3 and SAT at bound 4; the extracted 32-transition trail is independently checked |
| Cross-backend three-round PRESENT linear optimum | Preserved legacy MILP fixture records weight 4; shared signed LAT semantics must agree across encodings | Ported to SMT in M10.4b3a | Real Z3 proves UNSAT at bound 3 and SAT at bound 4; the extracted 48-transition trail retains signs and is independently checked across all layers |
| SAT/CMS/MILP four-round Speck32/64 linear optimum | Legacy optimum weight 3, masks `0x40b010c1 -> 0x2c102010`, and four modular-add transitions | Ported to SMT in M10.4b3b | Real Z3 validates the exact modular-add relation for all four restored transitions, weights `2+0+0+1`, and signs `+,+,+,-`; shared Walsh semantics independently checks each result. The reference was regenerated with legacy MiniSat 2.2.1 |
| `smt_model_test.py` generated assertion strings and solver catalogue | Backend-shaped fixed-value syntax, unsupported base-method exception, and runtime solver metadata | Superseded in M10.8d | Shared `FixedValue` constraints, immutable `SMTFormula`/SMT-LIB serialization, and explicit `Z3Solver` provenance replace mutable model internals and global registries |
| `smt_xor_differential_model_test.py::test_find_all_xor_differential_trails_with_weight_at_most` | Exactly 28 Speck32/64-5 trails at weights 9 through 10 | Ported in M10.8d | `MiniZincSolver.solve_all` accepts the count as complete only after Chuffed's exhaustive terminal marker; all 28 assignments decode through independent paired-carry semantics and have distinct input/output boundaries |
| Reduced fixtures in `smt_xor_linear_model_test.py` | Speck32/64-3 optimum 1 and fixed-weight 7; eight Speck8/16-4 trails at weight at most 2 | Partially ported in M10.8d | Graph-wired `SpeckLinearSMTModel` and Z3 prove three-round weight 0 UNSAT / weight 1 SAT and retain feasible weight 7; decoding independently recounts correlations and wiring. The eight-trail case alone requires M10.9b toy classification, M10.9d nonstandard Speck8/16, and M10.8d nonzero key-mask composition, not just bounded enumeration |

## MILP models

| Legacy test | Semantic assertions and provenance | Disposition | v5 coverage |
| --- | --- | --- | --- |
| `milp_xor_differential_model_test.py` two-round PRESENT optimum | Complete cipher minimum XOR-differential weight 4 | Ported to portable MILP in M10.5b | The exact DDT selector model covers all 32 graph S-boxes and permutation wiring; GLPK proves optimum 4 and the shared checker validates every decoded transition and boundary |
| `milp_xor_linear_model_test.py` four-round Speck32/64 optimum | Minimum weight 3 and exact modular-add mask transitions, shared with SAT/CMS | Component relation ported in M10.5c | GLPK validates all four restored transitions with the exact parity/support model; weights `2+0+0+1` and signs `+,+,+,-` are recomputed by shared Walsh semantics |
| Gurobi `monomial_prediction_test.py` S-box ANF/transition behavior | Exact output ANFs and 3SDP-woU monomial transitions derived from lookup tables; legacy suite is skipped behind Sage/Gurobi | Portable component baseline in M10.8a | Dependency-free Möbius ANFs reproduce every PRESENT S-box value; symbolic cube coefficients preserve GF(2) parity; exact transition tables compile to portable MILP and real GLPK accepts/rejects fixed possible/impossible pairs |
| Gurobi `monomial_prediction_test.py` Trivium cases: the 13-clock ANF in `test_find_anf_of_specific_output_bit`, `test_find_superpoly_trivium_200`, `test_find_tight_upper_bound_degree_via_parity_of_superpoly_of_specific_output_bit_trivium_200`, `test_check_correctness_of_partial_anf_or_superpoly_trivium_200`, `test_find_upper_bound_degree_trivium_508`, `test_find_tight_upper_bound_degree_via_parity_trivium_508`, `test_find_partial_anf_at_cube_trivium_590` | Reduced-Trivium keystream-bit ANF, single-variable cube superpoly, and IV-degree bounds tightened by monomial parity. Every one of these tests carries `@pytest.mark.skip(reason="Requires Gurobi license")` and has therefore never executed in any legacy CI run, so its literal expectations are unverified claims and not oracle values | Requirement ported in M10.8c3c with newly derived, independently checked fixtures | `next/src/claasp_next/ciphers/block_functions/trivium.py` extracts the fixed-length `block_functions` primitive from the legacy stream-cipher construction, with `number_of_initialization_clocks` and `keystream_bit_size` as free parameters. `test_trivium_algebra.py` establishes the exact 13-clock ANF `i9 + i24 + k0 + k27`, the exact 200-clock superpoly `k39 + k40*k41 + k66` of cube `i53` with cube degree 2, the exact 200-clock ANF (degree 3, 58 monomials, IV degree 3), and the sound-but-loose structural IV bound 4; `test_glpk_trivium_monomials.py` proves the 160- and 200-clock parity enumerations terminate in UNSAT and recover exactly the four top IV monomials of the exact ANF. Every claim is re-checked by exhaustive concrete cube sums or by exact ANF expansion, which share no code with the solver path. The 13-clock ANF and the 200-clock superpoly/degree agree with the legacy literals, which are thereby confirmed rather than assumed; the 508- and 590-clock cases exceed the fast-suite budget and stay open under M10.8d |
| Gurobi `monomial_prediction_test.py` `test_is_cube_monomial_feasible_at_specific_output_bit_over_cube_keyless_ublock_6`, `test_find_coefficient_of_cube_by_divide_and_conquer_gaston`, `test_find_superpoly_by_divide_and_conquer_speck` | uBlock-128 keyless 56-dimensional cube feasibility, Gaston-3 divide-and-conquer cube coefficient 1, and a Speck-6 divide-and-conquer superpoly over per-round key variables; all three are skipped behind a Gurobi license and unverified | Deferred | No typed uBlock or Gaston primitive exists in `next/src/claasp_next/primitives`, and their cryptanalytic fixtures cannot be restated without one, as M10.8c3c anticipated. The divide-and-conquer decomposition is additionally an unmigrated middle-round composition method rather than a fixture, so the Speck case is deferred with them even though typed Speck exists. M10.9d supplies the primitives and M10.8d owns the composition method; no expected value is transcribed in the meantime |

## Algebraic models

| Legacy test | Semantic assertions and provenance | Disposition | v5 coverage |
| --- | --- | --- | --- |
| `algebraic/constraints_test.py::test_equality_polynomials` | A vector equality is represented by one zero polynomial per paired bit; unequal vector lengths are rejected | Superseded in M10.8d | `equality_polynomials` uses the dependency-free square-free Boolean polynomial representation, with exhaustive three-bit equality coverage |
| `algebraic/constraints_test.py::test_mod_addition_polynomials` | Exact little-endian ripple-addition equations, with either explicit carries or carries eliminated into output ANFs | Ported in M10.8d | `modular_addition_polynomials` preserves the quadratic carry recurrence and exhaustively proves the eliminated four-bit equations equivalent to addition modulo 16 |
| `algebraic/constraints_test.py::test_mod_subtraction_polynomials` | Exact little-endian ripple-subtraction equations, with either explicit borrows or borrows eliminated into output ANFs | Ported in M10.8d | `modular_subtraction_polynomials` preserves the legacy borrow recurrence and exhaustively proves the eliminated four-bit equations equivalent to subtraction modulo 16 |
| `algebraic_model_test.py` connection, ring, variable, and polynomial-system tests | Sage Boolean-ring construction, legacy wire-variable names, and exact equation/variable counts for one-round `FancyBlockCipher` | Superseded in M10.8d | Typed polynomial lowering retains component provenance and structural statistics; exact Boolean symbolic evaluation and prime-field witnesses are independently checked against graph execution. Incidental legacy names and counts are not serialized v5 contracts |
| `AlgebraicModel.is_algebraically_secure` | Reports a primitive secure whenever a Gröbner-basis computation exceeds a caller-provided timeout | Removed in M10.8d | A timeout is not cryptanalytic evidence. v5 algebra drivers report status, backend, version, runtime, and diagnostics; no Boolean security conclusion is inferred from resource exhaustion |
| `boolean_polynomial_ring.py::is_boolean_polynomial_ring` | Identifies Sage's concrete Boolean polynomial ring type | Superseded in M10.8d | `BooleanPolynomial` directly provides normalized square-free GF(2) arithmetic and requires neither Sage nor a runtime ring-type predicate |

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
- Cipher inversion in `claasp/cipher_modules/inverse_cipher.py` and its direct
  and cipher-level round-trip regressions.
- Component analysis in `claasp/cipher_modules/component_analysis_tests.py`,
  including Sage-backed S-box, Boolean-polynomial, matrix, branch-number, and
  plotting behavior.
- Dataset generators plus NIST STS and Dieharder wrappers/parsers under
  `claasp/cipher_modules/statistical_tests/`, including bundled parser/KAT
  fixtures and benchmark coverage.
- Black-box and differential neural distinguishers in
  `claasp/cipher_modules/neural_network_tests.py`; TensorFlow/Keras behavior is
  optional experimental evidence, while dataset/label contracts belong in
  baseline coverage.
- Gurobi monomial prediction in
  `claasp/cipher_modules/models/milp/milp_models/Gurobi/monomial_prediction.py`,
  including ANF, degree-bound, cube/superpoly, parity, and S-box monomial
  transition capabilities. The semantics require an open-source baseline;
  licensed Gurobi remains optional.
- Reports and result presentation, including the legacy `Report` entry points
  and their serialization/plotting dependencies.
- Graph, serialization, code generation, diagrams, transformations, and
  compilers, classified during M10.10 and M10.14–M10.15.

The diagram milestone is complete in M10.5d5: graph structure, rounds,
logical-unit selections, and concrete annotations are covered through one
backend-neutral IR with routed box-and-connector ASCII art, TikZ serialization,
and an externally tested LaTeX driver. ASCII routes retain input order, source
IDs, and selected positions; the same execution or cryptanalytic annotation is
rendered without backend-specific adaptation. The remaining M10.8 inventory
classifies historical semantic diagram fixtures independently of this renderer.

Each cryptanalytic row must say whether its expected result is an optimum,
feasibility witness, or bound; record publication or legacy origin and solver
version; and name the independent semantic checker used by v5.

M10.12b–c supersede the legacy eager NumPy dataset containers with lazy,
re-iterable correlation, zero-IV CBC, low-density, and high-density streams.
The v5 stream format is fixed-width raw output bytes with explicit MSB-first,
big-endian, sample-major/block-major conventions; its stable JSON manifest
records seed, construction parameters, primitive realization, and SHA-256.
M10.12d ports the dependency-free report boundary. The NIST summary parser is
regressed against every one of the 188 rows in all five committed
``finalAnalysisReport.txt`` reference artifacts, retaining repeated subtests,
histogram bins, undefined values, proportions, and failure markers. The
Dieharder parser preserves its legacy row schema and aggregates, but no legacy
test asserted a scientific Dieharder result and no output fixture was
committed; its synthetic parser fixture is therefore new structural evidence.
Empty Dieharder output now raises an error instead of fabricating an
``unavailable`` failure; plotting/report generation belongs to M10.14.
M10.12e1 ports the exact legacy Dieharder ``-g 201 -f INPUT -a`` and selected
``-d TEST`` invocation semantics through an isolated, shell-free driver. Its
result adds the stream SHA-256, tool version, stable command, runtime, and
captured diagnostics. A bounded dedicated CI job checks a real executable;
because the legacy tests contained no assertions or committed output, this is
adapter compatibility rather than preservation of a fixed p-value claim.
NIST STS process integration is now delivered as well: unlike Dieharder,
the patched, non-interactive ``assess`` build under ``required_dependencies/``
never prints its report to stdout, so ``NistStsDriver`` locates and reads the
fixed ``experiments/AlgorithmTesting/finalAnalysisReport.txt`` report file it
(re)writes under its compile-time-constant working directory immediately
after each run, serializes invocations against that shared path with an
in-process lock plus a best-effort cross-process file lock, and requires the
report's modification time to have advanced rather than trusting ``assess``'s
own inverted exit-code convention. A dedicated CI job builds the patched tool
from source exactly as ``docker/Dockerfile`` does and exercises one bounded
smoke run through the real executable.

M10.13 supersedes ``claasp/cipher_modules/neural_network_tests.py``'s
``round_output``/``round_key_output``/arbitrary-``component_ids`` projection
behavior -- which matched substrings of each legacy component's
free-text `description` -- with a typed equivalent: `component_output_dataset`
and `xor_differential_component_dataset` read the requested value directly
out of the primitive's `ExecutionTrace` (`Cipher.evaluate_with_trace`), and
`round_component_ids` selects every component id CLAASP added within one
round so passing it as `component_ids` reproduces the legacy round/round-key
projection without requiring the graph to declare an explicit concatenated
intermediate-output component. Dataset/label contracts (which component or
round is projected, and the resulting feature/label shape) are dependency-free
baseline coverage; no legacy test asserted a specific trained accuracy for
these projections, so only shape and value equality against direct trace
inspection are preserved, not a numeric fixture. The optional ML driver
disposition mirrors Dieharder's: legacy trained with TensorFlow/Keras
(`docker/Dockerfile` pins `tensorflow==2.13.0`); v5 instead ships
`claasp_next.drivers.neural.SklearnMLPDriver`, a `scikit-learn`-backed
`NeuralTrainingDriver` chosen over TensorFlow/Keras to keep the optional `ml`
extra and its dedicated `neural-ml-execution` CI job light and fast. Nothing
in `claasp_next` imports scikit-learn (or any ML framework) outside that
driver's `train` method, and no test asserts an exact accuracy value -- only
a documented threshold on a small, real reduced-round Speck32/64 differential
distinguisher, per M10.13's tolerance/threshold-based evidence requirement.

## CP models

| Legacy test | Semantic assertions and provenance | Disposition | v5 coverage |
| --- | --- | --- | --- |
| `mzn_model_test.py::test_assemble_model_orders_variables_constraints_outputs` | MiniZinc language sections are emitted in deterministic valid order | Superseded in M10.6a | Immutable `MiniZincModel.source()` covers includes, declarations, constraints, solve item, and outputs without mutable model internals |
| Legacy MiniZinc wrapper solve/status parsing | A real CP solver returns named values and distinguishes satisfiable from unsatisfiable models | Ported in M10.6a | Dedicated CLI integration uses JSON output, validates SAT projection and UNSAT status, and requires no MiniZinc Python package |
| `mzn_cipher_model_test.py::test_find_missing_bits` | Full Speck32/64 fixed plaintext/key yields designers' ciphertext `0xa86842f2` | Ported in M10.6b | Exact Boolean-to-MiniZinc lowering reuses typed component semantics, restores the full 22-round result, and independently evaluates it; reduced-round unknown-key recovery verifies the projected key the same way |
| Cross-backend two-round PRESENT differential optimum | Legacy MILP establishes minimum XOR-differential weight 4 | Ported to CP in M10.6c1 | Native MiniZinc table constraints consume the shared `PropagationProblem`; a real solver proves bound 3 UNSAT and bound 4 SAT, then the common checker validates all 32 transitions and wiring boundaries |
| Cross-backend three-round PRESENT linear optimum | Preserved legacy fixture establishes minimum XOR-linear weight 4 | Ported to CP in M10.6c2 | Native MiniZinc signed-LAT tables consume `PropagationProblem`; a real solver proves bound 3 UNSAT and bound 4 SAT, and the common checker reconstructs correlation signs and validates all 48 transitions and boundaries |
| Selected Speck deterministic-truncated propagation | Input `00000000011111001110000000000000` propagates after round one to `????100000000000????100000000011` | Ported in M10.6c3 | Paired-carry semantics moved from analysis into shared semantic types; MiniZinc projects the three-valued fixed-pattern result and decoding independently compares it with shared propagation |
| Local impossible PRESENT S-box transition | Difference `1 -> 1` is impossible while `1 -> 3` is feasible with weight 2 | Ported to CP in M10.6c3 | Native MiniZinc table from the shared DDT provider proves the impossible pair UNSAT and the possible pair SAT; exhaustive semantic provider independently validates the result |
| Differential, linear, truncated, impossible, boomerang, and differential-linear CP suites | Legacy feasibility, optimum, and bound fixtures across ordinary and ARX-optimized models | Scheduled for M10.6c–d | Row-level classification occurs as each shared-semantic lowering begins |
