# Advanced CP migration inventory

This inventory is the M10.6d1 acceptance artifact. It covers every specialized
legacy model under `claasp/cipher_modules/models/cp/mzn_models`. A generated
MiniZinc line count is not a scientific result and will not be preserved as an
acceptance test. We retain published or legacy cryptanalytic results, semantic
boundary behavior, and solver feasibility claims; deterministic source tests
belong to the portable representation itself.

| Legacy model family | Preserved evidence | v5 disposition | Checkpoint |
|---|---|---|---|
| `mzn_cipher_model` | Full Speck32/64 evaluation `0xa86842f2` and reduced key recovery | Migrated through common Boolean-to-MiniZinc lowering and independently evaluated | M10.6b |
| `mzn_cipher_model_arx_optimized` | Functional ARX cipher solving | Superseded by graph lowering; optimization must be an internal lowering strategy, not a public model class | M10.6b, M10.6d2 |
| `mzn_xor_differential_model` | Exact differential feasibility and weights, including Speck five-round weight 9 | Shared `PropagationProblem`; retain the result-bearing Speck fixture | M10.6d2 |
| `mzn_xor_differential_model_arx_optimized` | Speck32/64 five-round optimum 9, four-round bounded searches, Raiden result 6, per-round bounds | First preserve Speck optimum 9; add other ciphers only after their typed graphs and independent checkers exist | M10.6d2 |
| `mzn_xor_linear_model` | PRESENT weight 4 and Speck32/64 four-round weight 3 | PRESENT migrated; Speck result already represented by shared exact modular-add linear semantics and remains a CP composition candidate | M10.6c2, later extension |
| deterministic truncated models | Speck pattern propagation | Initial fixed-pattern Speck regression migrated; generalized search remains | M10.6c3, M10.6d3 |
| ARX-optimized deterministic truncated model | Same semantic result with specialized declarations | Supersede the public duplicate with a lowering optimization after generalized truncated semantics exist | M10.6d3 |
| wordwise deterministic truncated model | Enabled legacy coverage checks only declarations and fixed-key structure; no fixed trail result | Native enum states and CP projection supersede sentinel/line-count checks; graph-derived AES singleton-to-column diffusion is explicitly labelled new v5 evidence | M10.6d3c1–c2 |
| probabilistic truncated model (legacy: semi-deterministic) | Local scaled-cost fixtures 309/700; Speck results of weight `1.0` / `0.0` with partially known output patterns | Typed local transitions and multi-round Speck composition migrated with independent checking | M10.6d3a–b |
| impossible XOR-differential model | Speck-7 nonzero-endpoint search is UNSAT; Simon-11 fixes input `00000000000000000000000000000001`, inverse output `00000020200000000000000000000000`, forward middle `22222222222222220222222122222202`, and backward middle `22222222002222202222222022222222` | Compose bidirectional propagation and retain both fixtures; Simon fixture explicitly depends on typed Simon32/64 migration | M10.6d4b–d |
| hybrid impossible model | LBlock-4 returns six all-unrestricted boundary solutions; improbable variant reports weight 0 or 2–3 depending on constraints | Express the boundary as semantic overrides in one `PropagationProblem`; defer reproduction until typed LBlock exists | M10.6d4, cipher prerequisite |
| active-S-box objective models | Minimum active S-box counts and fixed-count feasibility | General objective over graph annotations; merge two legacy classes into one objective API | M10.6d4 |
| boomerang ARX-optimized model | Upper/lower trail compatibility and parsed result consistency | Add explicit boomerang boundary semantics and independently verify both constituent trails | M10.6d5 |
| differential-linear model | Speck total weight 14 and component results | Add a composed attack result holding differential trail, linear trail, and connecting boundary | M10.6d5 |
| differential-linear continuous model | Continuous scores/status fixtures | Treat as numerical heuristic, record precision/tolerance, and never use it to certify exact UNSAT or optimality | M10.6d6 |

## Acceptance rules

Each migrated exact model must consume shared semantics, use an open-source
solver in external CI, and project its assignment into a portable result. A
checker independent of the generated MiniZinc source must validate every
reported transition and graph boundary. An optimum requires both a satisfying
witness at the claimed weight and an unsatisfiable lower bound.

Continuous models instead require a documented numeric representation,
tolerance, and reproducibility envelope. They may report candidates or bounds,
but must not share an exact-proof status type unless a separate exact checker
establishes the claim.

## Dependency order

Exact ARX composition comes first because its modular-add semantics already
exist and its weight-9 Speck fixture is a strong end-to-end regression.
Generalized truncated domains follow and are then reused by impossible search.
Boomerang and differential-linear models depend on explicit multi-trail
boundaries. Continuous propagation is last because it introduces numerical
contracts unrelated to exact MiniZinc satisfiability.
