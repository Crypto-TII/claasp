# CLAASP v5 review, bit-vector/AO validation, and release plan

## Status and authority

This plan supersedes the execution portion of `v5-plan.md` after the validated
`5.0.0rc1` checkpoint. The former plan remains the historical implementation
and migration tracker. No merge, final license-file change, repository
transfer, or publication is authorized merely because an earlier machine gate
passed.

The next release decision is deliberately human-led. The candidate must first
survive a careful manual review and then demonstrate that its typed graph,
representation, analysis, and driver boundaries support the intended
bit-vector and AO analysis packages without architectural workarounds.

## Confirmed initial repository scope

Only these repositories belong to the initial CLAASP organization migration:

| Repository | Current baseline | Timing |
|---|---|---|
| `Crypto-TII/claasp` | validated v5 candidate plus the evolving CLAASP 4 line | review and AO work first |
| `Crypto-TII/claasping_aradi` | legacy CLAASP | final migration phase |
| `Crypto-TII/claasping_ballet` | legacy CLAASP | final migration phase |
| `Crypto-TII/claasping_splight` | legacy CLAASP | final migration phase |
| `peacker/claasp_solvers_benchmarks` | legacy CLAASP | final migration phase |

`claasp-llm`, `claasp-pro`, `claasp-symmetric-cipher-analysis`, and
`jupyter-claasp-cascada-deployment` are explicitly outside the initial scope.
They are neither migration blockers nor implicitly abandoned; a later plan may
admit them independently.

The organization handle and assignment of at least two owners are intentionally
deferred until the final phase.

## License decision

MIT is the selected target license for CLAASP v5, recorded from the project
owner's 2026-09-21 direction. The checked-out candidate remains
GPL-3.0-or-later until a dedicated, reviewable license-change slice updates the
root license, package metadata, source/data classifications, third-party
notices, and provenance authority together. That slice must attach the final
authorization evidence; selecting MIT in this plan must not create a false
claim that the current files have already been relicensed.

## Dependency-ordered work

### R1. Review authority and comparison material

- Keep the exhaustive machine matrix at
  `migration/m11a_bidirectional_migration.json` authoritative.
- Generate `docs/final_migration_audit.md` with every legacy source/test record,
  its disposition, destination(s), relationship (direct, split,
  consolidated, removed, or inapplicable), and reason.
- Include the reverse list of every shipped v5 artifact, its predecessor(s),
  or its new-v5 rationale.
- Maintain the short, non-exhaustive overview in `v5-main-changes.md`.
- Reject stale paths, missing reasons, unclassified records, or undocumented
  new artifacts in CI.

### R2. Careful manual/human v5 review

Review the branch by architectural area rather than by commit count:

1. public API, naming, immutability, validation, and error contracts;
2. domains, graph structure, components, composites, and primitive authoring;
3. execution semantics, traces, annotations, and provenance;
4. SAT/SMT/MILP/CP/polynomial representations and solver projections;
5. analyses, transformations, serialization, generated source, and drivers;
6. catalogue, presentation, documentation, packaging, and dependency
   isolation;
7. the complete legacy-to-v5 and v5-to-legacy mapping, concentrating on
   removals, splits, consolidations, and behavior intentionally not retained.

Review findings must be recorded with severity, owner, affected public
contract, decision, evidence, and resolution commit. The merge gate remains
closed until the designated reviewers explicitly sign off and all blocking
findings are resolved. Machine tests complement this review; they do not
substitute for it.

### R3. CASCADA/CryptoSMT bit-vector audit and design

Use the checked-out reference implementations in `ranea/CASCADA` and the
CryptoSMT workspace as design evidence, not as code to copy implicitly. In a
dedicated follow-up session:

- inventory their bit-vector expression systems, primitive models, properties,
  searches, solver interfaces, and result contracts;
- compare them with CLAASP's existing semantic types, SMT representation,
  solver projections, and typed graph rather than creating a parallel stack;
- decide which contracts belong in shared semantics, a bit-vector
  representation, analyses, and an optional Boolector driver;
- record fixed representative workloads, expected results, unsupported cases,
  performance boundaries, and independent correctness checks;
- audit licenses, authorship, and provenance before adapting any implementation
  or model; and
- specify the public API, serialization, diagnostics, optional-dependency
  behavior, and canonical-image requirements before implementation.

The core package must remain importable without Boolector or its Python
bindings. The design must also decide whether the supported boundary uses an
external executable, Python bindings, or both; this plan does not prejudge that
choice merely because Boolector is required in the release image.

### R4. Bit-vector modelling and Boolector implementation

Implement the accepted R3 design as separately reviewable slices. Keep shared
bit-vector meaning independent of solver syntax, reuse the existing graph and
SMT infrastructure where its contracts fit, and isolate Boolector behind a
driver. Pin the selected Boolector distribution or build in the canonical
Docker environment without adding it to dependency-free core imports.

Require deterministic model output, typed results and diagnostics,
serialization where applicable, executable examples, cross-checks against the
scalar reference or another independent backend, and fixed CASCADA/CryptoSMT
parity evidence. Update API documentation, optional-tool guidance, image-size
evidence, multi-architecture container checks, quality gates, inventory, and
wheel audits in the same workstream.

### R5. AO analysis requirements and design probes

Before adding production AO packages, record representative workloads and the
contracts they require. Each probe must answer:

- which graph/domain/component constructs it consumes;
- whether it works over authored, transformed, composite, and deserialized
  primitives;
- which semantic and representation layers it extends;
- how optional solvers or scientific packages remain isolated;
- which immutable inputs, results, diagnostics, provenance, and serialization
  it exposes;
- how correctness is checked independently of the backend;
- whether the public API remains small and usable rather than exposing an
  implementation workaround.

At least one end-to-end AO analysis must exercise the intended extension path
before the architecture is accepted. Any architectural mismatch reopens the
smallest affected v5 contract and receives focused parity, documentation, and
regression evidence.

### R6. AO module/package implementation

Implement the agreed AO modules only after R5 fixes their requirements. Each
package must include typed public APIs, deterministic examples, catalogue
registration where applicable, dependency-isolation tests, backend parity or
independent validation, serializable provenance-bearing results, and user and
developer documentation. Update the public-API, documentation, typing,
inventory, and wheel authorities in the same slices.

### R7. Post-review candidate checkpoint

Resolve every blocking review/AO finding, apply the MIT license slice with its
authorization evidence, and build a new candidate. Repeat the complete host,
amd64, and arm64 matrix, external tools, doctests, warning-free documentation,
format/lint/type checks, wheel/sdist audit, and all closure gates. Do not reuse
the `5.0.0rc1` evidence for a materially changed candidate.

### R8. Final CLAASP 4 freeze and reconciliation

The current `develop` line is still active and may culminate in CLAASP 4.0.
Fetching it now is informational, not the final review boundary. Once its
maintainers declare the line frozen:

- fetch the exact final tip and record the release/tag/commit;
- classify every commit after the current reconciliation boundary;
- port applicable correctness fixes without importing obsolete mutable APIs;
- regenerate the exhaustive bidirectional comparison against the frozen tree;
- preserve a clearly identified CLAASP 4 maintenance branch or tag.

Any later upstream commit invalidates this slice until classified.

### R9. Final satellite-repository migration

Migrate `claasping_aradi`, `claasping_ballet`, `claasping_splight`, and
`claasp_solvers_benchmarks` only after the reviewed v5/AO API is stable. For
each repository, record its legacy CLAASP assumptions, replace them with the
reviewed v5 API, add fixed behavior evidence, update packaging/documentation,
and decide whether history is transferred, archived, or superseded. All four
must pass their agreed gates before organization-wide publication.

### R10. Organization, merge, transfer, and publication

Last, resolve the `claasp` handle and name at least two owners. Revalidate
permissions and metadata, create private staging under non-final names, freeze
and back up the source repositories, and obtain the human merge confirmation.
Transfer the existing public `Crypto-TII/claasp` repository without changing
its visibility so its stars, forks, issues, releases, history, and redirects
remain attached. Install the reviewed v5 branch, verify the retained CLAASP 4
reference, run the post-transfer audit, and only then publish packages, images,
documentation, and the final release.

## Immediate next gate

R1 is machine work. R2 is the next decision gate and requires explicit human
review confirmation. No merge is scheduled. The bit-vector work is registered
for a dedicated session after that review. AO requirements may be drafted in
parallel with review, but production AO APIs should wait until their design
probes and the relevant reviewed core contracts are accepted.
