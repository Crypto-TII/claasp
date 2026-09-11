# CLAASP v5 usability audit

This is a living audit of friction exposed by public examples and reference
ciphers. Resolved items stay listed so later refactors do not regress them.

## Resolved

- Traditional ciphers accept packed integer inputs and return a packed integer.
- `cipher.evaluate(...)` accepts positional, keyword, or mapping input styles.
- `cipher.evaluate_with_trace(...)` exposes intermediate component values only
  when requested.
- Single-element prime-field states accept an integer; vectors retain tuples
  of field elements rather than inventing an ambiguous packed representation.
- AES, PRESENT, Speck, MiMC, Poseidon, and parameter-catalogue introductory
  examples no longer require direct `ScalarEvaluator` use.
- Public examples include the imports needed to run them independently.
- Ports support indexing/slicing, whole ports are component inputs, and routine
  component IDs are automatic.
- Packed boundary conversion rejects overflow instead of truncating values.

## Open items and owning milestones

| Friction | Required outcome | Owner |
| --- | --- | --- |
| Batch evaluation still exposes backend-oriented input layout | Add a friendly cipher-level batch API while retaining explicit optimized backends | M9.2 documentation/API pass |
| Cipher and parameter discovery requires knowing class/module names | Add a searchable catalogue with configurations and short examples | M9.2 |
| There is no uniform decryption/inversion capability | Specify which ciphers expose decryption and which analyses invert constraints | M10.1/M10.2 |
| Analysis currently exposes CNF/model terminology | Add graph-level constraints, projections, and a concise analysis facade | M10.1 |
| Result formatting differs between evaluation, batch, and solver layers | Define stable user-facing result objects and raw/encoded access | M10.1 |
| Reduced-round semantics can differ by primitive | Document whether a reduced instance is a prefix or retains final-round rules | M9.2 |
| Errors name internal domains and value types before user concepts | Audit common failure paths and add actionable messages/examples | M9.2 |
| Serialization and diagrams may expose internal identifiers | Design human labels separately from stable machine identifiers | M10.8 |

Every introductory documentation example is reviewed against this audit when
its owning milestone closes.
