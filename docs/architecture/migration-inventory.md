# CLAASP v5 migration inventory

This is a living inventory. Each item eventually receives one of four states:
`ported`, `superseded`, `deferred`, or `not applicable`.

## Dependency baseline

At the start of the v5 branch, 27 production Python modules contain a direct
top-level `sage` import. The important architectural hotspots include:

- `claasp/component.py`
- `claasp/components/sbox_component.py`
- `claasp/components/linear_layer_component.py`
- `claasp/components/mix_column_component.py`
- `claasp/components/fsr_component.py`
- `claasp/cipher_modules/generic_functions.py`
- `claasp/cipher_modules/models/algebraic/algebraic_model.py`
- model base classes for SAT, CP, and MILP
- shared utility modules used by ciphers and analyses

The existing distribution also declares `sage-package` as a required runtime
dependency and executes its historical doctest suite through Sage. The
`next/` distribution intentionally has neither behavior.

## Migration table

| Legacy area | Initial v5 disposition | Validation |
| --- | --- | --- |
| Cipher and round graph | Superseded by typed graph | Graph invariant tests |
| Input bit positions | Superseded by logical-unit selections | Type/selection tests |
| Component identifiers | Port semantics, redesign API | Determinism tests |
| Bit scalar evaluation | Deferred until bit components | Differential tests |
| Vectorized evaluation | Superseded by evaluator backend | Scalar/batch equivalence |
| Permutation | Port as domain-neutral component | Multi-domain tests |
| Constants and outputs | Port as structural components | Unit tests |
| S-box lookup table | Port as bit-vector finite map | Published vectors |
| MixColumn | Superseded by typed linear map | AES comparison |
| Modular integer operations | Deferred | ARX comparison |
| Boolean algebraic model | Deferred as external backend | Existing model fixtures |
| SAT/SMT/MILP/CP models | Deferred as external backends | Selected trail searches |
| Serialization | Superseded by schema v5 | Round-trip tests |
| Diagram compilers | Deferred | Snapshot/semantic tests |
| Cipher catalogue | Incremental migration | Known-answer tests |

## Reference implementations

The initial end-to-end set is:

- MiMC: minimal prime-field algebraic permutation/cipher.
- Poseidon or Poseidon2: vector prime-field permutation with partial rounds.
- Speck: integer modular arithmetic and rotations.
- AES or ToyAES: bit encodings, lookup maps, and `GF(2^8)` linear algebra.
- PRESENT or GIFT: conventional bit-oriented SPN.

## Update rule

After each merge from `develop`, changes affecting this inventory are recorded
here. Semantic fixes and new authoritative test vectors receive priority over
mechanical ports of legacy APIs.
