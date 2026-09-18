# Primitive inversion audit

Generated at 2026-09-18T14:09:15+00:00 from commit `69bb7b16` on macOS-26.3-x86_64-i386-64bit, Python 3.11.12.

## Scope and interpretation

This audit covers every public primitive and every named parameter set in the committed v5 catalogue, including toy and single-component primitives. The operation under test recovers the first primitive input from the primitive output while retaining every other primitive input. Therefore, **verified** means that the current solver-free graph transformation constructed an inverse and recovered the original first input for two deterministic semantic samples. It does not mean that a multi-input primitive is globally bijective without retained inputs.

The catalogue's bijectivity obligation is reported independently. A `yes` is a specification/classification claim; a failed transformation on such a row identifies a methodology gap, not proof that the mathematical primitive is non-invertible. Conversely, a recoverable operand of XOR or modular addition may verify even when the whole multi-input function has no catalogue bijectivity obligation.

Inverse construction was measured 1 time(s) per successful configuration and the median is shown. Each attempt had a 600-second limit, with 4 isolated workers running concurrently. `1-round ms` is a separately constructed public configuration using `number_of_rounds=1` or `number_of_steps=1`; a one-graph-round primitive reuses its full measurement. `ms/round` is also supplied as the full construction time divided by immutable graph-round count. Construction of the forward graph and semantic evaluation are excluded from inversion timings.

## Summary

- Public primitives: **142**
- Official parameter sets checked: **234**
- Primitives with at least one verified configuration: **78**
- Primitives verified for every official configuration: **78**
- Configuration outcomes: **1 inversion-error**, **103 not-supported**, **130 verified**
- Catalogue-bijective configurations verified by the current transformation: **113/188**
- Configurations without a catalogue bijectivity obligation that still support first-input recovery with auxiliaries: **17/46**
- One-round outcomes: **5 construction-error**, **1 inversion-error**, **87 not-supported**, **13 unavailable**, **128 verified**

| Category | Primitives | Configurations | Verified | Not supported | Timed out | Other |
|---|---:|---:|---:|---:|---:|---:|
| `block_ciphers` | 61 | 132 | 84 | 48 | 0 | 0 |
| `block_functions` | 8 | 8 | 1 | 7 | 0 | 0 |
| `functions` | 7 | 11 | 0 | 11 | 0 | 0 |
| `permutations` | 27 | 39 | 23 | 16 | 0 | 0 |
| `single_component_primitives` | 23 | 23 | 14 | 8 | 0 | 1 |
| `toy_primitives` | 7 | 7 | 5 | 2 | 0 | 0 |
| `tweakable_block_ciphers` | 9 | 14 | 3 | 11 | 0 | 0 |

### Failure and stall diagnostics

| Diagnostic class | Configurations |
|---|---:|
| `disconnected_dependency` | 2 |
| `information_loss` | 7 |
| `inversion-error` | 1 |
| `multiple_predecessors` | 91 |
| `unsupported_component` | 3 |

### Slowest verified full inversions

| Primitive | Parameter set | Full ms | Graph rounds | ms/round |
|---|---|---:|---:|---:|
| `KatanFSR` | `standard-3` | 140034.419 | 254 | 551.317 |
| `KtantanFSR` | `standard-3` | 124592.927 | 254 | 490.523 |
| `KatanFSR` | `standard-2` | 73266.126 | 254 | 288.449 |
| `Knot` | `standard-3` | 66261.457 | 100 | 662.615 |
| `KtantanFSR` | `standard-2` | 61767.273 | 254 | 243.178 |
| `Ballet` | `standard-3` | 59878.489 | 74 | 809.169 |
| `Skinny` | `standard-6` | 54487.906 | 56 | 972.998 |
| `GastonSboxTheta` | `standard-1` | 49451.838 | 12 | 4120.986 |
| `Sparkle` | `standard-6` | 35511.740 | 12 | 2959.312 |
| `Knot` | `standard-2` | 29316.194 | 76 | 385.739 |

## Candidate follow-up milestone

This audit does not open or alter a tracker milestone. Its results suggest that a future inversion-methodology milestone should, in dependency order:

1. replace repeated whole-graph propagation scans with a dependency-driven work queue and benchmark scaling from one round to full KATAN/KTANTAN FSR graphs;
2. distinguish genuinely ambiguous multi-predecessor recovery from reversible Feistel/state-split structure, which is the dominant current stall class;
3. add explicit inverse contracts for reversible feedback-register transitions and IDEA encoded-group multiplication while preserving information-loss failures for non-bijective operations;
4. make zero-input and unavailable-one-round boundaries return typed diagnostics instead of incidental constructor or indexing exceptions; and
5. retain this audit as a reproducible performance and semantic regression baseline.

## Configuration results

Times are milliseconds. Parameters are the exact values passed to the public constructor.

### block_ciphers

| Primitive | Parameter set | Parameters | Obligation | Graph rounds | Components | 1-round outcome | 1-round ms | Full outcome | Full ms | ms/round | Semantic | Diagnostic |
|---|---|---|:---:|---:|---:|---|---:|---|---:|---:|:---:|---|
| `AES` | `standard-1` | `{"key_bit_size":128,"number_of_rounds":10}` | yes | 11 | 110 | `verified` | 5.060 | `verified` | 57.624 | 5.239 | 2/2 | — |
| `AES` | `standard-2` | `{"key_bit_size":192,"number_of_rounds":12}` | yes | 13 | 118 | `verified` | 4.676 | `verified` | 68.750 | 5.288 | 2/2 | — |
| `AES` | `standard-3` | `{"key_bit_size":256,"number_of_rounds":14}` | yes | 15 | 135 | `verified` | 4.492 | `verified` | 85.250 | 5.683 | 2/2 | — |
| `Aradi` | `default` | `{"number_of_rounds":16}` | yes | 16 | 868 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_14]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_15_14] |
| `AradiSBox` | `standard-1` | `{"number_of_rounds":16}` | yes | 16 | 1252 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_40]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_15_40] |
| `AradiSBoxCompactLinearMap` | `standard-1` | `{"number_of_rounds":16}` | yes | 16 | 932 | `verified` | 29.527 | `verified` | 3300.699 | 206.294 | 2/2 | — |
| `BEA1` | `standard-1` | `{"number_of_rounds":11}` | yes | 11 | 442 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_174]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_10_16] |
| `Baksheesh` | `standard-1` | `{"block_bit_size":128,"key_bit_size":128,"number_of_rounds":35}` | yes | 35 | 1296 | `verified` | 9.039 | `verified` | 4182.823 | 119.509 | 2/2 | — |
| `Ballet` | `standard-1` | `{"block_bit_size":128,"key_bit_size":128,"number_of_rounds":46}` | yes | 46 | 594 | `verified` | 5.445 | `verified` | 11073.508 | 240.728 | 2/2 | — |
| `Ballet` | `standard-2` | `{"block_bit_size":128,"key_bit_size":256,"number_of_rounds":48}` | yes | 48 | 808 | `verified` | 5.692 | `verified` | 19626.581 | 408.887 | 2/2 | — |
| `Ballet` | `standard-3` | `{"block_bit_size":256,"key_bit_size":256,"number_of_rounds":74}` | yes | 74 | 958 | `verified` | 15.675 | `verified` | 59878.489 | 809.169 | 2/2 | — |
| `CHAM` | `default` | `{"block_bit_size":64,"key_bit_size":128,"number_of_rounds":null}` | yes | 88 | 576 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_3]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [modular_add_84_4] |
| `Cast` | `standard-1` | `{"key_bit_size":128,"number_of_rounds":16}` | yes | 17 | 579 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [modadd_1_10]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_15_11] |
| `Cast` | `standard-2` | `{"key_bit_size":80,"number_of_rounds":12}` | yes | 13 | 533 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [modadd_1_10]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_11_11] |
| `Cast` | `standard-3` | `{"key_bit_size":40,"number_of_rounds":12}` | yes | 13 | 533 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [modadd_1_10]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_11_11] |
| `DES` | `default` | `{"number_of_rounds":16,"number_of_sboxes":8}` | yes | 16 | 244 | `not-supported: information_loss: BitVectorSBox lookup table is not bijective [sbox_0_8]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_15_13] |
| `DESExactKeyLength` | `standard-1` | `{"number_of_rounds":16,"number_of_sboxes":8}` | yes | 16 | 244 | `not-supported: information_loss: BitVectorSBox lookup table is not bijective [sbox_0_8]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_15_13] |
| `Gift` | `default` | `{"block_bit_size":128,"number_of_rounds":null}` | yes | 40 | 678 | `verified` | 17.663 | `verified` | 16904.170 | 422.604 | 2/2 | — |
| `GiftSbox` | `standard-1` | `{"block_bit_size":64,"number_of_rounds":28}` | yes | 28 | 726 | `verified` | 3.343 | `verified` | 1113.821 | 39.779 | 2/2 | — |
| `GiftSbox` | `standard-2` | `{"block_bit_size":128,"number_of_rounds":40}` | yes | 40 | 1678 | `verified` | 5.586 | `verified` | 4295.242 | 107.381 | 2/2 | — |
| `Gost` | `standard-1` | `{"block_bit_size":64,"key_bit_size":256,"number_of_rounds":32}` | yes | 32 | 352 | `verified` | 2.910 | `verified` | 1704.507 | 53.266 | 2/2 | — |
| `HIGHT` | `default` | `{"block_bit_size":64,"key_bit_size":128,"number_of_rounds":null,"sub_keys_zero":false,"transformations_flag":true}` | yes | 32 | 1032 | `verified` | 1.311 | `verified` | 93.390 | 2.918 | 2/2 | — |
| `IDEA` | `default` | `{"number_of_rounds":8}` | yes | 10 | 122 | `not-supported: unsupported_component: IDEA multiplication needs its encoded-group inverse operation [i_d_e_a_multiply_2_0]` | — | `not-supported` | — | — | — | unsupported_component: IDEA multiplication needs its encoded-group inverse operation [i_d_e_a_multiply_9_0] |
| `Kalyna` | `default` | `{"number_of_rounds":10}` | yes | 11 | 560 | `construction-error: KeyError: 1` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [modadd_10_19] |
| `Kasumi` | `standard-1` | `{"block_bit_size":64,"key_bit_size":128,"number_of_rounds":8}` | yes | 8 | 674 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_57]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_6_78] |
| `Katan` | `default` | `{"block_bit_size":32,"ir_mode":"strict","key_bit_size":80,"number_of_rounds":null}` | yes | 254 | 1699 | `verified` | 1.982 | `verified` | 9206.665 | 36.247 | 2/2 | — |
| `KatanFSR` | `standard-1` | `{"block_bit_size":32,"key_bit_size":80,"number_of_rounds":254}` | yes | 254 | 1698 | `verified` | 2.746 | `verified` | 22370.032 | 88.071 | 2/2 | — |
| `KatanFSR` | `standard-2` | `{"block_bit_size":48,"key_bit_size":80,"number_of_rounds":254}` | yes | 254 | 2968 | `verified` | 2.906 | `verified` | 73266.126 | 288.449 | 2/2 | — |
| `KatanFSR` | `standard-3` | `{"block_bit_size":64,"key_bit_size":80,"number_of_rounds":254}` | yes | 254 | 4238 | `verified` | 4.435 | `verified` | 140034.419 | 551.317 | 2/2 | — |
| `Ktantan` | `default` | `{"block_bit_size":32,"ir_mode":"strict","key_bit_size":80,"number_of_rounds":null}` | yes | 254 | 1271 | `verified` | 2.435 | `verified` | 6749.693 | 26.574 | 2/2 | — |
| `KtantanFSR` | `standard-1` | `{"block_bit_size":32,"key_bit_size":80,"number_of_rounds":254}` | yes | 254 | 1270 | `verified` | 1.905 | `verified` | 16440.131 | 64.725 | 2/2 | — |
| `KtantanFSR` | `standard-2` | `{"block_bit_size":48,"key_bit_size":80,"number_of_rounds":254}` | yes | 254 | 2540 | `verified` | 2.875 | `verified` | 61767.273 | 243.178 | 2/2 | — |
| `KtantanFSR` | `standard-3` | `{"block_bit_size":64,"key_bit_size":80,"number_of_rounds":254}` | yes | 254 | 3810 | `verified` | 4.578 | `verified` | 124592.927 | 490.523 | 2/2 | — |
| `LBlock` | `standard-1` | `{"number_of_rounds":32}` | yes | 32 | 512 | `verified` | 4.339 | `verified` | 2516.657 | 78.646 | 2/2 | — |
| `LEA` | `default` | `{"block_bit_size":128,"key_bit_size":192,"number_of_rounds":null,"reorder_input_and_output":true}` | yes | 28 | 1022 | `verified` | 6.807 | `verified` | 273.651 | 9.773 | 2/2 | — |
| `Led` | `standard-1` | `{"key_bit_size":64,"number_of_rounds":32}` | yes | 8 | 713 | `construction-error: AssertionError: Number of rounds must be a multiple of 4.` | — | `verified` | 928.550 | 116.069 | 2/2 | — |
| `Led` | `standard-2` | `{"key_bit_size":128,"number_of_rounds":48}` | yes | 12 | 1069 | `construction-error: AssertionError: Number of rounds must be a multiple of 4.` | — | `verified` | 1984.024 | 165.335 | 2/2 | — |
| `LowMC` | `default` | `{"block_bit_size":128,"key_bit_size":128,"number_of_rounds":null,"number_of_sboxes":null}` | yes | 20 | 302 | `construction-error: ValueError: No available number of sboxes for the given parameters.` | — | `verified` | 6436.134 | 321.807 | 2/2 | — |
| `MSX` | `standard-1` | `{"block_bit_size":64,"key_bit_size":128,"number_of_rounds":14}` | yes | 14 | 310 | `verified` | 20.589 | `verified` | 1470.140 | 105.010 | 2/2 | — |
| `MSX` | `standard-2` | `{"block_bit_size":128,"key_bit_size":128,"number_of_rounds":18}` | yes | 18 | 752 | `verified` | 41.987 | `verified` | 4502.108 | 250.117 | 2/2 | — |
| `MSX` | `standard-3` | `{"block_bit_size":128,"key_bit_size":256,"number_of_rounds":18}` | yes | 18 | 756 | `verified` | 51.018 | `verified` | 4868.469 | 270.471 | 2/2 | — |
| `Midori` | `standard-1` | `{"block_bit_size":64,"key_bit_size":128,"number_of_rounds":16}` | yes | 16 | 379 | `verified` | 4.407 | `verified` | 388.309 | 24.269 | 2/2 | — |
| `Midori` | `standard-2` | `{"block_bit_size":128,"key_bit_size":128,"number_of_rounds":20}` | yes | 20 | 1434 | `verified` | 8.126 | `verified` | 1865.246 | 93.262 | 2/2 | — |
| `Piccolo` | `standard-1` | `{"key_bit_size":80,"number_of_rounds":25}` | yes | 25 | 628 | `verified` | 4.841 | `verified` | 724.818 | 28.993 | 2/2 | — |
| `Piccolo` | `standard-2` | `{"key_bit_size":128,"number_of_rounds":31}` | yes | 31 | 778 | `verified` | 4.623 | `verified` | 1075.153 | 34.682 | 2/2 | — |
| `Present` | `default` | `{"key_bit_size":80,"number_of_rounds":31}` | yes | 31 | 683 | `verified` | 2.937 | `verified` | 750.759 | 24.218 | 2/2 | — |
| `Prince` | `default` | `{"number_of_rounds":12}` | yes | 11 | 254 | `verified` | 17.705 | `verified` | 288.739 | 26.249 | 2/2 | — |
| `PrinceV2` | `default` | `{"number_of_rounds":12}` | yes | 11 | 254 | `verified` | 16.736 | `verified` | 285.761 | 25.978 | 2/2 | — |
| `RC5` | `default` | `{"key_size":64,"number_of_rounds":16,"word_size":16}` | yes | 17 | 645 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [modular_add_1_2]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [modular_add_16_2] |
| `Raiden` | `default` | `{"block_bit_size":64,"key_bit_size":128,"left_shift_amount":9,"number_of_rounds":null,"right_shift_amount":14}` | yes | 16 | 288 | `verified` | 0.717 | `verified` | 27.329 | 1.708 | 2/2 | — |
| `Rectangle` | `standard-1` | `{"key_bit_size":80,"number_of_rounds":25}` | yes | 25 | 751 | `verified` | 7.845 | `verified` | 2336.557 | 93.462 | 2/2 | — |
| `Rectangle` | `standard-2` | `{"key_bit_size":128,"number_of_rounds":25}` | yes | 25 | 851 | `verified` | 9.128 | `verified` | 3024.925 | 120.997 | 2/2 | — |
| `Rijndael` | `standard-1` | `{"block_bit_size":128,"key_bit_size":128,"number_of_rounds":10}` | yes | 10 | 317 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_28]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_9_16] |
| `Rijndael` | `standard-10` | `{"block_bit_size":160,"key_bit_size":256,"number_of_rounds":14}` | yes | 14 | 522 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_30]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_13_20] |
| `Rijndael` | `standard-11` | `{"block_bit_size":192,"key_bit_size":128,"number_of_rounds":12}` | yes | 12 | 574 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_47]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_11_24] |
| `Rijndael` | `standard-12` | `{"block_bit_size":192,"key_bit_size":160,"number_of_rounds":12}` | yes | 12 | 545 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_46]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_11_24] |
| `Rijndael` | `standard-13` | `{"block_bit_size":192,"key_bit_size":192,"number_of_rounds":12}` | yes | 12 | 523 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_38]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_11_24] |
| `Rijndael` | `standard-14` | `{"block_bit_size":192,"key_bit_size":224,"number_of_rounds":13}` | yes | 13 | 596 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_41]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_12_24] |
| `Rijndael` | `standard-15` | `{"block_bit_size":192,"key_bit_size":256,"number_of_rounds":14}` | yes | 14 | 628 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_36]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_13_24] |
| `Rijndael` | `standard-16` | `{"block_bit_size":224,"key_bit_size":128,"number_of_rounds":13}` | yes | 13 | 724 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_60]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_12_28] |
| `Rijndael` | `standard-17` | `{"block_bit_size":224,"key_bit_size":160,"number_of_rounds":13}` | yes | 13 | 688 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_52]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_12_28] |
| `Rijndael` | `standard-18` | `{"block_bit_size":224,"key_bit_size":192,"number_of_rounds":13}` | yes | 13 | 666 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_51]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_12_28] |
| `Rijndael` | `standard-19` | `{"block_bit_size":224,"key_bit_size":224,"number_of_rounds":13}` | yes | 13 | 696 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_47]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_12_28] |
| `Rijndael` | `standard-2` | `{"block_bit_size":128,"key_bit_size":160,"number_of_rounds":11}` | yes | 11 | 334 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_27]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_10_16] |
| `Rijndael` | `standard-20` | `{"block_bit_size":224,"key_bit_size":256,"number_of_rounds":14}` | yes | 14 | 734 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_46]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_13_28] |
| `Rijndael` | `standard-21` | `{"block_bit_size":256,"key_bit_size":128,"number_of_rounds":14}` | yes | 14 | 886 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_66]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_13_32] |
| `Rijndael` | `standard-22` | `{"block_bit_size":256,"key_bit_size":160,"number_of_rounds":14}` | yes | 14 | 843 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_65]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_13_32] |
| `Rijndael` | `standard-23` | `{"block_bit_size":256,"key_bit_size":192,"number_of_rounds":14}` | yes | 14 | 814 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_57]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_13_32] |
| `Rijndael` | `standard-24` | `{"block_bit_size":256,"key_bit_size":224,"number_of_rounds":14}` | yes | 14 | 863 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_60]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_13_32] |
| `Rijndael` | `standard-25` | `{"block_bit_size":256,"key_bit_size":256,"number_of_rounds":14}` | yes | 14 | 833 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_52]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_13_32] |
| `Rijndael` | `standard-3` | `{"block_bit_size":128,"key_bit_size":192,"number_of_rounds":12}` | yes | 12 | 351 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_26]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_11_16] |
| `Rijndael` | `standard-4` | `{"block_bit_size":128,"key_bit_size":224,"number_of_rounds":13}` | yes | 13 | 396 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_25]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_12_16] |
| `Rijndael` | `standard-5` | `{"block_bit_size":128,"key_bit_size":256,"number_of_rounds":14}` | yes | 14 | 416 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_17]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_13_16] |
| `Rijndael` | `standard-6` | `{"block_bit_size":160,"key_bit_size":128,"number_of_rounds":11}` | yes | 11 | 436 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_41]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_10_20] |
| `Rijndael` | `standard-7` | `{"block_bit_size":160,"key_bit_size":160,"number_of_rounds":11}` | yes | 11 | 414 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_33]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_10_20] |
| `Rijndael` | `standard-8` | `{"block_bit_size":160,"key_bit_size":192,"number_of_rounds":12}` | yes | 12 | 437 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_32]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_11_20] |
| `Rijndael` | `standard-9` | `{"block_bit_size":160,"key_bit_size":224,"number_of_rounds":13}` | yes | 13 | 496 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_31]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_12_20] |
| `SM4` | `default` | `{"number_of_rounds":32,"state_size":8,"word_size":8}` | yes | 32 | 936 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_35]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_28_28] |
| `SPARX` | `default` | `{"block_bit_size":64,"key_bit_size":128,"number_of_rounds":null,"steps":null}` | yes | 8 | 394 | `verified` | 16.185 | `verified` | 741.854 | 92.732 | 2/2 | — |
| `Saecham` | `standard-1` | `{"number_of_rounds":88}` | yes | 88 | 576 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_3]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [modadd_84_5] |
| `Serpent` | `standard-1` | `{"key_bit_size":128,"number_of_rounds":32}` | yes | 32 | 3017 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_629]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_31_33] |
| `Serpent` | `standard-2` | `{"key_bit_size":192,"number_of_rounds":32}` | yes | 32 | 3015 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_627]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_31_33] |
| `Serpent` | `standard-3` | `{"key_bit_size":256,"number_of_rounds":32}` | yes | 32 | 3013 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_625]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_31_33] |
| `Simeck` | `default` | `{"block_bit_size":32,"key_bit_size":64,"number_of_rounds":null,"rotation_amounts":[-5,-1]}` | yes | 32 | 346 | `verified` | 0.331 | `verified` | 31.523 | 0.985 | 2/2 | — |
| `SimeckSbox` | `standard-1` | `{"block_bit_size":32,"key_bit_size":64,"number_of_rounds":32}` | yes | 32 | 283 | `verified` | 1.673 | `verified` | 686.544 | 21.455 | 2/2 | — |
| `SimeckSbox` | `standard-2` | `{"block_bit_size":48,"key_bit_size":96,"number_of_rounds":36}` | yes | 36 | 390 | `verified` | 1.687 | `verified` | 1181.098 | 32.808 | 2/2 | — |
| `SimeckSbox` | `standard-3` | `{"block_bit_size":64,"key_bit_size":128,"number_of_rounds":44}` | yes | 44 | 565 | `verified` | 2.011 | `verified` | 2299.009 | 52.250 | 2/2 | — |
| `Simon` | `default` | `{"block_bit_size":32,"key_bit_size":64,"number_of_rounds":null}` | yes | 32 | 332 | `verified` | 0.373 | `verified` | 28.892 | 0.903 | 2/2 | — |
| `SimonSbox` | `standard-1` | `{"block_bit_size":32,"key_bit_size":64,"number_of_rounds":32}` | yes | 32 | 240 | `verified` | 1.516 | `verified` | 936.559 | 29.267 | 2/2 | — |
| `SimonSbox` | `standard-10` | `{"block_bit_size":128,"key_bit_size":256,"number_of_rounds":72}` | yes | 72 | 992 | `verified` | 9.657 | `verified` | 16234.645 | 225.481 | 2/2 | — |
| `SimonSbox` | `standard-2` | `{"block_bit_size":48,"key_bit_size":72,"number_of_rounds":36}` | yes | 36 | 279 | `verified` | 1.970 | `verified` | 1263.305 | 35.092 | 2/2 | — |
| `SimonSbox` | `standard-3` | `{"block_bit_size":48,"key_bit_size":96,"number_of_rounds":36}` | yes | 36 | 308 | `verified` | 2.003 | `verified` | 1716.536 | 47.682 | 2/2 | — |
| `SimonSbox` | `standard-4` | `{"block_bit_size":64,"key_bit_size":96,"number_of_rounds":42}` | yes | 42 | 369 | `verified` | 2.329 | `verified` | 2384.823 | 56.781 | 2/2 | — |
| `SimonSbox` | `standard-5` | `{"block_bit_size":64,"key_bit_size":128,"number_of_rounds":44}` | yes | 44 | 424 | `verified` | 3.558 | `verified` | 3556.422 | 80.828 | 2/2 | — |
| `SimonSbox` | `standard-6` | `{"block_bit_size":96,"key_bit_size":96,"number_of_rounds":52}` | yes | 52 | 566 | `verified` | 3.091 | `verified` | 5303.911 | 101.998 | 2/2 | — |
| `SimonSbox` | `standard-7` | `{"block_bit_size":96,"key_bit_size":144,"number_of_rounds":54}` | yes | 54 | 585 | `verified` | 3.247 | `verified` | 5555.746 | 102.884 | 2/2 | — |
| `SimonSbox` | `standard-8` | `{"block_bit_size":128,"key_bit_size":128,"number_of_rounds":68}` | yes | 68 | 878 | `verified` | 4.590 | `verified` | 11169.794 | 164.262 | 2/2 | — |
| `SimonSbox` | `standard-9` | `{"block_bit_size":128,"key_bit_size":192,"number_of_rounds":69}` | yes | 69 | 888 | `verified` | 3.857 | `verified` | 11153.681 | 161.648 | 2/2 | — |
| `Skinny` | `standard-1` | `{"block_bit_size":64,"key_bit_size":64,"number_of_rounds":32}` | yes | 32 | 1313 | `verified` | 8.027 | `verified` | 3789.611 | 118.425 | 2/2 | — |
| `Skinny` | `standard-2` | `{"block_bit_size":64,"key_bit_size":128,"number_of_rounds":36}` | yes | 36 | 2045 | `verified` | 13.206 | `verified` | 9667.578 | 268.544 | 2/2 | — |
| `Skinny` | `standard-3` | `{"block_bit_size":64,"key_bit_size":192,"number_of_rounds":40}` | yes | 40 | 2905 | `verified` | 15.988 | `verified` | 18997.727 | 474.943 | 2/2 | — |
| `Skinny` | `standard-4` | `{"block_bit_size":128,"key_bit_size":128,"number_of_rounds":40}` | yes | 40 | 1641 | `verified` | 12.011 | `verified` | 8508.431 | 212.711 | 2/2 | — |
| `Skinny` | `standard-5` | `{"block_bit_size":128,"key_bit_size":256,"number_of_rounds":48}` | yes | 48 | 2729 | `verified` | 15.459 | `verified` | 25025.167 | 521.358 | 2/2 | — |
| `Skinny` | `standard-6` | `{"block_bit_size":128,"key_bit_size":384,"number_of_rounds":56}` | yes | 56 | 4073 | `verified` | 21.745 | `verified` | 54487.906 | 972.998 | 2/2 | — |
| `Skipjack` | `default` | `{"number_of_rounds":32}` | yes | 32 | 464 | `verified` | 5.803 | `verified` | 2940.567 | 91.893 | 2/2 | — |
| `Speck` | `standard-1` | `{"block_bit_size":32,"key_bit_size":64,"number_of_rounds":22}` | yes | 22 | 236 | `verified` | 0.417 | `verified` | 52.480 | 2.385 | 2/2 | — |
| `Speck` | `standard-10` | `{"block_bit_size":128,"key_bit_size":256,"number_of_rounds":34}` | yes | 34 | 368 | `verified` | 0.527 | `verified` | 111.161 | 3.269 | 2/2 | — |
| `Speck` | `standard-2` | `{"block_bit_size":48,"key_bit_size":72,"number_of_rounds":22}` | yes | 22 | 236 | `verified` | 0.514 | `verified` | 49.908 | 2.269 | 2/2 | — |
| `Speck` | `standard-3` | `{"block_bit_size":48,"key_bit_size":96,"number_of_rounds":23}` | yes | 23 | 247 | `verified` | 0.853 | `verified` | 50.231 | 2.184 | 2/2 | — |
| `Speck` | `standard-4` | `{"block_bit_size":64,"key_bit_size":96,"number_of_rounds":26}` | yes | 26 | 280 | `verified` | 0.418 | `verified` | 64.114 | 2.466 | 2/2 | — |
| `Speck` | `standard-5` | `{"block_bit_size":64,"key_bit_size":128,"number_of_rounds":27}` | yes | 27 | 291 | `verified` | 0.451 | `verified` | 76.600 | 2.837 | 2/2 | — |
| `Speck` | `standard-6` | `{"block_bit_size":96,"key_bit_size":96,"number_of_rounds":28}` | yes | 28 | 302 | `verified` | 0.445 | `verified` | 80.736 | 2.883 | 2/2 | — |
| `Speck` | `standard-7` | `{"block_bit_size":96,"key_bit_size":144,"number_of_rounds":29}` | yes | 29 | 313 | `verified` | 0.450 | `verified` | 78.850 | 2.719 | 2/2 | — |
| `Speck` | `standard-8` | `{"block_bit_size":128,"key_bit_size":128,"number_of_rounds":32}` | yes | 32 | 346 | `verified` | 0.420 | `verified` | 96.217 | 3.007 | 2/2 | — |
| `Speck` | `standard-9` | `{"block_bit_size":128,"key_bit_size":192,"number_of_rounds":33}` | yes | 33 | 357 | `verified` | 0.443 | `verified` | 106.948 | 3.241 | 2/2 | — |
| `Speedy` | `standard-1` | `{"block_bit_size":192,"key_bit_size":192,"number_of_rounds":5}` | yes | 5 | 521 | `verified` | 16.235 | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_3_77] |
| `Splight` | `standard-1` | `{"block_bit_size":64,"key_bit_size":128,"number_of_rounds":32}` | yes | 32 | 864 | `verified` | 4.440 | `verified` | 2791.217 | 87.226 | 2/2 | — |
| `Subterranean` | `default` | `{"number_of_rounds":1}` | yes | 1 | 11 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_8]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_8] |
| `TEA` | `default` | `{"block_bit_size":64,"key_bit_size":128,"left_shift_amount":4,"number_of_rounds":null,"right_shift_amount":5}` | yes | 32 | 480 | `verified` | 0.819 | `verified` | 82.225 | 2.570 | 2/2 | — |
| `TinyJambu` | `default` | `{"key_bit_size":128,"number_of_rounds":640}` | yes | 640 | 1920 | `not-supported: disconnected_dependency: known boundaries do not connect to every requested target wire [key]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_512_2] |
| `TinyJambuFSRWordBased` | `standard-1` | `{"key_bit_size":128,"number_of_rounds":640}` | yes | 20 | 60 | `not-supported: ambiguous_boundary: primitive has no declared output` | — | `not-supported` | — | — | — | disconnected_dependency: known boundaries do not connect to every requested target wire [plaintext] |
| `TinyJambuWordBased` | `standard-1` | `{"key_bit_size":128,"number_of_rounds":640}` | yes | 20 | 60 | `not-supported: ambiguous_boundary: primitive has no declared output` | — | `verified` | 227.341 | 11.367 | 2/2 | — |
| `Twine` | `standard-1` | `{"key_bit_size":80,"number_of_rounds":36}` | yes | 36 | 900 | `verified` | 5.354 | `verified` | 3737.296 | 103.814 | 2/2 | — |
| `Twine` | `standard-2` | `{"key_bit_size":128,"number_of_rounds":36}` | yes | 36 | 972 | `verified` | 4.973 | `verified` | 3949.733 | 109.715 | 2/2 | — |
| `Twofish` | `standard-1` | `{"key_length":128,"number_of_rounds":16}` | yes | 16 | 1303 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_219]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_15_72] |
| `UKNIT` | `standard-1` | `{"number_of_rounds":12}` | yes | 13 | 283 | `verified` | 6.669 | `verified` | 218.618 | 16.817 | 2/2 | — |
| `Ublock` | `default` | `{"block_bit_size":128,"key_bit_size":128,"number_of_rounds":null}` | yes | 16 | 1121 | `verified` | 38.491 | `verified` | 7422.951 | 463.934 | 2/2 | — |
| `UblockSingleLinearLayer` | `standard-1` | `{"block_bit_size":128,"key_bit_size":128,"number_of_rounds":16}` | yes | 16 | 881 | `verified` | 47.459 | `verified` | 1667.062 | 104.191 | 2/2 | — |
| `UblockSingleLinearLayer` | `standard-2` | `{"block_bit_size":128,"key_bit_size":256,"number_of_rounds":24}` | yes | 24 | 1705 | `verified` | 50.328 | `verified` | 4023.020 | 167.626 | 2/2 | — |
| `UblockSingleLinearLayer` | `standard-3` | `{"block_bit_size":256,"key_bit_size":256,"number_of_rounds":24}` | yes | 24 | 2473 | `verified` | 174.591 | `verified` | 8583.885 | 357.662 | 2/2 | — |
| `Warp` | `default` | `{"number_of_rounds":41}` | yes | 41 | 1516 | `verified` | 6.394 | `verified` | 5426.372 | 132.351 | 2/2 | — |
| `XTEA` | `default` | `{"block_bit_size":64,"key_bit_size":128,"left_shift_amount":4,"number_of_rounds":null,"right_shift_amount":5}` | yes | 32 | 512 | `verified` | 0.639 | `verified` | 76.432 | 2.388 | 2/2 | — |

### block_functions

| Primitive | Parameter set | Parameters | Obligation | Graph rounds | Components | 1-round outcome | 1-round ms | Full outcome | Full ms | ms/round | Semantic | Diagnostic |
|---|---|---|:---:|---:|---:|---|---:|---|---:|---:|:---:|---|
| `A51` | `standard-1` | `{"frame_bit_size":22,"key_bit_size":64,"number_of_normal_clocks_at_initialization":100,"number_of_rounds":228}` | no | 229 | 633 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_1_1]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_1_1] |
| `A52` | `standard-1` | `{"frame_bit_size":22,"key_bit_size":64,"number_of_normal_clocks_at_initialization":100,"number_of_rounds":228}` | no | 229 | 2688 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_189]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_189] |
| `Bivium` | `standard-1` | `{"iv_bit_size":80,"key_bit_size":80,"keystream_bit_len":256,"number_of_initialization_clocks":708,"state_bit_size":177}` | no | 257 | 515 | `unavailable` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_1_0] |
| `ChaChaKeystreamBlock` | `standard-1` | `{"block_bit_size":512,"key_bit_size":256,"number_of_rounds":20}` | no | 41 | 978 | `verified` | 10.753 | `verified` | 242.657 | 5.918 | 2/2 | — |
| `SiphashMAC` | `standard-1` | `{"compression_rounds":2,"finalization_rounds":4,"message_byte_size":15,"output_bit_size":64}` | no | 9 | 131 | `unavailable` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_8_16] |
| `Snow3G` | `standard-1` | `{"iv_bit_size":128,"key_bit_size":128,"keystream_word_size":2,"number_of_initialization_clocks":32}` | no | 35 | 24651 | `unavailable` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_33_20] |
| `Trivium` | `default` | `{"keystream_bit_size":64,"number_of_initialization_clocks":1152}` | no | 1217 | 7362 | `unavailable` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_1153_0] |
| `Zuc` | `standard-1` | `{"iv_bit_size":128,"key_bit_size":128,"len_keystream_word":1,"number_of_initialization_clocks":32}` | no | 2 | 1035 | `unavailable` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_1_22] |

### functions

| Primitive | Parameter set | Parameters | Obligation | Graph rounds | Components | 1-round outcome | 1-round ms | Full outcome | Full ms | ms/round | Semantic | Diagnostic |
|---|---|---|:---:|---:|---:|---|---:|---|---:|---:|:---:|---|
| `Blake` | `standard-1` | `{"block_bit_size":512,"number_of_rounds":28,"state_bit_size":512}` | no | 28 | 2016 | `not-supported: disconnected_dependency: known boundaries do not connect to every requested target wire [input_message]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_26_7] |
| `Blake` | `standard-2` | `{"block_bit_size":1024,"number_of_rounds":32,"state_bit_size":1024,"word_size":64}` | no | 32 | 2304 | `not-supported: disconnected_dependency: known boundaries do not connect to every requested target wire [input_message]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_30_7] |
| `Blake2` | `standard-1` | `{"block_bit_size":1024,"number_of_rounds":12,"state_bit_size":1024}` | no | 12 | 1152 | `verified` | 229.293 | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_11_4] |
| `BluetoothE0` | `standard-1` | `{"fsm_bit_size":4,"key_bit_size":128,"keystream_bit_len":125,"lfsr_state_bit_size":128}` | no | 125 | 2000 | `unavailable` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_0] |
| `MD5` | `standard-1` | `{"number_of_rounds":64,"word_size":32}` | no | 64 | 600 | `not-supported: disconnected_dependency: known boundaries do not connect to every requested target wire [input_message]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [modadd_60_8] |
| `SHA1` | `standard-1` | `{"number_of_rounds":80,"word_size":32}` | no | 80 | 582 | `not-supported: disconnected_dependency: known boundaries do not connect to every requested target wire [input_message]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [modadd_75_4] |
| `SHA2` | `standard-1` | `{"number_of_rounds":64,"output_bit_size":256}` | no | 65 | 1792 | `not-supported: disconnected_dependency: known boundaries do not connect to every requested target wire [input_message]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [modadd_56_29] |
| `SHA2` | `standard-2` | `{"number_of_rounds":64,"output_bit_size":224}` | no | 65 | 1792 | `not-supported: disconnected_dependency: known boundaries do not connect to every requested target wire [input_message]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [modadd_57_29] |
| `SHA2` | `standard-3` | `{"number_of_rounds":80,"output_bit_size":512}` | no | 81 | 2272 | `not-supported: disconnected_dependency: known boundaries do not connect to every requested target wire [input_message]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [modadd_72_29] |
| `SHA2` | `standard-4` | `{"number_of_rounds":80,"output_bit_size":384}` | no | 81 | 2272 | `not-supported: disconnected_dependency: known boundaries do not connect to every requested target wire [input_message]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [modadd_74_29] |
| `Whirlpool` | `standard-1` | `{"number_of_rounds":10,"state_size":8,"word_size":8}` | no | 10 | 1633 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_165]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_9_163] |

### permutations

| Primitive | Parameter set | Parameters | Obligation | Graph rounds | Components | 1-round outcome | 1-round ms | Full outcome | Full ms | ms/round | Semantic | Diagnostic |
|---|---|---|:---:|---:|---:|---|---:|---|---:|---:|:---:|---|
| `Ascon` | `default` | `{"number_of_rounds":12}` | yes | 12 | 468 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_26]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_11_26] |
| `AsconSboxSigma` | `standard-1` | `{"number_of_rounds":12}` | yes | 12 | 852 | `verified` | 82.360 | `verified` | 1463.082 | 121.924 | 2/2 | — |
| `AsconSboxSigmaNoMatrix` | `standard-1` | `{"number_of_rounds":12}` | yes | 12 | 972 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_68]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_11_68] |
| `ChaCha` | `default` | `{"number_of_rounds":20,"rotations":[16,12,8,7],"word_size":32}` | yes | 20 | 960 | `verified` | 2.154 | `verified` | 193.636 | 9.682 | 2/2 | — |
| `ChaskeyPi` | `standard-1` | `{"number_of_rounds":12,"word_size":32}` | yes | 12 | 168 | `verified` | 9.431 | `verified` | 944.600 | 78.717 | 2/2 | — |
| `Forro` | `standard-1` | `{"number_of_rounds":14}` | yes | 14 | 672 | `verified` | 74.818 | `verified` | 10340.772 | 738.627 | 2/2 | — |
| `Forro` | `standard-2` | `{"number_of_rounds":10}` | yes | 10 | 480 | `verified` | 63.664 | `verified` | 5306.521 | 530.652 | 2/2 | — |
| `Gaston` | `default` | `{"number_of_rounds":12}` | yes | 12 | 540 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_40]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_11_40] |
| `GastonSbox` | `standard-1` | `{"number_of_rounds":12}` | yes | 12 | 1128 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_18]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_11_18] |
| `GastonSboxTheta` | `standard-1` | `{"number_of_rounds":12}` | yes | 12 | 924 | `verified` | 3861.493 | `verified` | 49451.838 | 4120.986 | 2/2 | — |
| `Gimli` | `default` | `{"number_of_rounds":24,"word_size":32}` | yes | 24 | 1452 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_12]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_23_12] |
| `GimliSbox` | `standard-1` | `{"number_of_rounds":24,"word_size":32}` | yes | 24 | 4236 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_45]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_23_45] |
| `GrainCore` | `standard-1` | `{"number_of_rounds":160}` | yes | 160 | 160 | `verified` | 1.203 | `verified` | 496.379 | 3.102 | 2/2 | — |
| `Keccak` | `default` | `{"number_of_rounds":24,"word_size":64}` | yes | 24 | 3408 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_67]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_23_67] |
| `KeccakInvertible` | `default` | `{"number_of_rounds":24,"word_size":64}` | yes | 24 | 9288 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_15]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_23_15] |
| `KeccakSbox` | `standard-1` | `{"number_of_rounds":18,"word_size":8}` | yes | 18 | 1926 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_15]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_17_15] |
| `KeccakSbox` | `standard-2` | `{"number_of_rounds":16,"word_size":16}` | yes | 16 | 2352 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_15]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_15_15] |
| `KeccakSbox` | `standard-3` | `{"number_of_rounds":20,"word_size":16}` | yes | 20 | 2940 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_15]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_19_15] |
| `Knot` | `standard-1` | `{"number_of_rounds":52,"state_bit_size":256}` | yes | 52 | 3588 | `verified` | 13.815 | `verified` | 8818.701 | 169.590 | 2/2 | — |
| `Knot` | `standard-2` | `{"number_of_rounds":76,"state_bit_size":384}` | yes | 76 | 7676 | `verified` | 42.343 | `verified` | 29316.194 | 385.739 | 2/2 | — |
| `Knot` | `standard-3` | `{"number_of_rounds":100,"state_bit_size":512}` | yes | 100 | 13300 | `verified` | 23.075 | `verified` | 66261.457 | 662.615 | 2/2 | — |
| `Norx` | `standard-1` | `{"number_of_rounds":4,"word_size":32}` | yes | 4 | 768 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_100]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_3_100] |
| `Norx` | `standard-2` | `{"number_of_rounds":4,"word_size":64}` | yes | 4 | 768 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_100]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_3_100] |
| `Photon` | `standard-1` | `{"t":256}` | yes | 12 | 980 | `verified` | 42.602 | `verified` | 812.638 | 67.720 | 2/2 | — |
| `Salsa` | `default` | `{"number_of_rounds":20,"rotations":[7,9,13,18],"word_size":32}` | yes | 20 | 960 | `verified` | 1.800 | `verified` | 115.499 | 5.775 | 2/2 | — |
| `Sparkle` | `standard-1` | `{"number_of_blocks":4,"number_of_steps":7}` | yes | 7 | 659 | `verified` | 147.127 | `verified` | 6241.127 | 891.590 | 2/2 | — |
| `Sparkle` | `standard-2` | `{"number_of_blocks":4,"number_of_steps":10}` | yes | 10 | 938 | `verified` | 135.738 | `verified` | 12947.101 | 1294.710 | 2/2 | — |
| `Sparkle` | `standard-3` | `{"number_of_blocks":6,"number_of_steps":7}` | yes | 7 | 953 | `verified` | 205.379 | `verified` | 9122.354 | 1303.193 | 2/2 | — |
| `Sparkle` | `standard-4` | `{"number_of_blocks":6,"number_of_steps":11}` | yes | 11 | 1493 | `verified` | 206.369 | `verified` | 22107.626 | 2009.784 | 2/2 | — |
| `Sparkle` | `standard-5` | `{"number_of_blocks":8,"number_of_steps":8}` | yes | 8 | 1424 | `verified` | 282.416 | `verified` | 15761.572 | 1970.197 | 2/2 | — |
| `Sparkle` | `standard-6` | `{"number_of_blocks":8,"number_of_steps":12}` | yes | 12 | 2132 | `verified` | 304.046 | `verified` | 35511.740 | 2959.312 | 2/2 | — |
| `Speckey` | `standard-1` | `{"number_of_rounds":1}` | yes | 1 | 4 | `verified` | 1.813 | `verified` | 1.444 | 1.444 | 2/2 | — |
| `SpongentPi` | `default` | `{"number_of_rounds":80,"state_bit_size":160}` | yes | 80 | 2080 | `verified` | 10.186 | `verified` | 8245.937 | 103.074 | 2/2 | — |
| `SpongentPiFSR` | `default` | `{"number_of_rounds":80,"state_bit_size":160}` | yes | 80 | 2080 | `verified` | 11.280 | `verified` | 8213.678 | 102.671 | 2/2 | — |
| `SpongentPiPrecomputation` | `standard-1` | `{"number_of_rounds":80,"state_bit_size":160}` | yes | 80 | 2000 | `verified` | 3.791 | `verified` | 5611.527 | 70.144 | 2/2 | — |
| `SpongentPiPrecomputation` | `standard-2` | `{"number_of_rounds":90,"state_bit_size":176}` | yes | 90 | 2430 | `verified` | 10.164 | `verified` | 7438.842 | 82.654 | 2/2 | — |
| `Xoodoo` | `default` | `{"number_of_rounds":3}` | yes | 3 | 108 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_25]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_2_25] |
| `XoodooInvertible` | `default` | `{"number_of_rounds":12}` | yes | 12 | 1860 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_10]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_11_10] |
| `XoodooSbox` | `standard-1` | `{"number_of_rounds":12}` | yes | 12 | 1860 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_10]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_11_10] |

### single_component_primitives

| Primitive | Parameter set | Parameters | Obligation | Graph rounds | Components | 1-round outcome | 1-round ms | Full outcome | Full ms | ms/round | Semantic | Diagnostic |
|---|---|---|:---:|---:|---:|---|---:|---|---:|---:|:---:|---|
| `Add` | `default` | `{"domain":null,"number_of_inputs":2,"unit_count":1}` | no | 1 | 1 | `verified` | 0.185 | `verified` | 0.130 | 0.130 | 2/2 | — |
| `BinaryAffineMap` | `default` | `{"matrix":null,"offset":0,"unit_count":1,"word_size":4}` | yes | 1 | 1 | `verified` | 0.189 | `verified` | 0.129 | 0.129 | 2/2 | — |
| `BitVectorSBox` | `default` | `{"input_bit_size":4,"lookup_table":null,"output_bit_size":null}` | no | 1 | 1 | `verified` | 0.184 | `verified` | 0.125 | 0.125 | 2/2 | — |
| `BitwiseAnd` | `default` | `{"number_of_inputs":2,"word_bit_size":4}` | no | 1 | 1 | `not-supported: information_loss: bitwise AND is not bijective in an operand [bitwise_and_0_0]` | — | `not-supported` | — | — | — | information_loss: bitwise AND is not bijective in an operand [bitwise_and_0_0] |
| `BitwiseNot` | `default` | `{"bit_size":4}` | no | 1 | 1 | `verified` | 0.155 | `verified` | 0.106 | 0.106 | 2/2 | — |
| `BitwiseOr` | `default` | `{"number_of_inputs":2,"word_bit_size":4}` | no | 1 | 1 | `not-supported: information_loss: bitwise OR is not bijective in an operand [bitwise_or_0_0]` | — | `not-supported` | — | — | — | information_loss: bitwise OR is not bijective in an operand [bitwise_or_0_0] |
| `Constant` | `default` | `{"output_bit_size":3,"value":2}` | no | 1 | 1 | `inversion-error: IndexError: primitive input position 0 is out of range` | — | `inversion-error` | — | — | — | IndexError: primitive input position 0 is out of range |
| `FeedbackRegister` | `default` | `{"parameters":null}` | no | 1 | 1 | `not-supported: unsupported_component: feedback-register inversion requires an explicit reversible transition contract [feedback_register_0_0]` | — | `not-supported` | — | — | — | unsupported_component: feedback-register inversion requires an explicit reversible transition contract [feedback_register_0_0] |
| `IDEAMultiply` | `default` | `{"number_of_inputs":2,"word_bit_size":16}` | no | 1 | 1 | `not-supported: unsupported_component: IDEA multiplication needs its encoded-group inverse operation [i_d_e_a_multiply_0_0]` | — | `not-supported` | — | — | — | unsupported_component: IDEA multiplication needs its encoded-group inverse operation [i_d_e_a_multiply_0_0] |
| `Identity` | `default` | `{"bit_size":32}` | no | 1 | 1 | `verified` | 0.350 | `verified` | 0.245 | 0.245 | 2/2 | — |
| `LinearMap` | `default` | `{"domain":null,"matrix":null}` | no | 1 | 1 | `verified` | 0.212 | `verified` | 0.142 | 0.142 | 2/2 | — |
| `ModularAdd` | `default` | `{"number_of_inputs":2,"word_bit_size":4}` | no | 1 | 1 | `verified` | 0.215 | `verified` | 0.134 | 0.134 | 2/2 | — |
| `ModularMultiply` | `default` | `{"number_of_inputs":2,"word_bit_size":4}` | no | 1 | 1 | `not-supported: information_loss: modular multiplication is not bijective for every auxiliary [modular_multiply_0_0]` | — | `not-supported` | — | — | — | information_loss: modular multiplication is not bijective for every auxiliary [modular_multiply_0_0] |
| `ModularSubtract` | `default` | `{"number_of_inputs":2,"word_bit_size":4}` | no | 1 | 1 | `verified` | 0.195 | `verified` | 0.132 | 0.132 | 2/2 | — |
| `Multiply` | `default` | `{"domain":null,"number_of_inputs":2,"unit_count":1}` | no | 1 | 1 | `not-supported: information_loss: multiplication is not bijective when an auxiliary can be zero [multiply_0_0]` | — | `not-supported` | — | — | — | information_loss: multiplication is not bijective when an auxiliary can be zero [multiply_0_0] |
| `Permutation` | `default` | `{"mapping":null,"word_size":1}` | no | 1 | 1 | `verified` | 0.179 | `verified` | 0.131 | 0.131 | 2/2 | — |
| `Power` | `default` | `{"domain":null,"exponent":3,"unit_count":1}` | yes | 1 | 1 | `verified` | 0.168 | `verified` | 0.113 | 0.113 | 2/2 | — |
| `Rotate` | `default` | `{"amount":1,"bit_size":8,"direction":"right"}` | no | 1 | 1 | `verified` | 0.169 | `verified` | 0.108 | 0.108 | 2/2 | — |
| `SBox` | `default` | `{"domain":null,"lookup_table":null,"unit_count":1}` | yes | 1 | 1 | `verified` | 0.163 | `verified` | 0.112 | 0.112 | 2/2 | — |
| `Shift` | `default` | `{"amount":1,"bit_size":8,"direction":"right"}` | no | 1 | 1 | `not-supported: information_loss: fixed shifts discard bits [shift_0_0]` | — | `not-supported` | — | — | — | information_loss: fixed shifts discard bits [shift_0_0] |
| `VariableRotate` | `default` | `{"amount_bit_size":3,"bit_size":8,"direction":"right"}` | no | 1 | 1 | `verified` | 0.178 | `verified` | 0.130 | 0.130 | 2/2 | — |
| `VariableShift` | `default` | `{"amount_bit_size":3,"bit_size":8,"direction":"right"}` | no | 1 | 1 | `not-supported: information_loss: variable shifts can discard bits [variable_shift_0_0]` | — | `not-supported` | — | — | — | information_loss: variable shifts can discard bits [variable_shift_0_0] |
| `Xor` | `default` | `{"number_of_inputs":2,"word_bit_size":4}` | no | 1 | 1 | `verified` | 0.277 | `verified` | 0.140 | 0.140 | 2/2 | — |

### toy_primitives

| Primitive | Parameter set | Parameters | Obligation | Graph rounds | Components | 1-round outcome | 1-round ms | Full outcome | Full ms | ms/round | Semantic | Diagnostic |
|---|---|---|:---:|---:|---:|---|---:|---|---:|---:|:---:|---|
| `CipherFour` | `default` | `{"block_bit_size":16,"key_bit_size":16,"number_of_rounds":5,"permutations":null,"rotation_layer":1,"sbox":null}` | no | 5 | 30 | `construction-error: ValueError: position 64 is outside source 'key' with 32 logical units` | — | `verified` | 5.025 | 1.005 | 2/2 | — |
| `Fancy` | `default` | `{"block_bit_size":24,"key_bit_size":24,"number_of_rounds":20}` | no | 20 | 250 | `verified` | 3.092 | `not-supported` | — | — | — | information_loss: fixed shifts discard bits [shift_19_11] |
| `Heys` | `default` | `{"block_bit_size":16,"key_bit_size":80,"number_of_rounds":4}` | no | 4 | 24 | `verified` | 0.887 | `verified` | 3.617 | 0.904 | 2/2 | — |
| `ToyAES` | `default` | `{"number_of_rounds":10,"state_size":4,"word_size":8}` | no | 10 | 127 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [add_0_9]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [add_9_8] |
| `ToyFeistel` | `default` | `{"block_bit_size":8,"key_bit_size":8,"number_of_rounds":5,"sbox":[14,9,15,0,13,4,10,11,1,2,8,3,7,6,12,5]}` | no | 5 | 35 | `verified` | 0.947 | `verified` | 10.991 | 2.198 | 2/2 | — |
| `ToySPN1` | `default` | `{"block_bit_size":6,"key_bit_size":6,"number_of_rounds":2,"rotation_layer":1,"sbox":[0,5,3,2,6,1,4,7]}` | no | 2 | 8 | `verified` | 0.734 | `verified` | 0.818 | 0.409 | 2/2 | — |
| `ToySPN2` | `default` | `{"block_bit_size":6,"key_bit_size":6,"number_of_rounds":2,"rotation_layer":1,"round_key_rotation":1,"sbox":[0,5,3,2,6,1,4,7]}` | no | 2 | 10 | `verified` | 0.741 | `verified` | 0.879 | 0.439 | 2/2 | — |

### tweakable_block_ciphers

| Primitive | Parameter set | Parameters | Obligation | Graph rounds | Components | 1-round outcome | 1-round ms | Full outcome | Full ms | ms/round | Semantic | Diagnostic |
|---|---|---|:---:|---:|---:|---|---:|---|---:|---:|:---:|---|
| `BipBip` | `standard-1` | `{"number_of_core_rounds":5,"number_of_shell_rounds_1":3,"number_of_shell_rounds_2":3}` | yes | 12 | 179 | `unavailable` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_8_2] |
| `Blink` | `standard-1` | `{"a":2,"b":3,"block_bit_size":64,"key_bit_size":448,"tweak_bit_size":64}` | yes | 10 | 1162 | `unavailable` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_9_65] |
| `Blink` | `standard-2` | `{"a":2,"b":3,"block_bit_size":64,"key_bit_size":448,"tweak_bit_size":128}` | yes | 10 | 1162 | `unavailable` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_9_65] |
| `Blink` | `standard-3` | `{"a":3,"b":3,"block_bit_size":128,"key_bit_size":1024,"tweak_bit_size":128}` | yes | 12 | 2572 | `unavailable` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_11_129] |
| `Blink` | `standard-4` | `{"a":3,"b":3,"block_bit_size":128,"key_bit_size":1024,"tweak_bit_size":256}` | yes | 12 | 2572 | `unavailable` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_11_129] |
| `Blink` | `standard-5` | `{"a":3,"b":5,"block_bit_size":128,"key_bit_size":1280,"tweak_bit_size":128}` | yes | 16 | 3088 | `unavailable` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_15_129] |
| `Blink` | `standard-6` | `{"a":3,"b":5,"block_bit_size":128,"key_bit_size":1280,"tweak_bit_size":256}` | yes | 16 | 3088 | `unavailable` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_15_129] |
| `Chilow` | `default` | `{"number_of_rounds":1,"tau":null}` | yes | 1 | 16 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_13]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_13] |
| `Mantis` | `default` | `{"number_of_rounds":6}` | yes | 12 | 426 | `verified` | 99.659 | `verified` | 1055.843 | 87.987 | 2/2 | — |
| `QARMAv2` | `default` | `{"key_bit_size":128,"number_of_layers":1,"number_of_rounds":10,"tweak_bit_size":128}` | yes | 21 | 1197 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_2_64]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_20_64] |
| `QARMAv2MixColumn` | `standard-1` | `{"key_bit_size":128,"number_of_layers":1,"number_of_rounds":10,"tweak_bit_size":128}` | yes | 21 | 685 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_2_39]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_20_39] |
| `SCARF` | `default` | `{"number_of_rounds":8}` | yes | 8 | 188 | `not-supported: disconnected_dependency: known boundaries do not connect to every requested target wire [plaintext]` | — | `not-supported` | — | — | — | disconnected_dependency: known boundaries do not connect to every requested target wire [plaintext] |
| `Threefish` | `default` | `{"block_bit_size":256,"key_bit_size":null,"number_of_rounds":null,"tweak_bit_size":128}` | yes | 73 | 590 | `verified` | 1.242 | `verified` | 302.762 | 4.147 | 2/2 | — |
| `Trax` | `default` | `{"number_of_rounds":17}` | yes | 17 | 1876 | `verified` | 6.694 | `verified` | 971.379 | 57.140 | 2/2 | — |

## Reproduction

From `next/`:

```console
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3.11 tools/audit_primitive_inversion.py
```

The report is a point-in-time benchmark. Compare future methodology changes on the same machine, Python version, timeout, and repetition count.
