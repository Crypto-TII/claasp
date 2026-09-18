# Primitive inversion audit

Generated at 2026-09-18T15:52:47+00:00 from commit `83d85069` on macOS-26.3-x86_64-i386-64bit, Python 3.11.12.

## Scope and interpretation

This audit covers every public primitive and every named parameter set in the committed v5 catalogue, including toy and single-component primitives. The operation under test recovers the catalogue data/state input from the primitive output while retaining every other primitive input. For a primitive without a bijectivity obligation, the first input remains the explicitly qualified recovery target. Therefore, **verified** means that the current solver-free graph transformation constructed an inverse and recovered the original target input for two deterministic semantic samples. It does not mean that a multi-input primitive is globally bijective without retained inputs.

The catalogue's bijectivity obligation is reported independently. A `yes` is a specification/classification claim; a failed transformation on such a row identifies a methodology gap, not proof that the mathematical primitive is non-invertible. Conversely, a recoverable operand of XOR or modular addition may verify even when the whole multi-input function has no catalogue bijectivity obligation.

Inverse construction was measured 1 time(s) per successful configuration and the median is shown. Each attempt had a 30-second limit, with 4 isolated workers running concurrently. `1-round ms` is a separately constructed public configuration using `number_of_rounds=1` or `number_of_steps=1`; a one-graph-round primitive reuses its full measurement. `ms/round` is also supplied as the full construction time divided by immutable graph-round count. Construction of the forward graph and semantic evaluation are excluded from inversion timings.

## Summary

- Public primitives: **142**
- Official parameter sets checked: **234**
- Primitives with at least one verified configuration: **119**
- Primitives verified for every official configuration: **119**
- Configuration outcomes: **1 not-applicable**, **21 not-supported**, **5 timeout**, **207 verified**
- Catalogue-bijective configurations verified by the current transformation: **188/188**
- Configurations without a catalogue bijectivity obligation that still support first-input recovery with auxiliaries: **19/46**
- One-round outcomes: **5 construction-error**, **1 not-applicable**, **21 not-supported**, **13 unavailable**, **194 verified**

| Category | Primitives | Configurations | Verified | Not supported | Timed out | Other |
|---|---:|---:|---:|---:|---:|---:|
| `block_ciphers` | 61 | 132 | 132 | 0 | 0 | 0 |
| `block_functions` | 8 | 8 | 1 | 5 | 2 | 0 |
| `functions` | 7 | 11 | 0 | 8 | 3 | 0 |
| `permutations` | 27 | 39 | 39 | 0 | 0 | 0 |
| `single_component_primitives` | 23 | 23 | 16 | 6 | 0 | 1 |
| `toy_primitives` | 7 | 7 | 5 | 2 | 0 | 0 |
| `tweakable_block_ciphers` | 9 | 14 | 14 | 0 | 0 | 0 |

### Failure and stall diagnostics

| Diagnostic class | Configurations |
|---|---:|
| `information_loss` | 7 |
| `multiple_predecessors` | 14 |
| `not-applicable` | 1 |
| `timeout` | 5 |

### Slowest verified full inversions

| Primitive | Parameter set | Full ms | Graph rounds | ms/round |
|---|---|---:|---:|---:|
| `Blink` | `standard-6` | 21233.982 | 16 | 1327.124 |
| `Blink` | `standard-4` | 17845.616 | 12 | 1487.135 |
| `Keccak` | `default` | 14953.531 | 24 | 623.064 |
| `KeccakInvertible` | `default` | 14582.615 | 24 | 607.609 |
| `Blink` | `standard-5` | 14334.877 | 16 | 895.930 |
| `Blink` | `standard-3` | 10702.431 | 12 | 891.869 |
| `Norx` | `standard-2` | 6924.577 | 4 | 1731.144 |
| `Speedy` | `standard-1` | 4652.016 | 5 | 930.403 |
| `Blink` | `standard-2` | 4474.683 | 10 | 447.468 |
| `GimliSbox` | `standard-1` | 3051.598 | 24 | 127.150 |

## Methodology status

This report is the acceptance evidence for tracker slice `M10.10h`. Its catalogue completeness condition is that every configuration carrying a bijectivity obligation has status `verified`. At this checkpoint, **188/188** such configurations satisfy that condition.

Non-verified rows remain visible because the audit also probes first-input recovery for hashes, stream functions, lossy teaching components, and other primitives without a catalogue bijectivity obligation. They are qualified results, not gaps in the bijective coverage claim. Future optimization can use the slowest-results table to prioritize graph construction cost, but must retain the same solver-free contracts, typed failures, provenance, and independent semantic round trips.

## Configuration results

Times are milliseconds. Parameters are the exact values passed to the public constructor.

### block_ciphers

| Primitive | Parameter set | Parameters | Recover | Obligation | Graph rounds | Components | 1-round outcome | 1-round ms | Full outcome | Full ms | ms/round | Semantic | Diagnostic |
|---|---|---|---|:---:|---:|---:|---|---:|---|---:|---:|:---:|---|
| `AES` | `standard-1` | `{"key_bit_size":128,"number_of_rounds":10}` | `plaintext` | yes | 11 | 110 | `verified` | 5.761 | `verified` | 6.559 | 0.596 | 2/2 | — |
| `AES` | `standard-2` | `{"key_bit_size":192,"number_of_rounds":12}` | `plaintext` | yes | 13 | 118 | `verified` | 5.808 | `verified` | 7.537 | 0.580 | 2/2 | — |
| `AES` | `standard-3` | `{"key_bit_size":256,"number_of_rounds":14}` | `plaintext` | yes | 15 | 135 | `verified` | 5.494 | `verified` | 8.661 | 0.577 | 2/2 | — |
| `Aradi` | `default` | `{"number_of_rounds":16}` | `plaintext` | yes | 16 | 868 | `verified` | 38.002 | `verified` | 324.985 | 20.312 | 2/2 | — |
| `AradiSBox` | `standard-1` | `{"number_of_rounds":16}` | `plaintext` | yes | 16 | 1252 | `verified` | 20.197 | `verified` | 387.107 | 24.194 | 2/2 | — |
| `AradiSBoxCompactLinearMap` | `standard-1` | `{"number_of_rounds":16}` | `plaintext` | yes | 16 | 932 | `verified` | 15.774 | `verified` | 306.145 | 19.134 | 2/2 | — |
| `BEA1` | `standard-1` | `{"number_of_rounds":11}` | `plaintext` | yes | 11 | 442 | `verified` | 35.841 | `verified` | 109.913 | 9.992 | 2/2 | — |
| `Baksheesh` | `standard-1` | `{"block_bit_size":128,"key_bit_size":128,"number_of_rounds":35}` | `plaintext` | yes | 35 | 1296 | `verified` | 7.822 | `verified` | 203.348 | 5.810 | 2/2 | — |
| `Ballet` | `standard-1` | `{"block_bit_size":128,"key_bit_size":128,"number_of_rounds":46}` | `plaintext` | yes | 46 | 594 | `verified` | 3.916 | `verified` | 252.606 | 5.491 | 2/2 | — |
| `Ballet` | `standard-2` | `{"block_bit_size":128,"key_bit_size":256,"number_of_rounds":48}` | `plaintext` | yes | 48 | 808 | `verified` | 3.536 | `verified` | 390.747 | 8.141 | 2/2 | — |
| `Ballet` | `standard-3` | `{"block_bit_size":256,"key_bit_size":256,"number_of_rounds":74}` | `plaintext` | yes | 74 | 958 | `verified` | 12.647 | `verified` | 743.931 | 10.053 | 2/2 | — |
| `CHAM` | `default` | `{"block_bit_size":64,"key_bit_size":128,"number_of_rounds":null}` | `plaintext` | yes | 88 | 576 | `verified` | 1.554 | `verified` | 17.163 | 0.195 | 2/2 | — |
| `Cast` | `standard-1` | `{"key_bit_size":128,"number_of_rounds":16}` | `plaintext` | yes | 17 | 579 | `verified` | 84.481 | `verified` | 126.109 | 7.418 | 2/2 | — |
| `Cast` | `standard-2` | `{"key_bit_size":80,"number_of_rounds":12}` | `plaintext` | yes | 13 | 533 | `verified` | 76.957 | `verified` | 116.592 | 8.969 | 2/2 | — |
| `Cast` | `standard-3` | `{"key_bit_size":40,"number_of_rounds":12}` | `plaintext` | yes | 13 | 533 | `verified` | 79.973 | `verified` | 119.278 | 9.175 | 2/2 | — |
| `DES` | `default` | `{"number_of_rounds":16,"number_of_sboxes":8}` | `plaintext` | yes | 16 | 244 | `verified` | 4.265 | `verified` | 41.931 | 2.621 | 2/2 | — |
| `DESExactKeyLength` | `standard-1` | `{"number_of_rounds":16,"number_of_sboxes":8}` | `plaintext` | yes | 16 | 244 | `verified` | 3.873 | `verified` | 44.167 | 2.760 | 2/2 | — |
| `Gift` | `default` | `{"block_bit_size":128,"number_of_rounds":null}` | `plaintext` | yes | 40 | 678 | `verified` | 13.993 | `verified` | 374.658 | 9.366 | 2/2 | — |
| `GiftSbox` | `standard-1` | `{"block_bit_size":64,"number_of_rounds":28}` | `plaintext` | yes | 28 | 726 | `verified` | 3.707 | `verified` | 103.519 | 3.697 | 2/2 | — |
| `GiftSbox` | `standard-2` | `{"block_bit_size":128,"number_of_rounds":40}` | `plaintext` | yes | 40 | 1678 | `verified` | 5.337 | `verified` | 367.042 | 9.176 | 2/2 | — |
| `Gost` | `standard-1` | `{"block_bit_size":64,"key_bit_size":256,"number_of_rounds":32}` | `plaintext` | yes | 32 | 352 | `verified` | 2.706 | `verified` | 81.286 | 2.540 | 2/2 | — |
| `HIGHT` | `default` | `{"block_bit_size":64,"key_bit_size":128,"number_of_rounds":null,"sub_keys_zero":false,"transformations_flag":true}` | `plaintext` | yes | 32 | 1032 | `verified` | 1.762 | `verified` | 30.764 | 0.961 | 2/2 | — |
| `IDEA` | `default` | `{"number_of_rounds":8}` | `plaintext` | yes | 10 | 122 | `verified` | 4.604 | `verified` | 39.547 | 3.955 | 2/2 | — |
| `Kalyna` | `default` | `{"number_of_rounds":10}` | `plaintext` | yes | 11 | 560 | `construction-error: KeyError: 1` | — | `verified` | 146.413 | 13.310 | 2/2 | — |
| `Kasumi` | `standard-1` | `{"block_bit_size":64,"key_bit_size":128,"number_of_rounds":8}` | `plaintext` | yes | 8 | 674 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_80]` | — | `verified` | 107.659 | 13.457 | 2/2 | — |
| `Katan` | `default` | `{"block_bit_size":32,"ir_mode":"strict","key_bit_size":80,"number_of_rounds":null}` | `plaintext` | yes | 254 | 1699 | `verified` | 1.696 | `verified` | 490.095 | 1.930 | 2/2 | — |
| `KatanFSR` | `standard-1` | `{"block_bit_size":32,"key_bit_size":80,"number_of_rounds":254}` | `plaintext` | yes | 254 | 1698 | `verified` | 1.896 | `verified` | 630.505 | 2.482 | 2/2 | — |
| `KatanFSR` | `standard-2` | `{"block_bit_size":48,"key_bit_size":80,"number_of_rounds":254}` | `plaintext` | yes | 254 | 2968 | `verified` | 2.454 | `verified` | 1417.128 | 5.579 | 2/2 | — |
| `KatanFSR` | `standard-3` | `{"block_bit_size":64,"key_bit_size":80,"number_of_rounds":254}` | `plaintext` | yes | 254 | 4238 | `verified` | 3.677 | `verified` | 2708.276 | 10.663 | 2/2 | — |
| `Ktantan` | `default` | `{"block_bit_size":32,"ir_mode":"strict","key_bit_size":80,"number_of_rounds":null}` | `plaintext` | yes | 254 | 1271 | `verified` | 1.850 | `verified` | 426.697 | 1.680 | 2/2 | — |
| `KtantanFSR` | `standard-1` | `{"block_bit_size":32,"key_bit_size":80,"number_of_rounds":254}` | `plaintext` | yes | 254 | 1270 | `verified` | 3.122 | `verified` | 428.063 | 1.685 | 2/2 | — |
| `KtantanFSR` | `standard-2` | `{"block_bit_size":48,"key_bit_size":80,"number_of_rounds":254}` | `plaintext` | yes | 254 | 2540 | `verified` | 2.525 | `verified` | 1314.690 | 5.176 | 2/2 | — |
| `KtantanFSR` | `standard-3` | `{"block_bit_size":64,"key_bit_size":80,"number_of_rounds":254}` | `plaintext` | yes | 254 | 3810 | `verified` | 6.011 | `verified` | 2058.406 | 8.104 | 2/2 | — |
| `LBlock` | `standard-1` | `{"number_of_rounds":32}` | `plaintext` | yes | 32 | 512 | `verified` | 3.661 | `verified` | 92.845 | 2.901 | 2/2 | — |
| `LEA` | `default` | `{"block_bit_size":128,"key_bit_size":192,"number_of_rounds":null,"reorder_input_and_output":true}` | `plaintext` | yes | 28 | 1022 | `verified` | 4.414 | `verified` | 45.085 | 1.610 | 2/2 | — |
| `Led` | `standard-1` | `{"key_bit_size":64,"number_of_rounds":32}` | `plaintext` | yes | 8 | 713 | `construction-error: AssertionError: Number of rounds must be a multiple of 4.` | — | `verified` | 81.881 | 10.235 | 2/2 | — |
| `Led` | `standard-2` | `{"key_bit_size":128,"number_of_rounds":48}` | `plaintext` | yes | 12 | 1069 | `construction-error: AssertionError: Number of rounds must be a multiple of 4.` | — | `verified` | 118.122 | 9.843 | 2/2 | — |
| `LowMC` | `default` | `{"block_bit_size":128,"key_bit_size":128,"number_of_rounds":null,"number_of_sboxes":null}` | `plaintext` | yes | 20 | 302 | `construction-error: ValueError: No available number of sboxes for the given parameters.` | — | `verified` | 207.864 | 10.393 | 2/2 | — |
| `MSX` | `standard-1` | `{"block_bit_size":64,"key_bit_size":128,"number_of_rounds":14}` | `plaintext` | yes | 14 | 310 | `verified` | 11.574 | `verified` | 107.871 | 7.705 | 2/2 | — |
| `MSX` | `standard-2` | `{"block_bit_size":128,"key_bit_size":128,"number_of_rounds":18}` | `plaintext` | yes | 18 | 752 | `verified` | 25.579 | `verified` | 262.879 | 14.604 | 2/2 | — |
| `MSX` | `standard-3` | `{"block_bit_size":128,"key_bit_size":256,"number_of_rounds":18}` | `plaintext` | yes | 18 | 756 | `verified` | 28.224 | `verified` | 266.784 | 14.821 | 2/2 | — |
| `Midori` | `standard-1` | `{"block_bit_size":64,"key_bit_size":128,"number_of_rounds":16}` | `plaintext` | yes | 16 | 379 | `verified` | 3.417 | `verified` | 49.236 | 3.077 | 2/2 | — |
| `Midori` | `standard-2` | `{"block_bit_size":128,"key_bit_size":128,"number_of_rounds":20}` | `plaintext` | yes | 20 | 1434 | `verified` | 6.444 | `verified` | 169.824 | 8.491 | 2/2 | — |
| `Piccolo` | `standard-1` | `{"key_bit_size":80,"number_of_rounds":25}` | `plaintext` | yes | 25 | 628 | `verified` | 3.928 | `verified` | 66.175 | 2.647 | 2/2 | — |
| `Piccolo` | `standard-2` | `{"key_bit_size":128,"number_of_rounds":31}` | `plaintext` | yes | 31 | 778 | `verified` | 3.944 | `verified` | 83.109 | 2.681 | 2/2 | — |
| `Present` | `default` | `{"key_bit_size":80,"number_of_rounds":31}` | `plaintext` | yes | 31 | 683 | `verified` | 3.019 | `verified` | 64.781 | 2.090 | 2/2 | — |
| `Prince` | `default` | `{"number_of_rounds":12}` | `plaintext` | yes | 11 | 254 | `verified` | 8.326 | `verified` | 54.226 | 4.930 | 2/2 | — |
| `PrinceV2` | `default` | `{"number_of_rounds":12}` | `plaintext` | yes | 11 | 254 | `verified` | 10.069 | `verified` | 51.451 | 4.677 | 2/2 | — |
| `RC5` | `default` | `{"key_size":64,"number_of_rounds":16,"word_size":16}` | `plaintext` | yes | 17 | 645 | `verified` | 4.483 | `verified` | 41.910 | 2.465 | 2/2 | — |
| `Raiden` | `default` | `{"block_bit_size":64,"key_bit_size":128,"left_shift_amount":9,"number_of_rounds":null,"right_shift_amount":14}` | `plaintext` | yes | 16 | 288 | `verified` | 0.739 | `verified` | 8.394 | 0.525 | 2/2 | — |
| `Rectangle` | `standard-1` | `{"key_bit_size":80,"number_of_rounds":25}` | `plaintext` | yes | 25 | 751 | `verified` | 5.295 | `verified` | 133.883 | 5.355 | 2/2 | — |
| `Rectangle` | `standard-2` | `{"key_bit_size":128,"number_of_rounds":25}` | `plaintext` | yes | 25 | 851 | `verified` | 6.149 | `verified` | 164.463 | 6.579 | 2/2 | — |
| `Rijndael` | `standard-1` | `{"block_bit_size":128,"key_bit_size":128,"number_of_rounds":10}` | `plaintext` | yes | 10 | 317 | `verified` | 8.141 | `verified` | 84.390 | 8.439 | 2/2 | — |
| `Rijndael` | `standard-10` | `{"block_bit_size":160,"key_bit_size":256,"number_of_rounds":14}` | `plaintext` | yes | 14 | 522 | `verified` | 10.495 | `verified` | 168.369 | 12.026 | 2/2 | — |
| `Rijndael` | `standard-11` | `{"block_bit_size":192,"key_bit_size":128,"number_of_rounds":12}` | `plaintext` | yes | 12 | 574 | `verified` | 24.282 | `verified` | 193.759 | 16.147 | 2/2 | — |
| `Rijndael` | `standard-12` | `{"block_bit_size":192,"key_bit_size":160,"number_of_rounds":12}` | `plaintext` | yes | 12 | 545 | `verified` | 14.244 | `verified` | 165.625 | 13.802 | 2/2 | — |
| `Rijndael` | `standard-13` | `{"block_bit_size":192,"key_bit_size":192,"number_of_rounds":12}` | `plaintext` | yes | 12 | 523 | `verified` | 11.705 | `verified` | 156.442 | 13.037 | 2/2 | — |
| `Rijndael` | `standard-14` | `{"block_bit_size":192,"key_bit_size":224,"number_of_rounds":13}` | `plaintext` | yes | 13 | 596 | `verified` | 13.015 | `verified` | 173.411 | 13.339 | 2/2 | — |
| `Rijndael` | `standard-15` | `{"block_bit_size":192,"key_bit_size":256,"number_of_rounds":14}` | `plaintext` | yes | 14 | 628 | `verified` | 10.918 | `verified` | 188.695 | 13.478 | 2/2 | — |
| `Rijndael` | `standard-16` | `{"block_bit_size":224,"key_bit_size":128,"number_of_rounds":13}` | `plaintext` | yes | 13 | 724 | `verified` | 22.364 | `verified` | 245.658 | 18.897 | 2/2 | — |
| `Rijndael` | `standard-17` | `{"block_bit_size":224,"key_bit_size":160,"number_of_rounds":13}` | `plaintext` | yes | 13 | 688 | `verified` | 15.613 | `verified` | 257.244 | 19.788 | 2/2 | — |
| `Rijndael` | `standard-18` | `{"block_bit_size":224,"key_bit_size":192,"number_of_rounds":13}` | `plaintext` | yes | 13 | 666 | `verified` | 20.794 | `verified` | 241.905 | 18.608 | 2/2 | — |
| `Rijndael` | `standard-19` | `{"block_bit_size":224,"key_bit_size":224,"number_of_rounds":13}` | `plaintext` | yes | 13 | 696 | `verified` | 14.379 | `verified` | 238.761 | 18.366 | 2/2 | — |
| `Rijndael` | `standard-2` | `{"block_bit_size":128,"key_bit_size":160,"number_of_rounds":11}` | `plaintext` | yes | 11 | 334 | `verified` | 7.709 | `verified` | 89.780 | 8.162 | 2/2 | — |
| `Rijndael` | `standard-20` | `{"block_bit_size":224,"key_bit_size":256,"number_of_rounds":14}` | `plaintext` | yes | 14 | 734 | `verified` | 15.218 | `verified` | 256.972 | 18.355 | 2/2 | — |
| `Rijndael` | `standard-21` | `{"block_bit_size":256,"key_bit_size":128,"number_of_rounds":14}` | `plaintext` | yes | 14 | 886 | `verified` | 28.577 | `verified` | 287.644 | 20.546 | 2/2 | — |
| `Rijndael` | `standard-22` | `{"block_bit_size":256,"key_bit_size":160,"number_of_rounds":14}` | `plaintext` | yes | 14 | 843 | `verified` | 28.431 | `verified` | 281.720 | 20.123 | 2/2 | — |
| `Rijndael` | `standard-23` | `{"block_bit_size":256,"key_bit_size":192,"number_of_rounds":14}` | `plaintext` | yes | 14 | 814 | `verified` | 23.738 | `verified` | 257.266 | 18.376 | 2/2 | — |
| `Rijndael` | `standard-24` | `{"block_bit_size":256,"key_bit_size":224,"number_of_rounds":14}` | `plaintext` | yes | 14 | 863 | `verified` | 23.644 | `verified` | 253.630 | 18.116 | 2/2 | — |
| `Rijndael` | `standard-25` | `{"block_bit_size":256,"key_bit_size":256,"number_of_rounds":14}` | `plaintext` | yes | 14 | 833 | `verified` | 22.520 | `verified` | 255.523 | 18.252 | 2/2 | — |
| `Rijndael` | `standard-3` | `{"block_bit_size":128,"key_bit_size":192,"number_of_rounds":12}` | `plaintext` | yes | 12 | 351 | `verified` | 7.373 | `verified` | 96.203 | 8.017 | 2/2 | — |
| `Rijndael` | `standard-4` | `{"block_bit_size":128,"key_bit_size":224,"number_of_rounds":13}` | `plaintext` | yes | 13 | 396 | `verified` | 6.814 | `verified` | 110.516 | 8.501 | 2/2 | — |
| `Rijndael` | `standard-5` | `{"block_bit_size":128,"key_bit_size":256,"number_of_rounds":14}` | `plaintext` | yes | 14 | 416 | `verified` | 6.615 | `verified` | 144.042 | 10.289 | 2/2 | — |
| `Rijndael` | `standard-6` | `{"block_bit_size":160,"key_bit_size":128,"number_of_rounds":11}` | `plaintext` | yes | 11 | 436 | `verified` | 12.034 | `verified` | 149.489 | 13.590 | 2/2 | — |
| `Rijndael` | `standard-7` | `{"block_bit_size":160,"key_bit_size":160,"number_of_rounds":11}` | `plaintext` | yes | 11 | 414 | `verified` | 11.450 | `verified` | 161.942 | 14.722 | 2/2 | — |
| `Rijndael` | `standard-8` | `{"block_bit_size":160,"key_bit_size":192,"number_of_rounds":12}` | `plaintext` | yes | 12 | 437 | `verified` | 17.530 | `verified` | 168.052 | 14.004 | 2/2 | — |
| `Rijndael` | `standard-9` | `{"block_bit_size":160,"key_bit_size":224,"number_of_rounds":13}` | `plaintext` | yes | 13 | 496 | `verified` | 10.664 | `verified` | 166.822 | 12.832 | 2/2 | — |
| `SM4` | `default` | `{"number_of_rounds":32,"state_size":8,"word_size":8}` | `plaintext` | yes | 32 | 936 | `verified` | 14.452 | `verified` | 236.697 | 7.397 | 2/2 | — |
| `SPARX` | `default` | `{"block_bit_size":64,"key_bit_size":128,"number_of_rounds":null,"steps":null}` | `plaintext` | yes | 8 | 394 | `verified` | 6.193 | `verified` | 51.424 | 6.428 | 2/2 | — |
| `Saecham` | `standard-1` | `{"number_of_rounds":88}` | `plaintext` | yes | 88 | 576 | `verified` | 9.731 | `verified` | 139.519 | 1.585 | 2/2 | — |
| `Serpent` | `standard-1` | `{"key_bit_size":128,"number_of_rounds":32}` | `plaintext` | yes | 32 | 3017 | `verified` | 113.717 | `verified` | 731.957 | 22.874 | 2/2 | — |
| `Serpent` | `standard-2` | `{"key_bit_size":192,"number_of_rounds":32}` | `plaintext` | yes | 32 | 3015 | `verified` | 114.375 | `verified` | 725.768 | 22.680 | 2/2 | — |
| `Serpent` | `standard-3` | `{"key_bit_size":256,"number_of_rounds":32}` | `plaintext` | yes | 32 | 3013 | `verified` | 116.403 | `verified` | 726.919 | 22.716 | 2/2 | — |
| `Simeck` | `default` | `{"block_bit_size":32,"key_bit_size":64,"number_of_rounds":null,"rotation_amounts":[-5,-1]}` | `plaintext` | yes | 32 | 346 | `verified` | 0.342 | `verified` | 10.131 | 0.317 | 2/2 | — |
| `SimeckSbox` | `standard-1` | `{"block_bit_size":32,"key_bit_size":64,"number_of_rounds":32}` | `plaintext` | yes | 32 | 283 | `verified` | 1.397 | `verified` | 55.449 | 1.733 | 2/2 | — |
| `SimeckSbox` | `standard-2` | `{"block_bit_size":48,"key_bit_size":96,"number_of_rounds":36}` | `plaintext` | yes | 36 | 390 | `verified` | 1.676 | `verified` | 79.161 | 2.199 | 2/2 | — |
| `SimeckSbox` | `standard-3` | `{"block_bit_size":64,"key_bit_size":128,"number_of_rounds":44}` | `plaintext` | yes | 44 | 565 | `verified` | 2.093 | `verified` | 131.035 | 2.978 | 2/2 | — |
| `Simon` | `default` | `{"block_bit_size":32,"key_bit_size":64,"number_of_rounds":null}` | `plaintext` | yes | 32 | 332 | `verified` | 0.374 | `verified` | 9.718 | 0.304 | 2/2 | — |
| `SimonSbox` | `standard-1` | `{"block_bit_size":32,"key_bit_size":64,"number_of_rounds":32}` | `plaintext` | yes | 32 | 240 | `verified` | 1.515 | `verified` | 55.208 | 1.725 | 2/2 | — |
| `SimonSbox` | `standard-10` | `{"block_bit_size":128,"key_bit_size":256,"number_of_rounds":72}` | `plaintext` | yes | 72 | 992 | `verified` | 9.629 | `verified` | 380.838 | 5.289 | 2/2 | — |
| `SimonSbox` | `standard-2` | `{"block_bit_size":48,"key_bit_size":72,"number_of_rounds":36}` | `plaintext` | yes | 36 | 279 | `verified` | 1.849 | `verified` | 69.744 | 1.937 | 2/2 | — |
| `SimonSbox` | `standard-3` | `{"block_bit_size":48,"key_bit_size":96,"number_of_rounds":36}` | `plaintext` | yes | 36 | 308 | `verified` | 1.850 | `verified` | 77.522 | 2.153 | 2/2 | — |
| `SimonSbox` | `standard-4` | `{"block_bit_size":64,"key_bit_size":96,"number_of_rounds":42}` | `plaintext` | yes | 42 | 369 | `verified` | 2.451 | `verified` | 109.253 | 2.601 | 2/2 | — |
| `SimonSbox` | `standard-5` | `{"block_bit_size":64,"key_bit_size":128,"number_of_rounds":44}` | `plaintext` | yes | 44 | 424 | `verified` | 2.250 | `verified` | 129.892 | 2.952 | 2/2 | — |
| `SimonSbox` | `standard-6` | `{"block_bit_size":96,"key_bit_size":96,"number_of_rounds":52}` | `plaintext` | yes | 52 | 566 | `verified` | 3.279 | `verified` | 192.759 | 3.707 | 2/2 | — |
| `SimonSbox` | `standard-7` | `{"block_bit_size":96,"key_bit_size":144,"number_of_rounds":54}` | `plaintext` | yes | 54 | 585 | `verified` | 3.214 | `verified` | 197.327 | 3.654 | 2/2 | — |
| `SimonSbox` | `standard-8` | `{"block_bit_size":128,"key_bit_size":128,"number_of_rounds":68}` | `plaintext` | yes | 68 | 878 | `verified` | 3.872 | `verified` | 344.270 | 5.063 | 2/2 | — |
| `SimonSbox` | `standard-9` | `{"block_bit_size":128,"key_bit_size":192,"number_of_rounds":69}` | `plaintext` | yes | 69 | 888 | `verified` | 9.484 | `verified` | 334.488 | 4.848 | 2/2 | — |
| `Skinny` | `standard-1` | `{"block_bit_size":64,"key_bit_size":64,"number_of_rounds":32}` | `plaintext` | yes | 32 | 1313 | `verified` | 5.521 | `verified` | 174.087 | 5.440 | 2/2 | — |
| `Skinny` | `standard-2` | `{"block_bit_size":64,"key_bit_size":128,"number_of_rounds":36}` | `plaintext` | yes | 36 | 2045 | `verified` | 6.491 | `verified` | 271.826 | 7.551 | 2/2 | — |
| `Skinny` | `standard-3` | `{"block_bit_size":64,"key_bit_size":192,"number_of_rounds":40}` | `plaintext` | yes | 40 | 2905 | `verified` | 7.566 | `verified` | 429.009 | 10.725 | 2/2 | — |
| `Skinny` | `standard-4` | `{"block_bit_size":128,"key_bit_size":128,"number_of_rounds":40}` | `plaintext` | yes | 40 | 1641 | `verified` | 6.895 | `verified` | 353.501 | 8.838 | 2/2 | — |
| `Skinny` | `standard-5` | `{"block_bit_size":128,"key_bit_size":256,"number_of_rounds":48}` | `plaintext` | yes | 48 | 2729 | `verified` | 8.952 | `verified` | 558.381 | 11.633 | 2/2 | — |
| `Skinny` | `standard-6` | `{"block_bit_size":128,"key_bit_size":384,"number_of_rounds":56}` | `plaintext` | yes | 56 | 4073 | `verified` | 9.736 | `verified` | 804.539 | 14.367 | 2/2 | — |
| `Skipjack` | `default` | `{"number_of_rounds":32}` | `plaintext` | yes | 32 | 464 | `verified` | 2.642 | `verified` | 84.060 | 2.627 | 2/2 | — |
| `Speck` | `standard-1` | `{"block_bit_size":32,"key_bit_size":64,"number_of_rounds":22}` | `plaintext` | yes | 22 | 236 | `verified` | 0.408 | `verified` | 6.943 | 0.316 | 2/2 | — |
| `Speck` | `standard-10` | `{"block_bit_size":128,"key_bit_size":256,"number_of_rounds":34}` | `plaintext` | yes | 34 | 368 | `verified` | 0.401 | `verified` | 10.659 | 0.314 | 2/2 | — |
| `Speck` | `standard-2` | `{"block_bit_size":48,"key_bit_size":72,"number_of_rounds":22}` | `plaintext` | yes | 22 | 236 | `verified` | 0.395 | `verified` | 7.011 | 0.319 | 2/2 | — |
| `Speck` | `standard-3` | `{"block_bit_size":48,"key_bit_size":96,"number_of_rounds":23}` | `plaintext` | yes | 23 | 247 | `verified` | 1.061 | `verified` | 11.349 | 0.493 | 2/2 | — |
| `Speck` | `standard-4` | `{"block_bit_size":64,"key_bit_size":96,"number_of_rounds":26}` | `plaintext` | yes | 26 | 280 | `verified` | 1.021 | `verified` | 10.817 | 0.416 | 2/2 | — |
| `Speck` | `standard-5` | `{"block_bit_size":64,"key_bit_size":128,"number_of_rounds":27}` | `plaintext` | yes | 27 | 291 | `verified` | 0.485 | `verified` | 9.028 | 0.334 | 2/2 | — |
| `Speck` | `standard-6` | `{"block_bit_size":96,"key_bit_size":96,"number_of_rounds":28}` | `plaintext` | yes | 28 | 302 | `verified` | 0.507 | `verified` | 9.388 | 0.335 | 2/2 | — |
| `Speck` | `standard-7` | `{"block_bit_size":96,"key_bit_size":144,"number_of_rounds":29}` | `plaintext` | yes | 29 | 313 | `verified` | 0.523 | `verified` | 9.885 | 0.341 | 2/2 | — |
| `Speck` | `standard-8` | `{"block_bit_size":128,"key_bit_size":128,"number_of_rounds":32}` | `plaintext` | yes | 32 | 346 | `verified` | 0.423 | `verified` | 10.254 | 0.320 | 2/2 | — |
| `Speck` | `standard-9` | `{"block_bit_size":128,"key_bit_size":192,"number_of_rounds":33}` | `plaintext` | yes | 33 | 357 | `verified` | 0.395 | `verified` | 10.441 | 0.316 | 2/2 | — |
| `Speedy` | `standard-1` | `{"block_bit_size":192,"key_bit_size":192,"number_of_rounds":5}` | `plaintext` | yes | 5 | 521 | `verified` | 11.416 | `verified` | 4652.016 | 930.403 | 2/2 | — |
| `Splight` | `standard-1` | `{"block_bit_size":64,"key_bit_size":128,"number_of_rounds":32}` | `plaintext` | yes | 32 | 864 | `verified` | 4.114 | `verified` | 119.266 | 3.727 | 2/2 | — |
| `Subterranean` | `default` | `{"number_of_rounds":1}` | `plaintext` | yes | 1 | 11 | `verified` | 62.401 | `verified` | 29.989 | 29.989 | 2/2 | — |
| `TEA` | `default` | `{"block_bit_size":64,"key_bit_size":128,"left_shift_amount":4,"number_of_rounds":null,"right_shift_amount":5}` | `plaintext` | yes | 32 | 480 | `verified` | 0.671 | `verified` | 15.304 | 0.478 | 2/2 | — |
| `TinyJambu` | `default` | `{"key_bit_size":128,"number_of_rounds":640}` | `plaintext` | yes | 640 | 1920 | `verified` | 2.951 | `verified` | 1363.754 | 2.131 | 2/2 | — |
| `TinyJambuFSRWordBased` | `standard-1` | `{"key_bit_size":128,"number_of_rounds":640}` | `plaintext` | yes | 20 | 60 | `not-supported: ambiguous_boundary: primitive has no declared output` | — | `verified` | 66.641 | 3.332 | 2/2 | — |
| `TinyJambuWordBased` | `standard-1` | `{"key_bit_size":128,"number_of_rounds":640}` | `plaintext` | yes | 20 | 60 | `not-supported: ambiguous_boundary: primitive has no declared output` | — | `verified` | 59.120 | 2.956 | 2/2 | — |
| `Twine` | `standard-1` | `{"key_bit_size":80,"number_of_rounds":36}` | `plaintext` | yes | 36 | 900 | `verified` | 4.029 | `verified` | 180.159 | 5.004 | 2/2 | — |
| `Twine` | `standard-2` | `{"key_bit_size":128,"number_of_rounds":36}` | `plaintext` | yes | 36 | 972 | `verified` | 4.311 | `verified` | 184.671 | 5.130 | 2/2 | — |
| `Twofish` | `standard-1` | `{"key_length":128,"number_of_rounds":16}` | `plaintext` | yes | 16 | 1303 | `verified` | 36.643 | `verified` | 226.148 | 14.134 | 2/2 | — |
| `UKNIT` | `standard-1` | `{"number_of_rounds":12}` | `plaintext` | yes | 13 | 283 | `verified` | 4.655 | `verified` | 62.855 | 4.835 | 2/2 | — |
| `Ublock` | `default` | `{"block_bit_size":128,"key_bit_size":128,"number_of_rounds":null}` | `plaintext` | yes | 16 | 1121 | `verified` | 12.923 | `verified` | 243.660 | 15.229 | 2/2 | — |
| `UblockSingleLinearLayer` | `standard-1` | `{"block_bit_size":128,"key_bit_size":128,"number_of_rounds":16}` | `plaintext` | yes | 16 | 881 | `verified` | 13.668 | `verified` | 141.947 | 8.872 | 2/2 | — |
| `UblockSingleLinearLayer` | `standard-2` | `{"block_bit_size":128,"key_bit_size":256,"number_of_rounds":24}` | `plaintext` | yes | 24 | 1705 | `verified` | 18.021 | `verified` | 243.433 | 10.143 | 2/2 | — |
| `UblockSingleLinearLayer` | `standard-3` | `{"block_bit_size":256,"key_bit_size":256,"number_of_rounds":24}` | `plaintext` | yes | 24 | 2473 | `verified` | 35.770 | `verified` | 500.069 | 20.836 | 2/2 | — |
| `Warp` | `default` | `{"number_of_rounds":41}` | `plaintext` | yes | 41 | 1516 | `verified` | 5.509 | `verified` | 237.573 | 5.794 | 2/2 | — |
| `XTEA` | `default` | `{"block_bit_size":64,"key_bit_size":128,"left_shift_amount":4,"number_of_rounds":null,"right_shift_amount":5}` | `plaintext` | yes | 32 | 512 | `verified` | 0.715 | `verified` | 15.879 | 0.496 | 2/2 | — |

### block_functions

| Primitive | Parameter set | Parameters | Recover | Obligation | Graph rounds | Components | 1-round outcome | 1-round ms | Full outcome | Full ms | ms/round | Semantic | Diagnostic |
|---|---|---|---|:---:|---:|---:|---|---:|---|---:|---:|:---:|---|
| `A51` | `standard-1` | `{"frame_bit_size":22,"key_bit_size":64,"number_of_normal_clocks_at_initialization":100,"number_of_rounds":228}` | `key` | no | 229 | 633 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_1_1]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_1_1] |
| `A52` | `standard-1` | `{"frame_bit_size":22,"key_bit_size":64,"number_of_normal_clocks_at_initialization":100,"number_of_rounds":228}` | `key` | no | 229 | 2688 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_189]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_189] |
| `Bivium` | `standard-1` | `{"iv_bit_size":80,"key_bit_size":80,"keystream_bit_len":256,"number_of_initialization_clocks":708,"state_bit_size":177}` | `key` | no | 257 | 515 | `unavailable` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_256_0] |
| `ChaChaKeystreamBlock` | `standard-1` | `{"block_bit_size":512,"key_bit_size":256,"number_of_rounds":20}` | `plaintext` | no | 41 | 978 | `verified` | 9.102 | `verified` | 47.819 | 1.166 | 2/2 | — |
| `SiphashMAC` | `standard-1` | `{"compression_rounds":2,"finalization_rounds":4,"message_byte_size":15,"output_bit_size":64}` | `input_message` | no | 9 | 131 | `unavailable` | — | `timeout` | — | — | — | inverse construction exceeded 30 s |
| `Snow3G` | `standard-1` | `{"iv_bit_size":128,"key_bit_size":128,"keystream_word_size":2,"number_of_initialization_clocks":32}` | `key` | no | 35 | 24651 | `unavailable` | — | `timeout` | — | — | — | inverse construction exceeded 30 s |
| `Trivium` | `default` | `{"keystream_bit_size":64,"number_of_initialization_clocks":1152}` | `key` | no | 1217 | 7362 | `unavailable` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_1153_0] |
| `Zuc` | `standard-1` | `{"iv_bit_size":128,"key_bit_size":128,"len_keystream_word":1,"number_of_initialization_clocks":32}` | `key` | no | 2 | 1035 | `unavailable` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_1_22] |

### functions

| Primitive | Parameter set | Parameters | Recover | Obligation | Graph rounds | Components | 1-round outcome | 1-round ms | Full outcome | Full ms | ms/round | Semantic | Diagnostic |
|---|---|---|---|:---:|---:|---:|---|---:|---|---:|---:|:---:|---|
| `Blake` | `standard-1` | `{"block_bit_size":512,"number_of_rounds":28,"state_bit_size":512}` | `input_message` | no | 28 | 2016 | `not-supported: disconnected_dependency: known boundaries do not connect to every requested target wire [input_message]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [modadd_27_12] |
| `Blake` | `standard-2` | `{"block_bit_size":1024,"number_of_rounds":32,"state_bit_size":1024,"word_size":64}` | `input_message` | no | 32 | 2304 | `not-supported: disconnected_dependency: known boundaries do not connect to every requested target wire [input_message]` | — | `timeout` | — | — | — | inverse construction exceeded 30 s |
| `Blake2` | `standard-1` | `{"block_bit_size":1024,"number_of_rounds":12,"state_bit_size":1024}` | `input_message` | no | 12 | 1152 | `verified` | 76.426 | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [modadd_11_90] |
| `BluetoothE0` | `standard-1` | `{"fsm_bit_size":4,"key_bit_size":128,"keystream_bit_len":125,"lfsr_state_bit_size":128}` | `input_state` | no | 125 | 2000 | `unavailable` | — | `timeout` | — | — | — | inverse construction exceeded 30 s |
| `MD5` | `standard-1` | `{"number_of_rounds":64,"word_size":32}` | `input_message` | no | 64 | 600 | `not-supported: disconnected_dependency: known boundaries do not connect to every requested target wire [input_message]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [modadd_60_8] |
| `SHA1` | `standard-1` | `{"number_of_rounds":80,"word_size":32}` | `input_message` | no | 80 | 582 | `not-supported: disconnected_dependency: known boundaries do not connect to every requested target wire [input_message]` | — | `timeout` | — | — | — | inverse construction exceeded 30 s |
| `SHA2` | `standard-1` | `{"number_of_rounds":64,"output_bit_size":256}` | `input_message` | no | 65 | 1792 | `not-supported: disconnected_dependency: known boundaries do not connect to every requested target wire [input_message]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [modadd_63_22] |
| `SHA2` | `standard-2` | `{"number_of_rounds":64,"output_bit_size":224}` | `input_message` | no | 65 | 1792 | `not-supported: disconnected_dependency: known boundaries do not connect to every requested target wire [input_message]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [modadd_63_22] |
| `SHA2` | `standard-3` | `{"number_of_rounds":80,"output_bit_size":512}` | `input_message` | no | 81 | 2272 | `not-supported: disconnected_dependency: known boundaries do not connect to every requested target wire [input_message]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [modadd_79_22] |
| `SHA2` | `standard-4` | `{"number_of_rounds":80,"output_bit_size":384}` | `input_message` | no | 81 | 2272 | `not-supported: disconnected_dependency: known boundaries do not connect to every requested target wire [input_message]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [modadd_76_29] |
| `Whirlpool` | `standard-1` | `{"number_of_rounds":10,"state_size":8,"word_size":8}` | `input_message` | no | 10 | 1633 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_165]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_9_163] |

### permutations

| Primitive | Parameter set | Parameters | Recover | Obligation | Graph rounds | Components | 1-round outcome | 1-round ms | Full outcome | Full ms | ms/round | Semantic | Diagnostic |
|---|---|---|---|:---:|---:|---:|---|---:|---|---:|---:|:---:|---|
| `Ascon` | `default` | `{"number_of_rounds":12}` | `plaintext` | yes | 12 | 468 | `verified` | 31.932 | `verified` | 321.677 | 26.806 | 2/2 | — |
| `AsconSboxSigma` | `standard-1` | `{"number_of_rounds":12}` | `plaintext` | yes | 12 | 852 | `verified` | 25.682 | `verified` | 173.527 | 14.461 | 2/2 | — |
| `AsconSboxSigmaNoMatrix` | `standard-1` | `{"number_of_rounds":12}` | `plaintext` | yes | 12 | 972 | `verified` | 31.413 | `verified` | 334.062 | 27.839 | 2/2 | — |
| `ChaCha` | `default` | `{"number_of_rounds":20,"rotations":[16,12,8,7],"word_size":32}` | `state` | yes | 20 | 960 | `verified` | 2.054 | `verified` | 37.252 | 1.863 | 2/2 | — |
| `ChaskeyPi` | `standard-1` | `{"number_of_rounds":12,"word_size":32}` | `plaintext` | yes | 12 | 168 | `verified` | 5.867 | `verified` | 62.236 | 5.186 | 2/2 | — |
| `Forro` | `standard-1` | `{"number_of_rounds":14}` | `plaintext` | yes | 14 | 672 | `verified` | 25.596 | `verified` | 361.196 | 25.800 | 2/2 | — |
| `Forro` | `standard-2` | `{"number_of_rounds":10}` | `plaintext` | yes | 10 | 480 | `verified` | 25.528 | `verified` | 254.030 | 25.403 | 2/2 | — |
| `Gaston` | `default` | `{"number_of_rounds":12}` | `plaintext` | yes | 12 | 540 | `verified` | 123.502 | `verified` | 525.492 | 43.791 | 2/2 | — |
| `GastonSbox` | `standard-1` | `{"number_of_rounds":12}` | `plaintext` | yes | 12 | 1128 | `verified` | 118.801 | `verified` | 520.331 | 43.361 | 2/2 | — |
| `GastonSboxTheta` | `standard-1` | `{"number_of_rounds":12}` | `plaintext` | yes | 12 | 924 | `verified` | 52.342 | `verified` | 318.533 | 26.544 | 2/2 | — |
| `Gimli` | `default` | `{"number_of_rounds":24,"word_size":32}` | `plaintext` | yes | 24 | 1452 | `verified` | 109.894 | `verified` | 3050.136 | 127.089 | 2/2 | — |
| `GimliSbox` | `standard-1` | `{"number_of_rounds":24,"word_size":32}` | `plaintext` | yes | 24 | 4236 | `verified` | 82.927 | `verified` | 3051.598 | 127.150 | 2/2 | — |
| `GrainCore` | `standard-1` | `{"number_of_rounds":160}` | `input_state` | yes | 160 | 160 | `verified` | 1.335 | `verified` | 213.799 | 1.336 | 2/2 | — |
| `Keccak` | `default` | `{"number_of_rounds":24,"word_size":64}` | `plaintext` | yes | 24 | 3408 | `verified` | 2012.391 | `verified` | 14953.531 | 623.064 | 2/2 | — |
| `KeccakInvertible` | `default` | `{"number_of_rounds":24,"word_size":64}` | `plaintext` | yes | 24 | 9288 | `verified` | 2054.442 | `verified` | 14582.615 | 607.609 | 2/2 | — |
| `KeccakSbox` | `standard-1` | `{"number_of_rounds":18,"word_size":8}` | `plaintext` | yes | 18 | 1926 | `verified` | 65.417 | `verified` | 444.885 | 24.716 | 2/2 | — |
| `KeccakSbox` | `standard-2` | `{"number_of_rounds":16,"word_size":16}` | `plaintext` | yes | 16 | 2352 | `verified` | 160.312 | `verified` | 965.902 | 60.369 | 2/2 | — |
| `KeccakSbox` | `standard-3` | `{"number_of_rounds":20,"word_size":16}` | `plaintext` | yes | 20 | 2940 | `verified` | 159.806 | `verified` | 1244.585 | 62.229 | 2/2 | — |
| `Knot` | `standard-1` | `{"number_of_rounds":52,"state_bit_size":256}` | `plaintext` | yes | 52 | 3588 | `verified` | 11.744 | `verified` | 574.284 | 11.044 | 2/2 | — |
| `Knot` | `standard-2` | `{"number_of_rounds":76,"state_bit_size":384}` | `plaintext` | yes | 76 | 7676 | `verified` | 33.346 | `verified` | 1266.681 | 16.667 | 2/2 | — |
| `Knot` | `standard-3` | `{"number_of_rounds":100,"state_bit_size":512}` | `plaintext` | yes | 100 | 13300 | `verified` | 22.779 | `verified` | 2404.491 | 24.045 | 2/2 | — |
| `Norx` | `standard-1` | `{"number_of_rounds":4,"word_size":32}` | `plaintext` | yes | 4 | 768 | `verified` | 607.575 | `verified` | 2707.198 | 676.799 | 2/2 | — |
| `Norx` | `standard-2` | `{"number_of_rounds":4,"word_size":64}` | `plaintext` | yes | 4 | 768 | `verified` | 1462.700 | `verified` | 6924.577 | 1731.144 | 2/2 | — |
| `Photon` | `standard-1` | `{"t":256}` | `plaintext` | yes | 12 | 980 | `verified` | 10.056 | `verified` | 112.438 | 9.370 | 2/2 | — |
| `Salsa` | `default` | `{"number_of_rounds":20,"rotations":[7,9,13,18],"word_size":32}` | `state` | yes | 20 | 960 | `verified` | 2.344 | `verified` | 34.890 | 1.745 | 2/2 | — |
| `Sparkle` | `standard-1` | `{"number_of_blocks":4,"number_of_steps":7}` | `plaintext` | yes | 7 | 659 | `verified` | 35.413 | `verified` | 226.780 | 32.397 | 2/2 | — |
| `Sparkle` | `standard-2` | `{"number_of_blocks":4,"number_of_steps":10}` | `plaintext` | yes | 10 | 938 | `verified` | 31.055 | `verified` | 347.799 | 34.780 | 2/2 | — |
| `Sparkle` | `standard-3` | `{"number_of_blocks":6,"number_of_steps":7}` | `plaintext` | yes | 7 | 953 | `verified` | 48.950 | `verified` | 358.084 | 51.155 | 2/2 | — |
| `Sparkle` | `standard-4` | `{"number_of_blocks":6,"number_of_steps":11}` | `plaintext` | yes | 11 | 1493 | `verified` | 47.026 | `verified` | 577.749 | 52.523 | 2/2 | — |
| `Sparkle` | `standard-5` | `{"number_of_blocks":8,"number_of_steps":8}` | `plaintext` | yes | 8 | 1424 | `verified` | 67.878 | `verified` | 518.464 | 64.808 | 2/2 | — |
| `Sparkle` | `standard-6` | `{"number_of_blocks":8,"number_of_steps":12}` | `plaintext` | yes | 12 | 2132 | `verified` | 70.094 | `verified` | 825.239 | 68.770 | 2/2 | — |
| `Speckey` | `standard-1` | `{"number_of_rounds":1}` | `plaintext` | yes | 1 | 4 | `verified` | 1.563 | `verified` | 1.680 | 1.680 | 2/2 | — |
| `SpongentPi` | `default` | `{"number_of_rounds":80,"state_bit_size":160}` | `plaintext` | yes | 80 | 2080 | `verified` | 10.123 | `verified` | 314.656 | 3.933 | 2/2 | — |
| `SpongentPiFSR` | `default` | `{"number_of_rounds":80,"state_bit_size":160}` | `plaintext` | yes | 80 | 2080 | `verified` | 9.785 | `verified` | 312.483 | 3.906 | 2/2 | — |
| `SpongentPiPrecomputation` | `standard-1` | `{"number_of_rounds":80,"state_bit_size":160}` | `plaintext` | yes | 80 | 2000 | `verified` | 3.983 | `verified` | 305.238 | 3.815 | 2/2 | — |
| `SpongentPiPrecomputation` | `standard-2` | `{"number_of_rounds":90,"state_bit_size":176}` | `plaintext` | yes | 90 | 2430 | `verified` | 4.277 | `verified` | 378.097 | 4.201 | 2/2 | — |
| `Xoodoo` | `default` | `{"number_of_rounds":3}` | `plaintext` | yes | 3 | 108 | `verified` | 127.593 | `verified` | 161.107 | 53.702 | 2/2 | — |
| `XoodooInvertible` | `default` | `{"number_of_rounds":12}` | `plaintext` | yes | 12 | 1860 | `verified` | 131.394 | `verified` | 677.371 | 56.448 | 2/2 | — |
| `XoodooSbox` | `standard-1` | `{"number_of_rounds":12}` | `plaintext` | yes | 12 | 1860 | `verified` | 131.166 | `verified` | 670.910 | 55.909 | 2/2 | — |

### single_component_primitives

| Primitive | Parameter set | Parameters | Recover | Obligation | Graph rounds | Components | 1-round outcome | 1-round ms | Full outcome | Full ms | ms/round | Semantic | Diagnostic |
|---|---|---|---|:---:|---:|---:|---|---:|---|---:|---:|:---:|---|
| `Add` | `default` | `{"domain":null,"number_of_inputs":2,"unit_count":1}` | `input_0` | no | 1 | 1 | `verified` | 0.217 | `verified` | 0.159 | 0.159 | 2/2 | — |
| `BinaryAffineMap` | `default` | `{"matrix":null,"offset":0,"unit_count":1,"word_size":4}` | `input` | yes | 1 | 1 | `verified` | 0.199 | `verified` | 0.146 | 0.146 | 2/2 | — |
| `BitVectorSBox` | `default` | `{"input_bit_size":4,"lookup_table":null,"output_bit_size":null}` | `input` | no | 1 | 1 | `verified` | 0.215 | `verified` | 0.158 | 0.158 | 2/2 | — |
| `BitwiseAnd` | `default` | `{"number_of_inputs":2,"word_bit_size":4}` | `input_0` | no | 1 | 1 | `not-supported: information_loss: bitwise AND is not bijective in an operand [bitwise_and_0_0]` | — | `not-supported` | — | — | — | information_loss: bitwise AND is not bijective in an operand [bitwise_and_0_0] |
| `BitwiseNot` | `default` | `{"bit_size":4}` | `input` | no | 1 | 1 | `verified` | 0.174 | `verified` | 0.133 | 0.133 | 2/2 | — |
| `BitwiseOr` | `default` | `{"number_of_inputs":2,"word_bit_size":4}` | `input_0` | no | 1 | 1 | `not-supported: information_loss: bitwise OR is not bijective in an operand [bitwise_or_0_0]` | — | `not-supported` | — | — | — | information_loss: bitwise OR is not bijective in an operand [bitwise_or_0_0] |
| `Constant` | `default` | `{"output_bit_size":3,"value":2}` | `—` | no | 1 | 1 | `not-applicable: primitive has no input to recover` | — | `not-applicable` | — | — | — | primitive has no input to recover |
| `FeedbackRegister` | `default` | `{"parameters":null}` | `input` | no | 1 | 1 | `verified` | 0.204 | `verified` | 0.147 | 0.147 | 2/2 | — |
| `IDEAMultiply` | `default` | `{"number_of_inputs":2,"word_bit_size":16}` | `input_0` | no | 1 | 1 | `verified` | 0.226 | `verified` | 0.170 | 0.170 | 2/2 | — |
| `Identity` | `default` | `{"bit_size":32}` | `input` | no | 1 | 1 | `verified` | 0.326 | `verified` | 0.256 | 0.256 | 2/2 | — |
| `LinearMap` | `default` | `{"domain":null,"matrix":null}` | `input` | no | 1 | 1 | `verified` | 0.221 | `verified` | 0.146 | 0.146 | 2/2 | — |
| `ModularAdd` | `default` | `{"number_of_inputs":2,"word_bit_size":4}` | `input_0` | no | 1 | 1 | `verified` | 0.202 | `verified` | 0.151 | 0.151 | 2/2 | — |
| `ModularMultiply` | `default` | `{"number_of_inputs":2,"word_bit_size":4}` | `input_0` | no | 1 | 1 | `not-supported: information_loss: modular multiplication is not bijective for every auxiliary [modular_multiply_0_0]` | — | `not-supported` | — | — | — | information_loss: modular multiplication is not bijective for every auxiliary [modular_multiply_0_0] |
| `ModularSubtract` | `default` | `{"number_of_inputs":2,"word_bit_size":4}` | `input_0` | no | 1 | 1 | `verified` | 0.189 | `verified` | 0.146 | 0.146 | 2/2 | — |
| `Multiply` | `default` | `{"domain":null,"number_of_inputs":2,"unit_count":1}` | `input_0` | no | 1 | 1 | `not-supported: information_loss: multiplication is not bijective when an auxiliary can be zero [multiply_0_0]` | — | `not-supported` | — | — | — | information_loss: multiplication is not bijective when an auxiliary can be zero [multiply_0_0] |
| `Permutation` | `default` | `{"mapping":null,"word_size":1}` | `input` | no | 1 | 1 | `verified` | 0.238 | `verified` | 0.160 | 0.160 | 2/2 | — |
| `Power` | `default` | `{"domain":null,"exponent":3,"unit_count":1}` | `input` | yes | 1 | 1 | `verified` | 0.181 | `verified` | 0.131 | 0.131 | 2/2 | — |
| `Rotate` | `default` | `{"amount":1,"bit_size":8,"direction":"right"}` | `input` | no | 1 | 1 | `verified` | 0.163 | `verified` | 0.130 | 0.130 | 2/2 | — |
| `SBox` | `default` | `{"domain":null,"lookup_table":null,"unit_count":1}` | `input` | yes | 1 | 1 | `verified` | 0.174 | `verified` | 0.138 | 0.138 | 2/2 | — |
| `Shift` | `default` | `{"amount":1,"bit_size":8,"direction":"right"}` | `input` | no | 1 | 1 | `not-supported: information_loss: fixed shifts discard bits [shift_0_0]` | — | `not-supported` | — | — | — | information_loss: fixed shifts discard bits [shift_0_0] |
| `VariableRotate` | `default` | `{"amount_bit_size":3,"bit_size":8,"direction":"right"}` | `input` | no | 1 | 1 | `verified` | 0.188 | `verified` | 0.148 | 0.148 | 2/2 | — |
| `VariableShift` | `default` | `{"amount_bit_size":3,"bit_size":8,"direction":"right"}` | `input` | no | 1 | 1 | `not-supported: information_loss: variable shifts can discard bits [variable_shift_0_0]` | — | `not-supported` | — | — | — | information_loss: variable shifts can discard bits [variable_shift_0_0] |
| `Xor` | `default` | `{"number_of_inputs":2,"word_bit_size":4}` | `input_0` | no | 1 | 1 | `verified` | 0.189 | `verified` | 0.151 | 0.151 | 2/2 | — |

### toy_primitives

| Primitive | Parameter set | Parameters | Recover | Obligation | Graph rounds | Components | 1-round outcome | 1-round ms | Full outcome | Full ms | ms/round | Semantic | Diagnostic |
|---|---|---|---|:---:|---:|---:|---|---:|---|---:|---:|:---:|---|
| `CipherFour` | `default` | `{"block_bit_size":16,"key_bit_size":16,"number_of_rounds":5,"permutations":null,"rotation_layer":1,"sbox":null}` | `plaintext` | no | 5 | 30 | `construction-error: ValueError: position 64 is outside source 'key' with 32 logical units` | — | `verified` | 3.279 | 0.656 | 2/2 | — |
| `Fancy` | `default` | `{"block_bit_size":24,"key_bit_size":24,"number_of_rounds":20}` | `plaintext` | no | 20 | 250 | `verified` | 1.702 | `not-supported` | — | — | — | information_loss: fixed shifts discard bits [shift_19_11] |
| `Heys` | `default` | `{"block_bit_size":16,"key_bit_size":80,"number_of_rounds":4}` | `plaintext` | no | 4 | 24 | `verified` | 0.934 | `verified` | 2.630 | 0.657 | 2/2 | — |
| `ToyAES` | `default` | `{"number_of_rounds":10,"state_size":4,"word_size":8}` | `key` | no | 10 | 127 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [add_0_9]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [add_9_8] |
| `ToyFeistel` | `default` | `{"block_bit_size":8,"key_bit_size":8,"number_of_rounds":5,"sbox":[14,9,15,0,13,4,10,11,1,2,8,3,7,6,12,5]}` | `plaintext` | no | 5 | 35 | `verified` | 0.899 | `verified` | 3.485 | 0.697 | 2/2 | — |
| `ToySPN1` | `default` | `{"block_bit_size":6,"key_bit_size":6,"number_of_rounds":2,"rotation_layer":1,"sbox":[0,5,3,2,6,1,4,7]}` | `plaintext` | no | 2 | 8 | `verified` | 0.721 | `verified` | 0.690 | 0.345 | 2/2 | — |
| `ToySPN2` | `default` | `{"block_bit_size":6,"key_bit_size":6,"number_of_rounds":2,"rotation_layer":1,"round_key_rotation":1,"sbox":[0,5,3,2,6,1,4,7]}` | `plaintext` | no | 2 | 10 | `verified` | 0.842 | `verified` | 0.784 | 0.392 | 2/2 | — |

### tweakable_block_ciphers

| Primitive | Parameter set | Parameters | Recover | Obligation | Graph rounds | Components | 1-round outcome | 1-round ms | Full outcome | Full ms | ms/round | Semantic | Diagnostic |
|---|---|---|---|:---:|---:|---:|---|---:|---|---:|---:|:---:|---|
| `BipBip` | `standard-1` | `{"number_of_core_rounds":5,"number_of_shell_rounds_1":3,"number_of_shell_rounds_2":3}` | `plaintext` | yes | 12 | 179 | `unavailable` | — | `verified` | 204.376 | 17.031 | 2/2 | — |
| `Blink` | `standard-1` | `{"a":2,"b":3,"block_bit_size":64,"key_bit_size":448,"tweak_bit_size":64}` | `plaintext` | yes | 10 | 1162 | `unavailable` | — | `verified` | 2962.478 | 296.248 | 2/2 | — |
| `Blink` | `standard-2` | `{"a":2,"b":3,"block_bit_size":64,"key_bit_size":448,"tweak_bit_size":128}` | `plaintext` | yes | 10 | 1162 | `unavailable` | — | `verified` | 4474.683 | 447.468 | 2/2 | — |
| `Blink` | `standard-3` | `{"a":3,"b":3,"block_bit_size":128,"key_bit_size":1024,"tweak_bit_size":128}` | `plaintext` | yes | 12 | 2572 | `unavailable` | — | `verified` | 10702.431 | 891.869 | 2/2 | — |
| `Blink` | `standard-4` | `{"a":3,"b":3,"block_bit_size":128,"key_bit_size":1024,"tweak_bit_size":256}` | `plaintext` | yes | 12 | 2572 | `unavailable` | — | `verified` | 17845.616 | 1487.135 | 2/2 | — |
| `Blink` | `standard-5` | `{"a":3,"b":5,"block_bit_size":128,"key_bit_size":1280,"tweak_bit_size":128}` | `plaintext` | yes | 16 | 3088 | `unavailable` | — | `verified` | 14334.877 | 895.930 | 2/2 | — |
| `Blink` | `standard-6` | `{"a":3,"b":5,"block_bit_size":128,"key_bit_size":1280,"tweak_bit_size":256}` | `plaintext` | yes | 16 | 3088 | `unavailable` | — | `verified` | 21233.982 | 1327.124 | 2/2 | — |
| `Chilow` | `default` | `{"number_of_rounds":1,"tau":null}` | `plaintext` | yes | 1 | 16 | `verified` | 26.557 | `verified` | 7.960 | 7.960 | 2/2 | — |
| `Mantis` | `default` | `{"number_of_rounds":6}` | `plaintext` | yes | 12 | 426 | `verified` | 23.823 | `verified` | 84.419 | 7.035 | 2/2 | — |
| `QARMAv2` | `default` | `{"key_bit_size":128,"number_of_layers":1,"number_of_rounds":10,"tweak_bit_size":128}` | `plaintext` | yes | 21 | 1197 | `verified` | 62.182 | `verified` | 275.982 | 13.142 | 2/2 | — |
| `QARMAv2MixColumn` | `standard-1` | `{"key_bit_size":128,"number_of_layers":1,"number_of_rounds":10,"tweak_bit_size":128}` | `plaintext` | yes | 21 | 685 | `verified` | 41.521 | `verified` | 139.928 | 6.663 | 2/2 | — |
| `SCARF` | `default` | `{"number_of_rounds":8}` | `plaintext` | yes | 8 | 188 | `verified` | 15.756 | `verified` | 33.966 | 4.246 | 2/2 | — |
| `Threefish` | `default` | `{"block_bit_size":256,"key_bit_size":null,"number_of_rounds":null,"tweak_bit_size":128}` | `plaintext` | yes | 73 | 590 | `verified` | 1.221 | `verified` | 21.974 | 0.301 | 2/2 | — |
| `Trax` | `default` | `{"number_of_rounds":17}` | `plaintext` | yes | 17 | 1876 | `verified` | 5.390 | `verified` | 74.834 | 4.402 | 2/2 | — |

## Reproduction

From `next/`:

```console
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3.11 tools/audit_primitive_inversion.py
```

The report is a point-in-time benchmark. Compare future methodology changes on the same machine, Python version, timeout, and repetition count.
