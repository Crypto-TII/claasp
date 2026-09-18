# Primitive inversion audit

Generated at 2026-09-18T16:18:21+00:00 from commit `6aee0a31` on macOS-26.3-x86_64-i386-64bit, Python 3.11.12.

## Scope and interpretation

This audit covers every public primitive and every named parameter set in the committed v5 catalogue, including toy and single-component primitives. The operation under test recovers the catalogue-designated data/state input from the primitive output while retaining every other primitive input. The bijectivity obligation therefore describes that retained-input map, not global bijectivity of a multi-input function. For a primitive without a bijectivity obligation, the first input remains the explicitly qualified recovery target. Therefore, **verified** means that the current solver-free graph transformation constructed an inverse and recovered the original target input for two deterministic semantic samples. It does not mean that a multi-input primitive is globally bijective without retained inputs.

The catalogue's bijectivity obligation is reported independently. A `yes` is a specification/classification claim; a failed transformation on such a row identifies a methodology gap, not proof that the mathematical primitive is non-invertible. The obligation is attached to each named catalogue configuration; constructors that accept arbitrary tables, matrices, or domains can also create non-bijective graphs outside those named configurations.

Fixed semantic evidence separately records Fancy's lossy odd-round collision and collisions in ToyAES's optional two-bit-word teaching variants; neither negative case changes the positive obligation of ToyAES's named eight-bit-word configuration.

Inverse construction was measured 1 time(s) per successful configuration and the median is shown. Each attempt had a 30-second limit, with 4 isolated workers running concurrently. `1-round ms` is a separately constructed public configuration using `number_of_rounds=1` or `number_of_steps=1`; a one-graph-round primitive reuses its full measurement. `ms/round` is also supplied as the full construction time divided by immutable graph-round count. Construction of the forward graph and semantic evaluation are excluded from inversion timings.

## Summary

- Public primitives: **142**
- Official parameter sets checked: **234**
- Primitives with at least one verified configuration: **120**
- Primitives verified for every official configuration: **120**
- Configuration outcomes: **1 not-applicable**, **20 not-supported**, **5 timeout**, **208 verified**
- Retained-input-bijective catalogue configurations verified by the current transformation: **208/208**
- Configurations without a catalogue bijectivity obligation that still support first-input recovery with auxiliaries: **0/26**
- One-round outcomes: **5 construction-error**, **1 not-applicable**, **20 not-supported**, **13 unavailable**, **195 verified**

| Category | Primitives | Configurations | Verified | Not supported | Timed out | Other |
|---|---:|---:|---:|---:|---:|---:|
| `block_ciphers` | 61 | 132 | 132 | 0 | 0 | 0 |
| `block_functions` | 8 | 8 | 1 | 5 | 2 | 0 |
| `functions` | 7 | 11 | 0 | 8 | 3 | 0 |
| `permutations` | 27 | 39 | 39 | 0 | 0 | 0 |
| `single_component_primitives` | 23 | 23 | 16 | 6 | 0 | 1 |
| `toy_primitives` | 7 | 7 | 6 | 1 | 0 | 0 |
| `tweakable_block_ciphers` | 9 | 14 | 14 | 0 | 0 | 0 |

### Failure and stall diagnostics

| Diagnostic class | Configurations |
|---|---:|
| `information_loss` | 7 |
| `multiple_predecessors` | 13 |
| `not-applicable` | 1 |
| `timeout` | 5 |

### Slowest verified full inversions

| Primitive | Parameter set | Full ms | Graph rounds | ms/round |
|---|---|---:|---:|---:|
| `Blink` | `standard-6` | 23211.637 | 16 | 1450.727 |
| `Blink` | `standard-4` | 18985.496 | 12 | 1582.125 |
| `Blink` | `standard-5` | 15322.347 | 16 | 957.647 |
| `KeccakInvertible` | `default` | 15135.224 | 24 | 630.634 |
| `Keccak` | `default` | 14380.421 | 24 | 599.184 |
| `Blink` | `standard-3` | 11176.053 | 12 | 931.338 |
| `Norx` | `standard-2` | 7259.642 | 4 | 1814.911 |
| `Speedy` | `standard-1` | 4686.352 | 5 | 937.270 |
| `Blink` | `standard-2` | 4540.313 | 10 | 454.031 |
| `Gimli` | `default` | 3071.740 | 24 | 127.989 |

## Methodology status

This report is the acceptance evidence for tracker slice `M10.10h`. Its catalogue completeness condition is that every configuration carrying a bijectivity obligation has status `verified`. At this checkpoint, **208/208** such configurations satisfy that condition.

Non-verified rows remain visible because the audit also probes first-input recovery for hashes, stream-output functions, lossy teaching components, and other primitives without a catalogue bijectivity obligation. They are qualified results, not gaps in the bijective coverage claim. Future optimization can use the slowest-results table to prioritize graph construction cost, but must retain the same solver-free contracts, typed failures, provenance, and independent semantic round trips.

## Configuration results

Times are milliseconds. Parameters are the exact values passed to the public constructor.

### block_ciphers

| Primitive | Parameter set | Parameters | Recover | Obligation | Graph rounds | Components | 1-round outcome | 1-round ms | Full outcome | Full ms | ms/round | Semantic | Diagnostic |
|---|---|---|---|:---:|---:|---:|---|---:|---|---:|---:|:---:|---|
| `AES` | `standard-1` | `{"key_bit_size":128,"number_of_rounds":10}` | `plaintext` | yes | 11 | 110 | `verified` | 5.958 | `verified` | 6.992 | 0.636 | 2/2 | — |
| `AES` | `standard-2` | `{"key_bit_size":192,"number_of_rounds":12}` | `plaintext` | yes | 13 | 118 | `verified` | 6.176 | `verified` | 8.234 | 0.633 | 2/2 | — |
| `AES` | `standard-3` | `{"key_bit_size":256,"number_of_rounds":14}` | `plaintext` | yes | 15 | 135 | `verified` | 5.812 | `verified` | 9.085 | 0.606 | 2/2 | — |
| `Aradi` | `default` | `{"number_of_rounds":16}` | `plaintext` | yes | 16 | 868 | `verified` | 66.471 | `verified` | 320.714 | 20.045 | 2/2 | — |
| `AradiSBox` | `standard-1` | `{"number_of_rounds":16}` | `plaintext` | yes | 16 | 1252 | `verified` | 20.036 | `verified` | 337.806 | 21.113 | 2/2 | — |
| `AradiSBoxCompactLinearMap` | `standard-1` | `{"number_of_rounds":16}` | `plaintext` | yes | 16 | 932 | `verified` | 14.818 | `verified` | 259.702 | 16.231 | 2/2 | — |
| `BEA1` | `standard-1` | `{"number_of_rounds":11}` | `plaintext` | yes | 11 | 442 | `verified` | 35.315 | `verified` | 100.013 | 9.092 | 2/2 | — |
| `Baksheesh` | `standard-1` | `{"block_bit_size":128,"key_bit_size":128,"number_of_rounds":35}` | `plaintext` | yes | 35 | 1296 | `verified` | 6.836 | `verified` | 206.912 | 5.912 | 2/2 | — |
| `Ballet` | `standard-1` | `{"block_bit_size":128,"key_bit_size":128,"number_of_rounds":46}` | `plaintext` | yes | 46 | 594 | `verified` | 3.954 | `verified` | 241.210 | 5.244 | 2/2 | — |
| `Ballet` | `standard-2` | `{"block_bit_size":128,"key_bit_size":256,"number_of_rounds":48}` | `plaintext` | yes | 48 | 808 | `verified` | 3.612 | `verified` | 382.593 | 7.971 | 2/2 | — |
| `Ballet` | `standard-3` | `{"block_bit_size":256,"key_bit_size":256,"number_of_rounds":74}` | `plaintext` | yes | 74 | 958 | `verified` | 13.329 | `verified` | 758.498 | 10.250 | 2/2 | — |
| `CHAM` | `default` | `{"block_bit_size":64,"key_bit_size":128,"number_of_rounds":null}` | `plaintext` | yes | 88 | 576 | `verified` | 1.587 | `verified` | 18.178 | 0.207 | 2/2 | — |
| `Cast` | `standard-1` | `{"key_bit_size":128,"number_of_rounds":16}` | `plaintext` | yes | 17 | 579 | `verified` | 86.415 | `verified` | 142.109 | 8.359 | 2/2 | — |
| `Cast` | `standard-2` | `{"key_bit_size":80,"number_of_rounds":12}` | `plaintext` | yes | 13 | 533 | `verified` | 89.404 | `verified` | 129.342 | 9.949 | 2/2 | — |
| `Cast` | `standard-3` | `{"key_bit_size":40,"number_of_rounds":12}` | `plaintext` | yes | 13 | 533 | `verified` | 81.957 | `verified` | 122.304 | 9.408 | 2/2 | — |
| `DES` | `default` | `{"number_of_rounds":16,"number_of_sboxes":8}` | `plaintext` | yes | 16 | 244 | `verified` | 3.645 | `verified` | 41.762 | 2.610 | 2/2 | — |
| `DESExactKeyLength` | `standard-1` | `{"number_of_rounds":16,"number_of_sboxes":8}` | `plaintext` | yes | 16 | 244 | `verified` | 3.698 | `verified` | 43.913 | 2.745 | 2/2 | — |
| `Gift` | `default` | `{"block_bit_size":128,"number_of_rounds":null}` | `plaintext` | yes | 40 | 678 | `verified` | 11.333 | `verified` | 273.883 | 6.847 | 2/2 | — |
| `GiftSbox` | `standard-1` | `{"block_bit_size":64,"number_of_rounds":28}` | `plaintext` | yes | 28 | 726 | `verified` | 3.029 | `verified` | 96.272 | 3.438 | 2/2 | — |
| `GiftSbox` | `standard-2` | `{"block_bit_size":128,"number_of_rounds":40}` | `plaintext` | yes | 40 | 1678 | `verified` | 5.428 | `verified` | 265.711 | 6.643 | 2/2 | — |
| `Gost` | `standard-1` | `{"block_bit_size":64,"key_bit_size":256,"number_of_rounds":32}` | `plaintext` | yes | 32 | 352 | `verified` | 2.316 | `verified` | 69.125 | 2.160 | 2/2 | — |
| `HIGHT` | `default` | `{"block_bit_size":64,"key_bit_size":128,"number_of_rounds":null,"sub_keys_zero":false,"transformations_flag":true}` | `plaintext` | yes | 32 | 1032 | `verified` | 1.652 | `verified` | 31.225 | 0.976 | 2/2 | — |
| `IDEA` | `default` | `{"number_of_rounds":8}` | `plaintext` | yes | 10 | 122 | `verified` | 4.455 | `verified` | 38.997 | 3.900 | 2/2 | — |
| `Kalyna` | `default` | `{"number_of_rounds":10}` | `plaintext` | yes | 11 | 560 | `construction-error: KeyError: 1` | — | `verified` | 147.806 | 13.437 | 2/2 | — |
| `Kasumi` | `standard-1` | `{"block_bit_size":64,"key_bit_size":128,"number_of_rounds":8}` | `plaintext` | yes | 8 | 674 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_80]` | — | `verified` | 120.122 | 15.015 | 2/2 | — |
| `Katan` | `default` | `{"block_bit_size":32,"ir_mode":"strict","key_bit_size":80,"number_of_rounds":null}` | `plaintext` | yes | 254 | 1699 | `verified` | 1.646 | `verified` | 492.631 | 1.939 | 2/2 | — |
| `KatanFSR` | `standard-1` | `{"block_bit_size":32,"key_bit_size":80,"number_of_rounds":254}` | `plaintext` | yes | 254 | 1698 | `verified` | 1.850 | `verified` | 622.957 | 2.453 | 2/2 | — |
| `KatanFSR` | `standard-2` | `{"block_bit_size":48,"key_bit_size":80,"number_of_rounds":254}` | `plaintext` | yes | 254 | 2968 | `verified` | 2.583 | `verified` | 1448.253 | 5.702 | 2/2 | — |
| `KatanFSR` | `standard-3` | `{"block_bit_size":64,"key_bit_size":80,"number_of_rounds":254}` | `plaintext` | yes | 254 | 4238 | `verified` | 3.573 | `verified` | 2628.342 | 10.348 | 2/2 | — |
| `Ktantan` | `default` | `{"block_bit_size":32,"ir_mode":"strict","key_bit_size":80,"number_of_rounds":null}` | `plaintext` | yes | 254 | 1271 | `verified` | 1.724 | `verified` | 391.818 | 1.543 | 2/2 | — |
| `KtantanFSR` | `standard-1` | `{"block_bit_size":32,"key_bit_size":80,"number_of_rounds":254}` | `plaintext` | yes | 254 | 1270 | `verified` | 1.558 | `verified` | 407.432 | 1.604 | 2/2 | — |
| `KtantanFSR` | `standard-2` | `{"block_bit_size":48,"key_bit_size":80,"number_of_rounds":254}` | `plaintext` | yes | 254 | 2540 | `verified` | 3.016 | `verified` | 1220.847 | 4.806 | 2/2 | — |
| `KtantanFSR` | `standard-3` | `{"block_bit_size":64,"key_bit_size":80,"number_of_rounds":254}` | `plaintext` | yes | 254 | 3810 | `verified` | 3.541 | `verified` | 1996.991 | 7.862 | 2/2 | — |
| `LBlock` | `standard-1` | `{"number_of_rounds":32}` | `plaintext` | yes | 32 | 512 | `verified` | 3.440 | `verified` | 87.125 | 2.723 | 2/2 | — |
| `LEA` | `default` | `{"block_bit_size":128,"key_bit_size":192,"number_of_rounds":null,"reorder_input_and_output":true}` | `plaintext` | yes | 28 | 1022 | `verified` | 5.016 | `verified` | 34.543 | 1.234 | 2/2 | — |
| `Led` | `standard-1` | `{"key_bit_size":64,"number_of_rounds":32}` | `plaintext` | yes | 8 | 713 | `construction-error: AssertionError: Number of rounds must be a multiple of 4.` | — | `verified` | 74.342 | 9.293 | 2/2 | — |
| `Led` | `standard-2` | `{"key_bit_size":128,"number_of_rounds":48}` | `plaintext` | yes | 12 | 1069 | `construction-error: AssertionError: Number of rounds must be a multiple of 4.` | — | `verified` | 125.595 | 10.466 | 2/2 | — |
| `LowMC` | `default` | `{"block_bit_size":128,"key_bit_size":128,"number_of_rounds":null,"number_of_sboxes":null}` | `plaintext` | yes | 20 | 302 | `construction-error: ValueError: No available number of sboxes for the given parameters.` | — | `verified` | 213.890 | 10.694 | 2/2 | — |
| `MSX` | `standard-1` | `{"block_bit_size":64,"key_bit_size":128,"number_of_rounds":14}` | `plaintext` | yes | 14 | 310 | `verified` | 11.425 | `verified` | 105.168 | 7.512 | 2/2 | — |
| `MSX` | `standard-2` | `{"block_bit_size":128,"key_bit_size":128,"number_of_rounds":18}` | `plaintext` | yes | 18 | 752 | `verified` | 27.922 | `verified` | 272.227 | 15.124 | 2/2 | — |
| `MSX` | `standard-3` | `{"block_bit_size":128,"key_bit_size":256,"number_of_rounds":18}` | `plaintext` | yes | 18 | 756 | `verified` | 29.533 | `verified` | 275.652 | 15.314 | 2/2 | — |
| `Midori` | `standard-1` | `{"block_bit_size":64,"key_bit_size":128,"number_of_rounds":16}` | `plaintext` | yes | 16 | 379 | `verified` | 3.421 | `verified` | 51.664 | 3.229 | 2/2 | — |
| `Midori` | `standard-2` | `{"block_bit_size":128,"key_bit_size":128,"number_of_rounds":20}` | `plaintext` | yes | 20 | 1434 | `verified` | 6.532 | `verified` | 175.154 | 8.758 | 2/2 | — |
| `Piccolo` | `standard-1` | `{"key_bit_size":80,"number_of_rounds":25}` | `plaintext` | yes | 25 | 628 | `verified` | 4.031 | `verified` | 68.779 | 2.751 | 2/2 | — |
| `Piccolo` | `standard-2` | `{"key_bit_size":128,"number_of_rounds":31}` | `plaintext` | yes | 31 | 778 | `verified` | 3.787 | `verified` | 84.223 | 2.717 | 2/2 | — |
| `Present` | `default` | `{"key_bit_size":80,"number_of_rounds":31}` | `plaintext` | yes | 31 | 683 | `verified` | 3.147 | `verified` | 66.725 | 2.152 | 2/2 | — |
| `Prince` | `default` | `{"number_of_rounds":12}` | `plaintext` | yes | 11 | 254 | `verified` | 11.041 | `verified` | 52.360 | 4.760 | 2/2 | — |
| `PrinceV2` | `default` | `{"number_of_rounds":12}` | `plaintext` | yes | 11 | 254 | `verified` | 7.996 | `verified` | 49.398 | 4.491 | 2/2 | — |
| `RC5` | `default` | `{"key_size":64,"number_of_rounds":16,"word_size":16}` | `plaintext` | yes | 17 | 645 | `verified` | 5.147 | `verified` | 42.186 | 2.482 | 2/2 | — |
| `Raiden` | `default` | `{"block_bit_size":64,"key_bit_size":128,"left_shift_amount":9,"number_of_rounds":null,"right_shift_amount":14}` | `plaintext` | yes | 16 | 288 | `verified` | 0.757 | `verified` | 9.060 | 0.566 | 2/2 | — |
| `Rectangle` | `standard-1` | `{"key_bit_size":80,"number_of_rounds":25}` | `plaintext` | yes | 25 | 751 | `verified` | 5.468 | `verified` | 156.988 | 6.280 | 2/2 | — |
| `Rectangle` | `standard-2` | `{"key_bit_size":128,"number_of_rounds":25}` | `plaintext` | yes | 25 | 851 | `verified` | 6.684 | `verified` | 183.440 | 7.338 | 2/2 | — |
| `Rijndael` | `standard-1` | `{"block_bit_size":128,"key_bit_size":128,"number_of_rounds":10}` | `plaintext` | yes | 10 | 317 | `verified` | 9.121 | `verified` | 92.697 | 9.270 | 2/2 | — |
| `Rijndael` | `standard-10` | `{"block_bit_size":160,"key_bit_size":256,"number_of_rounds":14}` | `plaintext` | yes | 14 | 522 | `verified` | 9.338 | `verified` | 149.579 | 10.684 | 2/2 | — |
| `Rijndael` | `standard-11` | `{"block_bit_size":192,"key_bit_size":128,"number_of_rounds":12}` | `plaintext` | yes | 12 | 574 | `verified` | 14.047 | `verified` | 184.459 | 15.372 | 2/2 | — |
| `Rijndael` | `standard-12` | `{"block_bit_size":192,"key_bit_size":160,"number_of_rounds":12}` | `plaintext` | yes | 12 | 545 | `verified` | 18.285 | `verified` | 168.705 | 14.059 | 2/2 | — |
| `Rijndael` | `standard-13` | `{"block_bit_size":192,"key_bit_size":192,"number_of_rounds":12}` | `plaintext` | yes | 12 | 523 | `verified` | 12.634 | `verified` | 162.431 | 13.536 | 2/2 | — |
| `Rijndael` | `standard-14` | `{"block_bit_size":192,"key_bit_size":224,"number_of_rounds":13}` | `plaintext` | yes | 13 | 596 | `verified` | 13.153 | `verified` | 180.373 | 13.875 | 2/2 | — |
| `Rijndael` | `standard-15` | `{"block_bit_size":192,"key_bit_size":256,"number_of_rounds":14}` | `plaintext` | yes | 14 | 628 | `verified` | 10.942 | `verified` | 188.816 | 13.487 | 2/2 | — |
| `Rijndael` | `standard-16` | `{"block_bit_size":224,"key_bit_size":128,"number_of_rounds":13}` | `plaintext` | yes | 13 | 724 | `verified` | 23.032 | `verified` | 222.348 | 17.104 | 2/2 | — |
| `Rijndael` | `standard-17` | `{"block_bit_size":224,"key_bit_size":160,"number_of_rounds":13}` | `plaintext` | yes | 13 | 688 | `verified` | 17.297 | `verified` | 224.397 | 17.261 | 2/2 | — |
| `Rijndael` | `standard-18` | `{"block_bit_size":224,"key_bit_size":192,"number_of_rounds":13}` | `plaintext` | yes | 13 | 666 | `verified` | 16.075 | `verified` | 241.399 | 18.569 | 2/2 | — |
| `Rijndael` | `standard-19` | `{"block_bit_size":224,"key_bit_size":224,"number_of_rounds":13}` | `plaintext` | yes | 13 | 696 | `verified` | 16.189 | `verified` | 223.543 | 17.196 | 2/2 | — |
| `Rijndael` | `standard-2` | `{"block_bit_size":128,"key_bit_size":160,"number_of_rounds":11}` | `plaintext` | yes | 11 | 334 | `verified` | 7.971 | `verified` | 98.673 | 8.970 | 2/2 | — |
| `Rijndael` | `standard-20` | `{"block_bit_size":224,"key_bit_size":256,"number_of_rounds":14}` | `plaintext` | yes | 14 | 734 | `verified` | 15.011 | `verified` | 236.662 | 16.904 | 2/2 | — |
| `Rijndael` | `standard-21` | `{"block_bit_size":256,"key_bit_size":128,"number_of_rounds":14}` | `plaintext` | yes | 14 | 886 | `verified` | 25.581 | `verified` | 276.978 | 19.784 | 2/2 | — |
| `Rijndael` | `standard-22` | `{"block_bit_size":256,"key_bit_size":160,"number_of_rounds":14}` | `plaintext` | yes | 14 | 843 | `verified` | 26.135 | `verified` | 269.783 | 19.270 | 2/2 | — |
| `Rijndael` | `standard-23` | `{"block_bit_size":256,"key_bit_size":192,"number_of_rounds":14}` | `plaintext` | yes | 14 | 814 | `verified` | 37.346 | `verified` | 338.747 | 24.196 | 2/2 | — |
| `Rijndael` | `standard-24` | `{"block_bit_size":256,"key_bit_size":224,"number_of_rounds":14}` | `plaintext` | yes | 14 | 863 | `verified` | 27.277 | `verified` | 306.328 | 21.881 | 2/2 | — |
| `Rijndael` | `standard-25` | `{"block_bit_size":256,"key_bit_size":256,"number_of_rounds":14}` | `plaintext` | yes | 14 | 833 | `verified` | 22.910 | `verified` | 396.136 | 28.295 | 2/2 | — |
| `Rijndael` | `standard-3` | `{"block_bit_size":128,"key_bit_size":192,"number_of_rounds":12}` | `plaintext` | yes | 12 | 351 | `verified` | 7.975 | `verified` | 98.849 | 8.237 | 2/2 | — |
| `Rijndael` | `standard-4` | `{"block_bit_size":128,"key_bit_size":224,"number_of_rounds":13}` | `plaintext` | yes | 13 | 396 | `verified` | 6.963 | `verified` | 112.090 | 8.622 | 2/2 | — |
| `Rijndael` | `standard-5` | `{"block_bit_size":128,"key_bit_size":256,"number_of_rounds":14}` | `plaintext` | yes | 14 | 416 | `verified` | 6.301 | `verified` | 117.283 | 8.377 | 2/2 | — |
| `Rijndael` | `standard-6` | `{"block_bit_size":160,"key_bit_size":128,"number_of_rounds":11}` | `plaintext` | yes | 11 | 436 | `verified` | 11.733 | `verified` | 126.962 | 11.542 | 2/2 | — |
| `Rijndael` | `standard-7` | `{"block_bit_size":160,"key_bit_size":160,"number_of_rounds":11}` | `plaintext` | yes | 11 | 414 | `verified` | 11.632 | `verified` | 127.396 | 11.581 | 2/2 | — |
| `Rijndael` | `standard-8` | `{"block_bit_size":160,"key_bit_size":192,"number_of_rounds":12}` | `plaintext` | yes | 12 | 437 | `verified` | 11.655 | `verified` | 135.427 | 11.286 | 2/2 | — |
| `Rijndael` | `standard-9` | `{"block_bit_size":160,"key_bit_size":224,"number_of_rounds":13}` | `plaintext` | yes | 13 | 496 | `verified` | 10.376 | `verified` | 144.685 | 11.130 | 2/2 | — |
| `SM4` | `default` | `{"number_of_rounds":32,"state_size":8,"word_size":8}` | `plaintext` | yes | 32 | 936 | `verified` | 18.360 | `verified` | 361.939 | 11.311 | 2/2 | — |
| `SPARX` | `default` | `{"block_bit_size":64,"key_bit_size":128,"number_of_rounds":null,"steps":null}` | `plaintext` | yes | 8 | 394 | `verified` | 6.524 | `verified` | 52.458 | 6.557 | 2/2 | — |
| `Saecham` | `standard-1` | `{"number_of_rounds":88}` | `plaintext` | yes | 88 | 576 | `verified` | 10.081 | `verified` | 146.363 | 1.663 | 2/2 | — |
| `Serpent` | `standard-1` | `{"key_bit_size":128,"number_of_rounds":32}` | `plaintext` | yes | 32 | 3017 | `verified` | 124.670 | `verified` | 793.177 | 24.787 | 2/2 | — |
| `Serpent` | `standard-2` | `{"key_bit_size":192,"number_of_rounds":32}` | `plaintext` | yes | 32 | 3015 | `verified` | 124.321 | `verified` | 796.213 | 24.882 | 2/2 | — |
| `Serpent` | `standard-3` | `{"key_bit_size":256,"number_of_rounds":32}` | `plaintext` | yes | 32 | 3013 | `verified` | 134.548 | `verified` | 778.759 | 24.336 | 2/2 | — |
| `Simeck` | `default` | `{"block_bit_size":32,"key_bit_size":64,"number_of_rounds":null,"rotation_amounts":[-5,-1]}` | `plaintext` | yes | 32 | 346 | `verified` | 0.368 | `verified` | 10.972 | 0.343 | 2/2 | — |
| `SimeckSbox` | `standard-1` | `{"block_bit_size":32,"key_bit_size":64,"number_of_rounds":32}` | `plaintext` | yes | 32 | 283 | `verified` | 1.454 | `verified` | 57.929 | 1.810 | 2/2 | — |
| `SimeckSbox` | `standard-2` | `{"block_bit_size":48,"key_bit_size":96,"number_of_rounds":36}` | `plaintext` | yes | 36 | 390 | `verified` | 1.748 | `verified` | 86.273 | 2.396 | 2/2 | — |
| `SimeckSbox` | `standard-3` | `{"block_bit_size":64,"key_bit_size":128,"number_of_rounds":44}` | `plaintext` | yes | 44 | 565 | `verified` | 2.126 | `verified` | 134.906 | 3.066 | 2/2 | — |
| `Simon` | `default` | `{"block_bit_size":32,"key_bit_size":64,"number_of_rounds":null}` | `plaintext` | yes | 32 | 332 | `verified` | 0.366 | `verified` | 9.942 | 0.311 | 2/2 | — |
| `SimonSbox` | `standard-1` | `{"block_bit_size":32,"key_bit_size":64,"number_of_rounds":32}` | `plaintext` | yes | 32 | 240 | `verified` | 1.657 | `verified` | 56.347 | 1.761 | 2/2 | — |
| `SimonSbox` | `standard-10` | `{"block_bit_size":128,"key_bit_size":256,"number_of_rounds":72}` | `plaintext` | yes | 72 | 992 | `verified` | 17.513 | `verified` | 440.884 | 6.123 | 2/2 | — |
| `SimonSbox` | `standard-2` | `{"block_bit_size":48,"key_bit_size":72,"number_of_rounds":36}` | `plaintext` | yes | 36 | 279 | `verified` | 1.938 | `verified` | 76.027 | 2.112 | 2/2 | — |
| `SimonSbox` | `standard-3` | `{"block_bit_size":48,"key_bit_size":96,"number_of_rounds":36}` | `plaintext` | yes | 36 | 308 | `verified` | 1.999 | `verified` | 83.120 | 2.309 | 2/2 | — |
| `SimonSbox` | `standard-4` | `{"block_bit_size":64,"key_bit_size":96,"number_of_rounds":42}` | `plaintext` | yes | 42 | 369 | `verified` | 2.757 | `verified` | 112.883 | 2.688 | 2/2 | — |
| `SimonSbox` | `standard-5` | `{"block_bit_size":64,"key_bit_size":128,"number_of_rounds":44}` | `plaintext` | yes | 44 | 424 | `verified` | 2.311 | `verified` | 139.857 | 3.179 | 2/2 | — |
| `SimonSbox` | `standard-6` | `{"block_bit_size":96,"key_bit_size":96,"number_of_rounds":52}` | `plaintext` | yes | 52 | 566 | `verified` | 3.206 | `verified` | 210.534 | 4.049 | 2/2 | — |
| `SimonSbox` | `standard-7` | `{"block_bit_size":96,"key_bit_size":144,"number_of_rounds":54}` | `plaintext` | yes | 54 | 585 | `verified` | 3.425 | `verified` | 217.768 | 4.033 | 2/2 | — |
| `SimonSbox` | `standard-8` | `{"block_bit_size":128,"key_bit_size":128,"number_of_rounds":68}` | `plaintext` | yes | 68 | 878 | `verified` | 4.081 | `verified` | 365.663 | 5.377 | 2/2 | — |
| `SimonSbox` | `standard-9` | `{"block_bit_size":128,"key_bit_size":192,"number_of_rounds":69}` | `plaintext` | yes | 69 | 888 | `verified` | 9.519 | `verified` | 395.793 | 5.736 | 2/2 | — |
| `Skinny` | `standard-1` | `{"block_bit_size":64,"key_bit_size":64,"number_of_rounds":32}` | `plaintext` | yes | 32 | 1313 | `verified` | 5.881 | `verified` | 182.127 | 5.691 | 2/2 | — |
| `Skinny` | `standard-2` | `{"block_bit_size":64,"key_bit_size":128,"number_of_rounds":36}` | `plaintext` | yes | 36 | 2045 | `verified` | 6.897 | `verified` | 295.214 | 8.200 | 2/2 | — |
| `Skinny` | `standard-3` | `{"block_bit_size":64,"key_bit_size":192,"number_of_rounds":40}` | `plaintext` | yes | 40 | 2905 | `verified` | 7.922 | `verified` | 445.202 | 11.130 | 2/2 | — |
| `Skinny` | `standard-4` | `{"block_bit_size":128,"key_bit_size":128,"number_of_rounds":40}` | `plaintext` | yes | 40 | 1641 | `verified` | 7.408 | `verified` | 344.063 | 8.602 | 2/2 | — |
| `Skinny` | `standard-5` | `{"block_bit_size":128,"key_bit_size":256,"number_of_rounds":48}` | `plaintext` | yes | 48 | 2729 | `verified` | 8.894 | `verified` | 608.081 | 12.668 | 2/2 | — |
| `Skinny` | `standard-6` | `{"block_bit_size":128,"key_bit_size":384,"number_of_rounds":56}` | `plaintext` | yes | 56 | 4073 | `verified` | 10.124 | `verified` | 829.113 | 14.806 | 2/2 | — |
| `Skipjack` | `default` | `{"number_of_rounds":32}` | `plaintext` | yes | 32 | 464 | `verified` | 3.047 | `verified` | 90.546 | 2.830 | 2/2 | — |
| `Speck` | `standard-1` | `{"block_bit_size":32,"key_bit_size":64,"number_of_rounds":22}` | `plaintext` | yes | 22 | 236 | `verified` | 0.424 | `verified` | 7.511 | 0.341 | 2/2 | — |
| `Speck` | `standard-10` | `{"block_bit_size":128,"key_bit_size":256,"number_of_rounds":34}` | `plaintext` | yes | 34 | 368 | `verified` | 0.444 | `verified` | 10.915 | 0.321 | 2/2 | — |
| `Speck` | `standard-2` | `{"block_bit_size":48,"key_bit_size":72,"number_of_rounds":22}` | `plaintext` | yes | 22 | 236 | `verified` | 0.404 | `verified` | 7.694 | 0.350 | 2/2 | — |
| `Speck` | `standard-3` | `{"block_bit_size":48,"key_bit_size":96,"number_of_rounds":23}` | `plaintext` | yes | 23 | 247 | `verified` | 0.390 | `verified` | 7.521 | 0.327 | 2/2 | — |
| `Speck` | `standard-4` | `{"block_bit_size":64,"key_bit_size":96,"number_of_rounds":26}` | `plaintext` | yes | 26 | 280 | `verified` | 0.446 | `verified` | 13.133 | 0.505 | 2/2 | — |
| `Speck` | `standard-5` | `{"block_bit_size":64,"key_bit_size":128,"number_of_rounds":27}` | `plaintext` | yes | 27 | 291 | `verified` | 0.428 | `verified` | 8.855 | 0.328 | 2/2 | — |
| `Speck` | `standard-6` | `{"block_bit_size":96,"key_bit_size":96,"number_of_rounds":28}` | `plaintext` | yes | 28 | 302 | `verified` | 0.398 | `verified` | 9.593 | 0.343 | 2/2 | — |
| `Speck` | `standard-7` | `{"block_bit_size":96,"key_bit_size":144,"number_of_rounds":29}` | `plaintext` | yes | 29 | 313 | `verified` | 0.447 | `verified` | 9.482 | 0.327 | 2/2 | — |
| `Speck` | `standard-8` | `{"block_bit_size":128,"key_bit_size":128,"number_of_rounds":32}` | `plaintext` | yes | 32 | 346 | `verified` | 1.329 | `verified` | 15.067 | 0.471 | 2/2 | — |
| `Speck` | `standard-9` | `{"block_bit_size":128,"key_bit_size":192,"number_of_rounds":33}` | `plaintext` | yes | 33 | 357 | `verified` | 0.395 | `verified` | 10.594 | 0.321 | 2/2 | — |
| `Speedy` | `standard-1` | `{"block_bit_size":192,"key_bit_size":192,"number_of_rounds":5}` | `plaintext` | yes | 5 | 521 | `verified` | 16.561 | `verified` | 4686.352 | 937.270 | 2/2 | — |
| `Splight` | `standard-1` | `{"block_bit_size":64,"key_bit_size":128,"number_of_rounds":32}` | `plaintext` | yes | 32 | 864 | `verified` | 6.034 | `verified` | 128.166 | 4.005 | 2/2 | — |
| `Subterranean` | `default` | `{"number_of_rounds":1}` | `plaintext` | yes | 1 | 11 | `verified` | 70.586 | `verified` | 29.587 | 29.587 | 2/2 | — |
| `TEA` | `default` | `{"block_bit_size":64,"key_bit_size":128,"left_shift_amount":4,"number_of_rounds":null,"right_shift_amount":5}` | `plaintext` | yes | 32 | 480 | `verified` | 0.741 | `verified` | 16.116 | 0.504 | 2/2 | — |
| `TinyJambu` | `default` | `{"key_bit_size":128,"number_of_rounds":640}` | `plaintext` | yes | 640 | 1920 | `verified` | 1.554 | `verified` | 1428.578 | 2.232 | 2/2 | — |
| `TinyJambuFSRWordBased` | `standard-1` | `{"key_bit_size":128,"number_of_rounds":640}` | `plaintext` | yes | 20 | 60 | `not-supported: ambiguous_boundary: primitive has no declared output` | — | `verified` | 64.208 | 3.210 | 2/2 | — |
| `TinyJambuWordBased` | `standard-1` | `{"key_bit_size":128,"number_of_rounds":640}` | `plaintext` | yes | 20 | 60 | `not-supported: ambiguous_boundary: primitive has no declared output` | — | `verified` | 53.359 | 2.668 | 2/2 | — |
| `Twine` | `standard-1` | `{"key_bit_size":80,"number_of_rounds":36}` | `plaintext` | yes | 36 | 900 | `verified` | 4.295 | `verified` | 192.093 | 5.336 | 2/2 | — |
| `Twine` | `standard-2` | `{"key_bit_size":128,"number_of_rounds":36}` | `plaintext` | yes | 36 | 972 | `verified` | 4.782 | `verified` | 194.494 | 5.403 | 2/2 | — |
| `Twofish` | `standard-1` | `{"key_length":128,"number_of_rounds":16}` | `plaintext` | yes | 16 | 1303 | `verified` | 38.160 | `verified` | 258.761 | 16.173 | 2/2 | — |
| `UKNIT` | `standard-1` | `{"number_of_rounds":12}` | `plaintext` | yes | 13 | 283 | `verified` | 4.192 | `verified` | 57.064 | 4.390 | 2/2 | — |
| `Ublock` | `default` | `{"block_bit_size":128,"key_bit_size":128,"number_of_rounds":null}` | `plaintext` | yes | 16 | 1121 | `verified` | 13.957 | `verified` | 223.386 | 13.962 | 2/2 | — |
| `UblockSingleLinearLayer` | `standard-1` | `{"block_bit_size":128,"key_bit_size":128,"number_of_rounds":16}` | `plaintext` | yes | 16 | 881 | `verified` | 14.286 | `verified` | 149.769 | 9.361 | 2/2 | — |
| `UblockSingleLinearLayer` | `standard-2` | `{"block_bit_size":128,"key_bit_size":256,"number_of_rounds":24}` | `plaintext` | yes | 24 | 1705 | `verified` | 20.834 | `verified` | 259.788 | 10.825 | 2/2 | — |
| `UblockSingleLinearLayer` | `standard-3` | `{"block_bit_size":256,"key_bit_size":256,"number_of_rounds":24}` | `plaintext` | yes | 24 | 2473 | `verified` | 34.880 | `verified` | 491.502 | 20.479 | 2/2 | — |
| `Warp` | `default` | `{"number_of_rounds":41}` | `plaintext` | yes | 41 | 1516 | `verified` | 5.321 | `verified` | 245.087 | 5.978 | 2/2 | — |
| `XTEA` | `default` | `{"block_bit_size":64,"key_bit_size":128,"left_shift_amount":4,"number_of_rounds":null,"right_shift_amount":5}` | `plaintext` | yes | 32 | 512 | `verified` | 0.684 | `verified` | 15.317 | 0.479 | 2/2 | — |

### block_functions

| Primitive | Parameter set | Parameters | Recover | Obligation | Graph rounds | Components | 1-round outcome | 1-round ms | Full outcome | Full ms | ms/round | Semantic | Diagnostic |
|---|---|---|---|:---:|---:|---:|---|---:|---|---:|---:|:---:|---|
| `A51` | `standard-1` | `{"frame_bit_size":22,"key_bit_size":64,"number_of_normal_clocks_at_initialization":100,"number_of_rounds":228}` | `key` | no | 229 | 633 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_1_1]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_1_1] |
| `A52` | `standard-1` | `{"frame_bit_size":22,"key_bit_size":64,"number_of_normal_clocks_at_initialization":100,"number_of_rounds":228}` | `key` | no | 229 | 2688 | `not-supported: multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_189]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_0_189] |
| `Bivium` | `standard-1` | `{"iv_bit_size":80,"key_bit_size":80,"keystream_bit_len":256,"number_of_initialization_clocks":708,"state_bit_size":177}` | `key` | no | 257 | 515 | `unavailable` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_256_0] |
| `ChaChaKeystreamBlock` | `standard-1` | `{"block_bit_size":512,"key_bit_size":256,"number_of_rounds":20}` | `plaintext` | yes | 41 | 978 | `verified` | 9.510 | `verified` | 48.100 | 1.173 | 2/2 | — |
| `SiphashMAC` | `standard-1` | `{"compression_rounds":2,"finalization_rounds":4,"message_byte_size":15,"output_bit_size":64}` | `input_message` | no | 9 | 131 | `unavailable` | — | `timeout` | — | — | — | inverse construction exceeded 30 s |
| `Snow3G` | `standard-1` | `{"iv_bit_size":128,"key_bit_size":128,"keystream_word_size":2,"number_of_initialization_clocks":32}` | `key` | no | 35 | 24651 | `unavailable` | — | `timeout` | — | — | — | inverse construction exceeded 30 s |
| `Trivium` | `default` | `{"keystream_bit_size":64,"number_of_initialization_clocks":1152}` | `key` | no | 1217 | 7362 | `unavailable` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_1153_0] |
| `Zuc` | `standard-1` | `{"iv_bit_size":128,"key_bit_size":128,"len_keystream_word":1,"number_of_initialization_clocks":32}` | `key` | no | 2 | 1035 | `unavailable` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [xor_1_22] |

### functions

| Primitive | Parameter set | Parameters | Recover | Obligation | Graph rounds | Components | 1-round outcome | 1-round ms | Full outcome | Full ms | ms/round | Semantic | Diagnostic |
|---|---|---|---|:---:|---:|---:|---|---:|---|---:|---:|:---:|---|
| `Blake` | `standard-1` | `{"block_bit_size":512,"number_of_rounds":28,"state_bit_size":512}` | `input_message` | no | 28 | 2016 | `not-supported: disconnected_dependency: known boundaries do not connect to every requested target wire [input_message]` | — | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [modadd_27_12] |
| `Blake` | `standard-2` | `{"block_bit_size":1024,"number_of_rounds":32,"state_bit_size":1024,"word_size":64}` | `input_message` | no | 32 | 2304 | `not-supported: disconnected_dependency: known boundaries do not connect to every requested target wire [input_message]` | — | `timeout` | — | — | — | inverse construction exceeded 30 s |
| `Blake2` | `standard-1` | `{"block_bit_size":1024,"number_of_rounds":12,"state_bit_size":1024}` | `input_message` | no | 12 | 1152 | `verified` | 85.424 | `not-supported` | — | — | — | multiple_predecessors: component output leaves multiple unknown predecessors [modadd_11_90] |
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
| `Ascon` | `default` | `{"number_of_rounds":12}` | `plaintext` | yes | 12 | 468 | `verified` | 31.802 | `verified` | 329.015 | 27.418 | 2/2 | — |
| `AsconSboxSigma` | `standard-1` | `{"number_of_rounds":12}` | `plaintext` | yes | 12 | 852 | `verified` | 25.539 | `verified` | 171.497 | 14.291 | 2/2 | — |
| `AsconSboxSigmaNoMatrix` | `standard-1` | `{"number_of_rounds":12}` | `plaintext` | yes | 12 | 972 | `verified` | 33.014 | `verified` | 340.339 | 28.362 | 2/2 | — |
| `ChaCha` | `default` | `{"number_of_rounds":20,"rotations":[16,12,8,7],"word_size":32}` | `state` | yes | 20 | 960 | `verified` | 2.060 | `verified` | 37.125 | 1.856 | 2/2 | — |
| `ChaskeyPi` | `standard-1` | `{"number_of_rounds":12,"word_size":32}` | `plaintext` | yes | 12 | 168 | `verified` | 4.973 | `verified` | 57.735 | 4.811 | 2/2 | — |
| `Forro` | `standard-1` | `{"number_of_rounds":14}` | `plaintext` | yes | 14 | 672 | `verified` | 27.596 | `verified` | 371.088 | 26.506 | 2/2 | — |
| `Forro` | `standard-2` | `{"number_of_rounds":10}` | `plaintext` | yes | 10 | 480 | `verified` | 25.002 | `verified` | 254.988 | 25.499 | 2/2 | — |
| `Gaston` | `default` | `{"number_of_rounds":12}` | `plaintext` | yes | 12 | 540 | `verified` | 116.624 | `verified` | 499.035 | 41.586 | 2/2 | — |
| `GastonSbox` | `standard-1` | `{"number_of_rounds":12}` | `plaintext` | yes | 12 | 1128 | `verified` | 112.058 | `verified` | 505.203 | 42.100 | 2/2 | — |
| `GastonSboxTheta` | `standard-1` | `{"number_of_rounds":12}` | `plaintext` | yes | 12 | 924 | `verified` | 53.119 | `verified` | 326.491 | 27.208 | 2/2 | — |
| `Gimli` | `default` | `{"number_of_rounds":24,"word_size":32}` | `plaintext` | yes | 24 | 1452 | `verified` | 112.314 | `verified` | 3071.740 | 127.989 | 2/2 | — |
| `GimliSbox` | `standard-1` | `{"number_of_rounds":24,"word_size":32}` | `plaintext` | yes | 24 | 4236 | `verified` | 80.882 | `verified` | 3058.631 | 127.443 | 2/2 | — |
| `GrainCore` | `standard-1` | `{"number_of_rounds":160}` | `input_state` | yes | 160 | 160 | `verified` | 1.355 | `verified` | 210.737 | 1.317 | 2/2 | — |
| `Keccak` | `default` | `{"number_of_rounds":24,"word_size":64}` | `plaintext` | yes | 24 | 3408 | `verified` | 1984.337 | `verified` | 14380.421 | 599.184 | 2/2 | — |
| `KeccakInvertible` | `default` | `{"number_of_rounds":24,"word_size":64}` | `plaintext` | yes | 24 | 9288 | `verified` | 2103.235 | `verified` | 15135.224 | 630.634 | 2/2 | — |
| `KeccakSbox` | `standard-1` | `{"number_of_rounds":18,"word_size":8}` | `plaintext` | yes | 18 | 1926 | `verified` | 57.938 | `verified` | 431.859 | 23.992 | 2/2 | — |
| `KeccakSbox` | `standard-2` | `{"number_of_rounds":16,"word_size":16}` | `plaintext` | yes | 16 | 2352 | `verified` | 155.645 | `verified` | 952.349 | 59.522 | 2/2 | — |
| `KeccakSbox` | `standard-3` | `{"number_of_rounds":20,"word_size":16}` | `plaintext` | yes | 20 | 2940 | `verified` | 149.683 | `verified` | 1178.977 | 58.949 | 2/2 | — |
| `Knot` | `standard-1` | `{"number_of_rounds":52,"state_bit_size":256}` | `plaintext` | yes | 52 | 3588 | `verified` | 11.016 | `verified` | 583.947 | 11.230 | 2/2 | — |
| `Knot` | `standard-2` | `{"number_of_rounds":76,"state_bit_size":384}` | `plaintext` | yes | 76 | 7676 | `verified` | 32.752 | `verified` | 1333.157 | 17.542 | 2/2 | — |
| `Knot` | `standard-3` | `{"number_of_rounds":100,"state_bit_size":512}` | `plaintext` | yes | 100 | 13300 | `verified` | 23.451 | `verified` | 2467.608 | 24.676 | 2/2 | — |
| `Norx` | `standard-1` | `{"number_of_rounds":4,"word_size":32}` | `plaintext` | yes | 4 | 768 | `verified` | 640.381 | `verified` | 2841.151 | 710.288 | 2/2 | — |
| `Norx` | `standard-2` | `{"number_of_rounds":4,"word_size":64}` | `plaintext` | yes | 4 | 768 | `verified` | 1494.565 | `verified` | 7259.642 | 1814.911 | 2/2 | — |
| `Photon` | `standard-1` | `{"t":256}` | `plaintext` | yes | 12 | 980 | `verified` | 10.273 | `verified` | 114.012 | 9.501 | 2/2 | — |
| `Salsa` | `default` | `{"number_of_rounds":20,"rotations":[7,9,13,18],"word_size":32}` | `state` | yes | 20 | 960 | `verified` | 2.558 | `verified` | 36.357 | 1.818 | 2/2 | — |
| `Sparkle` | `standard-1` | `{"number_of_blocks":4,"number_of_steps":7}` | `plaintext` | yes | 7 | 659 | `verified` | 38.812 | `verified` | 235.194 | 33.599 | 2/2 | — |
| `Sparkle` | `standard-2` | `{"number_of_blocks":4,"number_of_steps":10}` | `plaintext` | yes | 10 | 938 | `verified` | 33.724 | `verified` | 340.355 | 34.035 | 2/2 | — |
| `Sparkle` | `standard-3` | `{"number_of_blocks":6,"number_of_steps":7}` | `plaintext` | yes | 7 | 953 | `verified` | 47.484 | `verified` | 348.818 | 49.831 | 2/2 | — |
| `Sparkle` | `standard-4` | `{"number_of_blocks":6,"number_of_steps":11}` | `plaintext` | yes | 11 | 1493 | `verified` | 45.765 | `verified` | 586.452 | 53.314 | 2/2 | — |
| `Sparkle` | `standard-5` | `{"number_of_blocks":8,"number_of_steps":8}` | `plaintext` | yes | 8 | 1424 | `verified` | 69.738 | `verified` | 550.099 | 68.762 | 2/2 | — |
| `Sparkle` | `standard-6` | `{"number_of_blocks":8,"number_of_steps":12}` | `plaintext` | yes | 12 | 2132 | `verified` | 72.087 | `verified` | 846.475 | 70.540 | 2/2 | — |
| `Speckey` | `standard-1` | `{"number_of_rounds":1}` | `plaintext` | yes | 1 | 4 | `verified` | 1.474 | `verified` | 1.558 | 1.558 | 2/2 | — |
| `SpongentPi` | `default` | `{"number_of_rounds":80,"state_bit_size":160}` | `plaintext` | yes | 80 | 2080 | `verified` | 10.774 | `verified` | 323.830 | 4.048 | 2/2 | — |
| `SpongentPiFSR` | `default` | `{"number_of_rounds":80,"state_bit_size":160}` | `plaintext` | yes | 80 | 2080 | `verified` | 10.997 | `verified` | 320.515 | 4.006 | 2/2 | — |
| `SpongentPiPrecomputation` | `standard-1` | `{"number_of_rounds":80,"state_bit_size":160}` | `plaintext` | yes | 80 | 2000 | `verified` | 3.945 | `verified` | 302.022 | 3.775 | 2/2 | — |
| `SpongentPiPrecomputation` | `standard-2` | `{"number_of_rounds":90,"state_bit_size":176}` | `plaintext` | yes | 90 | 2430 | `verified` | 4.298 | `verified` | 384.338 | 4.270 | 2/2 | — |
| `Xoodoo` | `default` | `{"number_of_rounds":3}` | `plaintext` | yes | 3 | 108 | `verified` | 132.627 | `verified` | 158.030 | 52.677 | 2/2 | — |
| `XoodooInvertible` | `default` | `{"number_of_rounds":12}` | `plaintext` | yes | 12 | 1860 | `verified` | 127.700 | `verified` | 674.040 | 56.170 | 2/2 | — |
| `XoodooSbox` | `standard-1` | `{"number_of_rounds":12}` | `plaintext` | yes | 12 | 1860 | `verified` | 129.900 | `verified` | 687.034 | 57.253 | 2/2 | — |

### single_component_primitives

| Primitive | Parameter set | Parameters | Recover | Obligation | Graph rounds | Components | 1-round outcome | 1-round ms | Full outcome | Full ms | ms/round | Semantic | Diagnostic |
|---|---|---|---|:---:|---:|---:|---|---:|---|---:|---:|:---:|---|
| `Add` | `default` | `{"domain":null,"number_of_inputs":2,"unit_count":1}` | `input_0` | yes | 1 | 1 | `verified` | 0.188 | `verified` | 0.147 | 0.147 | 2/2 | — |
| `BinaryAffineMap` | `default` | `{"matrix":null,"offset":0,"unit_count":1,"word_size":4}` | `input` | yes | 1 | 1 | `verified` | 0.195 | `verified` | 0.137 | 0.137 | 2/2 | — |
| `BitVectorSBox` | `default` | `{"input_bit_size":4,"lookup_table":null,"output_bit_size":null}` | `input` | yes | 1 | 1 | `verified` | 0.206 | `verified` | 0.153 | 0.153 | 2/2 | — |
| `BitwiseAnd` | `default` | `{"number_of_inputs":2,"word_bit_size":4}` | `input_0` | no | 1 | 1 | `not-supported: information_loss: bitwise AND is not bijective in an operand [bitwise_and_0_0]` | — | `not-supported` | — | — | — | information_loss: bitwise AND is not bijective in an operand [bitwise_and_0_0] |
| `BitwiseNot` | `default` | `{"bit_size":4}` | `input` | yes | 1 | 1 | `verified` | 0.173 | `verified` | 0.133 | 0.133 | 2/2 | — |
| `BitwiseOr` | `default` | `{"number_of_inputs":2,"word_bit_size":4}` | `input_0` | no | 1 | 1 | `not-supported: information_loss: bitwise OR is not bijective in an operand [bitwise_or_0_0]` | — | `not-supported` | — | — | — | information_loss: bitwise OR is not bijective in an operand [bitwise_or_0_0] |
| `Constant` | `default` | `{"output_bit_size":3,"value":2}` | `—` | no | 1 | 1 | `not-applicable: primitive has no input to recover` | — | `not-applicable` | — | — | — | primitive has no input to recover |
| `FeedbackRegister` | `default` | `{"parameters":null}` | `input` | yes | 1 | 1 | `verified` | 0.220 | `verified` | 0.144 | 0.144 | 2/2 | — |
| `IDEAMultiply` | `default` | `{"number_of_inputs":2,"word_bit_size":16}` | `input_0` | yes | 1 | 1 | `verified` | 0.200 | `verified` | 0.158 | 0.158 | 2/2 | — |
| `Identity` | `default` | `{"bit_size":32}` | `input` | yes | 1 | 1 | `verified` | 0.337 | `verified` | 0.250 | 0.250 | 2/2 | — |
| `LinearMap` | `default` | `{"domain":null,"matrix":null}` | `input` | yes | 1 | 1 | `verified` | 0.206 | `verified` | 0.138 | 0.138 | 2/2 | — |
| `ModularAdd` | `default` | `{"number_of_inputs":2,"word_bit_size":4}` | `input_0` | yes | 1 | 1 | `verified` | 0.339 | `verified` | 0.180 | 0.180 | 2/2 | — |
| `ModularMultiply` | `default` | `{"number_of_inputs":2,"word_bit_size":4}` | `input_0` | no | 1 | 1 | `not-supported: information_loss: modular multiplication is not bijective for every auxiliary [modular_multiply_0_0]` | — | `not-supported` | — | — | — | information_loss: modular multiplication is not bijective for every auxiliary [modular_multiply_0_0] |
| `ModularSubtract` | `default` | `{"number_of_inputs":2,"word_bit_size":4}` | `input_0` | yes | 1 | 1 | `verified` | 0.218 | `verified` | 0.154 | 0.154 | 2/2 | — |
| `Multiply` | `default` | `{"domain":null,"number_of_inputs":2,"unit_count":1}` | `input_0` | no | 1 | 1 | `not-supported: information_loss: multiplication is not bijective when an auxiliary can be zero [multiply_0_0]` | — | `not-supported` | — | — | — | information_loss: multiplication is not bijective when an auxiliary can be zero [multiply_0_0] |
| `Permutation` | `default` | `{"mapping":null,"word_size":1}` | `input` | yes | 1 | 1 | `verified` | 0.221 | `verified` | 0.155 | 0.155 | 2/2 | — |
| `Power` | `default` | `{"domain":null,"exponent":3,"unit_count":1}` | `input` | yes | 1 | 1 | `verified` | 0.182 | `verified` | 0.131 | 0.131 | 2/2 | — |
| `Rotate` | `default` | `{"amount":1,"bit_size":8,"direction":"right"}` | `input` | yes | 1 | 1 | `verified` | 0.173 | `verified` | 0.127 | 0.127 | 2/2 | — |
| `SBox` | `default` | `{"domain":null,"lookup_table":null,"unit_count":1}` | `input` | yes | 1 | 1 | `verified` | 0.171 | `verified` | 0.137 | 0.137 | 2/2 | — |
| `Shift` | `default` | `{"amount":1,"bit_size":8,"direction":"right"}` | `input` | no | 1 | 1 | `not-supported: information_loss: fixed shifts discard bits [shift_0_0]` | — | `not-supported` | — | — | — | information_loss: fixed shifts discard bits [shift_0_0] |
| `VariableRotate` | `default` | `{"amount_bit_size":3,"bit_size":8,"direction":"right"}` | `input` | yes | 1 | 1 | `verified` | 0.201 | `verified` | 0.154 | 0.154 | 2/2 | — |
| `VariableShift` | `default` | `{"amount_bit_size":3,"bit_size":8,"direction":"right"}` | `input` | no | 1 | 1 | `not-supported: information_loss: variable shifts can discard bits [variable_shift_0_0]` | — | `not-supported` | — | — | — | information_loss: variable shifts can discard bits [variable_shift_0_0] |
| `Xor` | `default` | `{"number_of_inputs":2,"word_bit_size":4}` | `input_0` | yes | 1 | 1 | `verified` | 0.186 | `verified` | 0.152 | 0.152 | 2/2 | — |

### toy_primitives

| Primitive | Parameter set | Parameters | Recover | Obligation | Graph rounds | Components | 1-round outcome | 1-round ms | Full outcome | Full ms | ms/round | Semantic | Diagnostic |
|---|---|---|---|:---:|---:|---:|---|---:|---|---:|---:|:---:|---|
| `CipherFour` | `default` | `{"block_bit_size":16,"key_bit_size":16,"number_of_rounds":5,"permutations":null,"rotation_layer":1,"sbox":null}` | `plaintext` | yes | 5 | 30 | `construction-error: ValueError: position 64 is outside source 'key' with 32 logical units` | — | `verified` | 3.465 | 0.693 | 2/2 | — |
| `Fancy` | `default` | `{"block_bit_size":24,"key_bit_size":24,"number_of_rounds":20}` | `plaintext` | no | 20 | 250 | `verified` | 1.833 | `not-supported` | — | — | — | information_loss: fixed shifts discard bits [shift_19_11] |
| `Heys` | `default` | `{"block_bit_size":16,"key_bit_size":80,"number_of_rounds":4}` | `plaintext` | yes | 4 | 24 | `verified` | 0.969 | `verified` | 2.689 | 0.672 | 2/2 | — |
| `ToyAES` | `default` | `{"number_of_rounds":10,"state_size":4,"word_size":8}` | `plaintext` | yes | 10 | 127 | `verified` | 1.456 | `verified` | 9.436 | 0.944 | 2/2 | — |
| `ToyFeistel` | `default` | `{"block_bit_size":8,"key_bit_size":8,"number_of_rounds":5,"sbox":[14,9,15,0,13,4,10,11,1,2,8,3,7,6,12,5]}` | `plaintext` | yes | 5 | 35 | `verified` | 0.911 | `verified` | 3.563 | 0.713 | 2/2 | — |
| `ToySPN1` | `default` | `{"block_bit_size":6,"key_bit_size":6,"number_of_rounds":2,"rotation_layer":1,"sbox":[0,5,3,2,6,1,4,7]}` | `plaintext` | yes | 2 | 8 | `verified` | 0.842 | `verified` | 0.733 | 0.366 | 2/2 | — |
| `ToySPN2` | `default` | `{"block_bit_size":6,"key_bit_size":6,"number_of_rounds":2,"rotation_layer":1,"round_key_rotation":1,"sbox":[0,5,3,2,6,1,4,7]}` | `plaintext` | yes | 2 | 10 | `verified` | 0.877 | `verified` | 0.829 | 0.415 | 2/2 | — |

### tweakable_block_ciphers

| Primitive | Parameter set | Parameters | Recover | Obligation | Graph rounds | Components | 1-round outcome | 1-round ms | Full outcome | Full ms | ms/round | Semantic | Diagnostic |
|---|---|---|---|:---:|---:|---:|---|---:|---|---:|---:|:---:|---|
| `BipBip` | `standard-1` | `{"number_of_core_rounds":5,"number_of_shell_rounds_1":3,"number_of_shell_rounds_2":3}` | `plaintext` | yes | 12 | 179 | `unavailable` | — | `verified` | 210.949 | 17.579 | 2/2 | — |
| `Blink` | `standard-1` | `{"a":2,"b":3,"block_bit_size":64,"key_bit_size":448,"tweak_bit_size":64}` | `plaintext` | yes | 10 | 1162 | `unavailable` | — | `verified` | 2987.477 | 298.748 | 2/2 | — |
| `Blink` | `standard-2` | `{"a":2,"b":3,"block_bit_size":64,"key_bit_size":448,"tweak_bit_size":128}` | `plaintext` | yes | 10 | 1162 | `unavailable` | — | `verified` | 4540.313 | 454.031 | 2/2 | — |
| `Blink` | `standard-3` | `{"a":3,"b":3,"block_bit_size":128,"key_bit_size":1024,"tweak_bit_size":128}` | `plaintext` | yes | 12 | 2572 | `unavailable` | — | `verified` | 11176.053 | 931.338 | 2/2 | — |
| `Blink` | `standard-4` | `{"a":3,"b":3,"block_bit_size":128,"key_bit_size":1024,"tweak_bit_size":256}` | `plaintext` | yes | 12 | 2572 | `unavailable` | — | `verified` | 18985.496 | 1582.125 | 2/2 | — |
| `Blink` | `standard-5` | `{"a":3,"b":5,"block_bit_size":128,"key_bit_size":1280,"tweak_bit_size":128}` | `plaintext` | yes | 16 | 3088 | `unavailable` | — | `verified` | 15322.347 | 957.647 | 2/2 | — |
| `Blink` | `standard-6` | `{"a":3,"b":5,"block_bit_size":128,"key_bit_size":1280,"tweak_bit_size":256}` | `plaintext` | yes | 16 | 3088 | `unavailable` | — | `verified` | 23211.637 | 1450.727 | 2/2 | — |
| `Chilow` | `default` | `{"number_of_rounds":1,"tau":null}` | `plaintext` | yes | 1 | 16 | `verified` | 25.781 | `verified` | 7.298 | 7.298 | 2/2 | — |
| `Mantis` | `default` | `{"number_of_rounds":6}` | `plaintext` | yes | 12 | 426 | `verified` | 21.210 | `verified` | 89.079 | 7.423 | 2/2 | — |
| `QARMAv2` | `default` | `{"key_bit_size":128,"number_of_layers":1,"number_of_rounds":10,"tweak_bit_size":128}` | `plaintext` | yes | 21 | 1197 | `verified` | 63.137 | `verified` | 297.939 | 14.188 | 2/2 | — |
| `QARMAv2MixColumn` | `standard-1` | `{"key_bit_size":128,"number_of_layers":1,"number_of_rounds":10,"tweak_bit_size":128}` | `plaintext` | yes | 21 | 685 | `verified` | 41.702 | `verified` | 146.703 | 6.986 | 2/2 | — |
| `SCARF` | `default` | `{"number_of_rounds":8}` | `plaintext` | yes | 8 | 188 | `verified` | 16.326 | `verified` | 34.438 | 4.305 | 2/2 | — |
| `Threefish` | `default` | `{"block_bit_size":256,"key_bit_size":null,"number_of_rounds":null,"tweak_bit_size":128}` | `plaintext` | yes | 73 | 590 | `verified` | 1.182 | `verified` | 25.587 | 0.351 | 2/2 | — |
| `Trax` | `default` | `{"number_of_rounds":17}` | `plaintext` | yes | 17 | 1876 | `verified` | 4.282 | `verified` | 76.279 | 4.487 | 2/2 | — |

## Reproduction

From `next/`:

```console
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3.11 tools/audit_primitive_inversion.py
```

The report is a point-in-time benchmark. Compare future methodology changes on the same machine, Python version, timeout, and repetition count.
