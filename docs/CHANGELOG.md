# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2023-11-27

### Added

- Unifying SAT xor diff and checker models
- create new a51 stream cipher with fsr component.
- create new tinyjambu permutation with fsr component.
- create new spongent pi permutation with fsr component.
- component_values to Minizinc output model
- Adding graph generator based on cipher component IDs
- create new BEA-1 cipher
- Adding max number of carries
- vectorized implementation of neural_network distinguishers and support for training round selection
- possibility to check differential trails automatically
- Compounded Xor Differential Cipher
- Salsa Permutation

### Changed

- Moved get_key_schedule_component_ids
- replaced BEA1 concatenate component for CP compatibility
- update cipher documentation with BEA-1
- window_size heuristic
- Latin Dances Ciphers
- Extracting init method from Salsa/Chacha
- Extracting methods from Salsa/ChaCha Extracting common methods from Salsa/ChaCha to util latin dances
- removing duplicate code

### Fixed

- Add ciphers folder to SonarCloud exclusion.
- xor-diff-mzn-model
- upgrade Tensorflow to work with m1 architecture
- compactification of cipher in SAT
- fix the bug of the nist_statistical_tests_test.py when the experiments folder existed, then the nist sts tools will stopped. fix the bug that some nist test files generated during runtime has incorrect read write permission.
- MILP external file paths are now absolute
- solver name added to input files names for testing cp models
- find_one_xor_differential_trail in cp two steps model
- test_find_all_xor_differential_trails_with_fixed_weight in two steps version
- number of active sboxes constraint generation
- updated instructions to set up Sagemath Python interpreter into PyCharm
- Kissat parsing

## [1.0.0] - 2023-04-28

### Added

- Everything! First public release.

[1.1.0]: https://github.com/Crypto-TII/claasp/releases/tag/v1.1.0
[1.0.0]: https://github.com/Crypto-TII/claasp/releases/tag/v1.0.0
