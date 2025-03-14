# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.0.0] - 2025-03-14

### Added

- Adding seed and number_of_processors parameters on cda.
- Support for differential-linear trails on report module.
- Optional probabilistic propagations for key schedule in the hybrid impossible model.
- Hybrid model for xor impossible differential trail search.
- Sat model for differential-linear distinguishers.
- Differential-linear checker.
- Add differential-linear search.
- Add commands to use gurobi in github server.
- Add a way to choose a component as cipher_output.
- New representation for aradi block cipher.
- Create ublock cipher.
- Create twine block cipher object.
- Build_generic_sat_model.
- Add support for heterogeneous model creation.
- Standard docstring head for sat and smt components.
- Build_generic_sat_model_from_dictionary.
- Clearer docstrings for sat and smt components.
- Merging models.
- Add automatic publish on pypi workflow.
- Fix typo in docker image name.
- Add m1 build workflow.
- Run docker image without pre-building.
- New interface of nist statistical tests.

### Changed

- Differential-linear cryptanalysis model.
- More compact lowmc sbox and linear layers.
- Refactor two methods in satxorlinearmodel.
- Fix_variables_value_constraints.
- Speed improvement on the division trail search module.
- Moving window_size_weight_pr_vars.
- Unified solve method for new unique minizinc model; defined internal solvers.

### Fixed

- Cp id bitwise model.
- Cp id bitwise model and align hybrid model.
- Addressing sonarqube issue.
- Adding seed to differential_linear tests.
- Addressing sonar reliability issue.
- Fixing differential-linear trail model.
- Mzn hybrid model for permutations.
- Sbox deterministic truncated constraints.
- Calculate_component_weight.
- Doctest.
- Xor linear model output issue.
- Minor errors.
- Mzn and not cp in testing.
- Update actions/download-artifact version.
- Update actions/upload-artifact version.
- Correct parameters for the nist statistical tests and dieharder.

## [3.0.0] - 2025-03-14

### Added

- Adding seed and number_of_processors parameters on cda.
- Support for differential-linear trails on report module.
- Optional probabilistic propagations for key schedule in the hybrid impossible model.
- Hybrid model for xor impossible differential trail search.
- Sat model for differential-linear distinguishers.
- Differential-linear checker.
- Add differential-linear search.
- Add commands to use gurobi in github server.
- Add a way to choose a component as cipher_output.
- New representation for aradi block cipher.
- Create ublock cipher.
- Create twine block cipher object.
- Build_generic_sat_model.
- Add support for heterogeneous model creation.
- Standard docstring head for sat and smt components.
- Build_generic_sat_model_from_dictionary.
- Clearer docstrings for sat and smt components.
- Merging models.
- Add automatic publish on pypi workflow.
- Fix typo in docker image name.
- Add m1 build workflow.
- Run docker image without pre-building.
- New interface of nist statistical tests.

### Changed

- Differential-linear cryptanalysis model.
- More compact lowmc sbox and linear layers.
- Refactor two methods in satxorlinearmodel.
- Fix_variables_value_constraints.
- Speed improvement on the division trail search module.
- Moving window_size_weight_pr_vars.
- Unified solve method for new unique minizinc model; defined internal solvers.

### Fixed

- Cp id bitwise model.
- Cp id bitwise model and align hybrid model.
- Addressing sonarqube issue.
- Adding seed to differential_linear tests.
- Addressing sonar reliability issue.
- Fixing differential-linear trail model.
- Mzn hybrid model for permutations.
- Sbox deterministic truncated constraints.
- Calculate_component_weight.
- Doctest.
- Xor linear model output issue.
- Minor errors.
- Mzn and not cp in testing.
- Update actions/download-artifact version.
- Update actions/upload-artifact version.
- Correct parameters for the nist statistical tests and dieharder.

## [2.6.0] - 2024-08-23

### Added

- Added prince cipher.
- Implement s-box version of simeck cipher.
- Implement simeck cipher.
- Testing.
- Working model for impossible xor differential trail extension for key recovery.
- Find lowest varied deterministic truncated xor differential trail search for cp.
- Cp impossible wordwise model and impossible trails extension.
- Allow sat s-boxes to handle rectangular case.
- Create new version of simon cipher.

### Changed

- Rename hash input from key to message.
- Improved incompatibility search in intermediate components.
- Window_size heuristic.

### Fixed

- Correct the incorrect show_graph paramter settings.
- Continuous diffusion analysis.
- Manipulate correctly rectangular s-boxes in smt.
- Doctests.
- Window_size heuristic. adding check for window -1.
- Codes duplications.
- Adressed slow pytests for lowmc cipher and milp xor differential trail search.
- Code smells.
- Removed the empty input_id_link that could occur in some cases of the partial inversion.
- 'plaintext' key error when using vectorized evaluation on a partially inverted cipher.
- Update sphinx version.
- Impossible attack extension model for cp.

## [2.5.0] - 2024-05-22

### Added

- Non rectangular s-boxes support for milp models.
- Solvers options and modularity.
- Cp solvers names and method.

### Changed

- Processing of intermediate outputs fixed for partial cipher creation method.
- Rearrange smt solver specifications.
- Rearrange sat solver specifications.
- Window size feature.

### Fixed

- Fix create_bash_script.py for local installation after distribution change.
- Fix platform and gurobi version for m1.
- Or component cp linear propagation declarations.
- Remove concatenate component in kasumi.

## [2.4.0] - 2024-04-06

### Added

- Added method to get milp solvers.
- Coinbc backend for milp module.

### Fixed

- Added date time to report folders and statistical tests folders. fixed neural network error message fixed trails output format to include hex words.
- Fixed trail search output format.

## [2.3.0] - 2024-03-22

### Added

- Create new speedy cipher.
- Create the a5/2 stream cipher.
- Create a test function for nist statistical tests and dieharder statistical tests that produces a parsed result, standardized for the report class.
- Gaston permutation with sbox component.
- Create qarmav2 with mixcolumn component.
- Support inversion of tweakable primitives and inversion of mixcolumn operation with a non irreducible polynomial.
- Adding bct mzn model for arx ciphers.
- Add option to start chacha permutation from a bottom lower round.
- Adding minizinc boomerang model.

### Changed

- Location of files related to milp inequalities for non linear components or large xors moved to userspace.
- Location of files related to milp external solvers change to current working directory.
- Continuous_tests to class.

### Fixed

- Add timestamp to milp external files.
- File path in cp module changed to absolute path.
- Consider whole solution when searching xor linear trails.
- Refactoring of algebraic tests to an object.
- Create claasp base image for test.
- Fix sonarcloud github action so forks can be analyzed on pr.

## [2.2.0] - 2024-03-07

### Added

- Create new Speedy cipher
- Create the A5/2 stream cipher
- Create the grain128 stream cipher
- Create a test function for nist statistical tests and dieharder statistical tests that produces a parsed result, standardized for the Report class
- SAT wordwise deterministic truncated XOR differential trail model
- Gaston permutation with sbox component
- Create Qarmav2 with MixColumn component
- Support inversion of tweakable primitives and inversion of MixColumn operation with a non irreducible polynomial
- Add option to start Chacha permutation from a bottom lower round
- Create bitwise impossible XOR differential trail search for SAT

### Changed

- Location of files related to MILP inequalities for non linear components or large xors moved to userspace
- Location of files related to MILP external solvers change to current working directory
- Continuous_tests to class

### Fixed

- Add timestamp to MILP external files
- File path in CP module changed to absolute path
- Consider whole solution when searching XOR linear trails
- Refactored algebraic tests to an object and added some tests
- Refactoring of algebraic tests to an object
- Create CLAASP base image for test
- Fix SonarCloud GitHub Action so Forks can be analyzed on PR

## [2.1.0] - 2024-01-30

### Added

- Sat deterministic truncated xor differential trail search.
- Fully automatic milp search of xor differential impossible trails at component level.
- Implement sat constraints for or operation.
- Add action to build claasp-lib image every time a new version is deployed to main.
- Create multi-stage build to generate docker image of claasp.
- Add sat deterministic truncated trail search.

### Changed

- Qarmav2 creator optimized, permutations removed and complexity reduced.

### Fixed

- Inversion for primitives using subkeys as inputs.
- Fixing networkx and numpy versions.
- Adapted tests.
- Move sat constraints for and in correct module.

## [2.0.0] - 2023-12-04

### Added

- Create report class Change: refactor statistical test functions and trail search functions outputs Change: refactor old pytest files for statistical test functions and trail search functions. Remove: remove old functions to create dataframes and heatmaps for statistical test functions
- External solver support for MILP truncated/impossible modules
- Implement scarf block cipher
- Window heuristic per modular addition

### Fixed

- Fix versioning

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

[4.0.0]: https://github.com/Crypto-TII/claasp/compare/v4.0.0..v3.0.0
[3.0.0]: https://github.com/Crypto-TII/claasp/compare/v3.0.0..v2.6.0
[2.6.0]: https://github.com/Crypto-TII/claasp/compare/v2.6.0..v2.5.0
[2.5.0]: https://github.com/Crypto-TII/claasp/compare/v2.5.0..v2.4.0
[2.4.0]: https://github.com/Crypto-TII/claasp/compare/v2.4.0..v2.3.0
[2.3.0]: https://github.com/Crypto-TII/claasp/compare/v2.3.0..v2.1.0
[2.1.0]: https://github.com/Crypto-TII/claasp/compare/v2.1.0..v2.0.0
[1.1.0]: https://github.com/Crypto-TII/claasp/releases/tag/v1.1.0
[1.0.0]: https://github.com/Crypto-TII/claasp/releases/tag/v1.0.0
