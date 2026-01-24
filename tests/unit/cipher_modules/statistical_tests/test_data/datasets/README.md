# Datasets for NIST STS equivalence tests

This folder contains fixed datasets used by the NIST STS equivalence test suite.

## Files

- random_ascii_small.txt: ASCII bitstream dataset (10 sequences, 1,000 bits each, random seed 11111).
- random_ascii_medium.txt: ASCII bitstream dataset (100 sequences, 10,000 bits each, random seed 22222).
- random_binary_small.bin: Binary dataset (10 sequences, 1,000 bits each, random seed 33333).
- random_binary_medium.bin: Binary dataset (100 sequences, 10,000 bits each, random seed 44444).
- structured_alternating_ascii.txt: ASCII dataset with alternating pattern (10 sequences, 10,000 bits each, seed 55555).
- structured_blocks_binary.bin: Binary dataset with block pattern (10 sequences, 10,000 bits each, seed 66666).
- subset_tests_random.bin: Binary dataset used for subset test selection (10 sequences, 10,000 bits each, seed 77777).
- nist_sts_test_vectors.json: Reference test vectors for unit tests.

All datasets are deterministic and can be regenerated using the scripts in scripts_to_generate_datasets.
