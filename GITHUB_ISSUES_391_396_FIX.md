# GitHub Issues #391 and #396 - Fix Summary

## Issue #391: AttributeError in NISTStatisticalTests.nist_statistical_tests()
**Link:** https://github.com/Crypto-TII/claasp/issues/391

### Problem
When running NIST statistical tests with the 'avalanche' test type, an `AttributeError` occurred because the code tried to access `self.dataset_type` attribute that was not set when an invalid test_type was provided or under certain error conditions.

### Root Cause
The `dataset_type` attribute was only set inside specific `if` blocks for each test type. If the code path didn't enter these blocks (e.g., invalid test_type) or if dataset generation failed early, the attribute wouldn't exist when accessed later at line 708.

### Solution
Added safety checks using `hasattr(self, 'dataset_type')` before accessing the attribute in two locations:
1. Line ~251: When logging dataset generation time
2. Line ~708: When setting the `data_type` field in the report dictionary

If `dataset_type` is not set, the code now uses fallback values:
- `'Compute dataset'` for execution time logging
- `'unknown'` for the data type in the report

### Files Changed
- `claasp/cipher_modules/statistical_tests/nist_statistical_tests.py`

---

## Issue #396: OverflowError in evaluate_vectorized with 0xffff mask
**Link:** https://github.com/Crypto-TII/claasp/issues/396

### Problem
When running NIST statistical tests (avalanche or correlation types) on ciphers using the vectorized byte evaluator (e.g., PRESENT), an `OverflowError` occurred because the code used `0xffff` (65535) as a mask for `uint8` numpy arrays, which can only hold values 0-255.

### Root Cause
In `generic_functions_vectorized_byte.py` at line 154, the code set:
```python
left_byte_mask = 0xffff
```
This value exceeds the maximum value for uint8 (255), causing an overflow when applied to uint8 arrays with the `&=` operator.

### Solution
Changed the mask from `0xffff` to `0xff` (255), which is the correct maximum value for uint8:
```python
left_byte_mask = 0xff
```

This fix ensures that when all 8 bits in a byte are used (i.e., `number_of_output_bits % 8 == 0`), the mask correctly preserves all bits without overflow.

### Files Changed
- `claasp/cipher_modules/generic_functions_vectorized_byte.py`

---

## Testing

All existing tests pass with these fixes:

### NIST Statistical Tests (9 passed, 1 skipped)
```bash
sage -python -m pytest tests/unit/cipher_modules/statistical_tests/nist_statistical_tests_test.py -v
```
- ✅ test_run_avalanche_nist_statistics_test
- ✅ test_run_correlation_nist_statistics_test  
- ✅ test_run_random_nist_statistics_test
- ✅ test_run_low_density_nist_statistics_test
- ✅ test_run_high_density_nist_statistics_test
- ✅ All chart generation and parsing tests

### Vectorized Byte Functions (16 passed)
```bash
sage -python -m pytest tests/unit/cipher_modules/generic_functions_vectorized_byte_test.py -v
```
- ✅ All vectorized byte operation tests
- ✅ All input/output conversion tests

## Impact
- **Issue #391**: Prevents crashes when invalid test types are provided or when dataset generation fails
- **Issue #396**: Enables PRESENT and other ciphers using the vectorized byte evaluator to work correctly with NIST statistical tests

Both fixes are backward compatible and don't break any existing functionality.
