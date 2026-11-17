# LEA Test Results LaTeX Tables

This document describes the LaTeX tables generated from LEA test log files.

## Generation Script

**File:** `generate_lea_latex_tables.py`

This Python script automatically parses LEA test log files from `test_operation_modadd/test_lea/` and generates professionally formatted LaTeX tables.

### Features

- ✅ Automatically extracts test parameters (R, r_0, r_m, r_1) from directory names
- ✅ Parses log files to extract:
  - Weights: Upper, Lower, Middle, Trail
  - Execution time
  - Seed numbers
- ✅ Calculates derived probabilities:
  - `p = 2^-upper`
  - `q = 2^-lower`
  - `r = 2^-middle`
  - `p^2q^2r = total probability`
- ✅ Formats all values with appropriate precision
  - Times: rounded to 2 decimal places
  - Probabilities: formatted in scientific notation for small values
- ✅ Generates two types of tables

## Output File

**File:** `lea_tables.tex`

Contains LaTeX-ready table definitions that can be included in a document with:
```latex
\input{lea_tables.tex}
```

## Table Types

### Table 1: Best Probability Results

**Title:** "LEA Test Results - Best Probability"

Contains the single best result (highest total probability) for each test configuration.

**Columns:**
- `R` - Number of rounds
- `$r_0$` - Parameter r_0
- `$r_m$` - Parameter r_m  
- `$r_1$` - Parameter r_1
- `$p$` - Probability 2^-upper
- `$q$` - Probability 2^-lower
- `$r$` - Probability 2^-middle
- `$p^2q^2r$` - Total probability
- `Seed` - Random seed used
- `Time (s)` - Execution time in seconds

### Tables 2+: Per-Configuration Results

For each test configuration (e.g., test_10r_4_1_5, test_11r_5_1_5, etc.), a separate table is generated containing all seed results.

**Columns:**
- `$r_0$`, `$r_m$`, `$r_1$` - Parameters (constant for each table)
- `$p$`, `$q$`, `$r$` - Probabilities
- `$p^2q^2r$` - Total probability
- `Seed` - Seed number (sorted)
- `Time (s)` - Execution time

## Test Configurations Included

| Configuration | Seeds | Rounds | Remarks |
|---|---|---|---|
| test_10r_4_1_5 | 10 | 10 | Base configuration |
| test_11r_5_1_5 | 10 | 11 | Extended rounds |
| test_12r_5_1_6 | 10 | 12 | Extended rounds |
| test_13r_6_1_6 | 10 | 13 | Extended rounds |
| test_14r_7_1_6 | 11 | 14 | Extended rounds |
| test_16r_8_1_7 | 10 | 16 | Extended rounds |
| test_16r_8_1_7_for_2_days | 10 | 16 | 2-day run |
| test_16r_8_1_7_time_1week_threads_24 | 10 | 16 | 1-week run, 24 threads |

**Total entries processed:** 81

## Usage

1. Run the generation script:
   ```bash
   python3 generate_lea_latex_tables.py
   ```

2. Include the generated tables in your LaTeX document:
   ```latex
   \documentclass{article}
   \usepackage{booktabs}
   
   \begin{document}
   
   \section{LEA Test Results}
   
   \input{lea_tables.tex}
   
   \end{document}
   ```

3. Compile with pdflatex or your preferred LaTeX compiler

## Probability Calculation Details

For each log entry, the script calculates:

```
p = 2^(-upper_weight)
q = 2^(-lower_weight)
r = 2^(-middle_weight)
total_prob = p^2 × q^2 × r
```

These represent the differential probabilities in the cryptanalysis.

## Notes

- All time values are given in seconds
- Very small probabilities are displayed in scientific notation (e.g., `2.14e-10`)
- The script automatically handles missing or incomplete log files
- Times shown include MiniZinc solver overhead
