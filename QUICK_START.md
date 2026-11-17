# LEA LaTeX Tables - Quick Start Guide

## What Was Generated

✅ **generate_lea_latex_tables.py** - Python script that parses LEA test logs
✅ **lea_tables.tex** - Generated LaTeX tables (ready to use!)
✅ **LEA_TABLES_README.md** - Detailed documentation
✅ **GENERATION_SUMMARY.txt** - Complete statistics

## Files Generated

```
/raid/homespace/rocbrunelli/claasp_x_boomerang/claasp/
├── generate_lea_latex_tables.py       # Main script
├── lea_tables.tex                      # Generated LaTeX (OUTPUT)
├── LEA_TABLES_README.md                # Documentation
├── GENERATION_SUMMARY.txt              # Statistics
└── QUICK_START.md                      # This file
```

## What's in lea_tables.tex

**9 professional LaTeX tables:**
- 1 overview table (best results)
- 8 per-configuration tables (all seeds for each configuration)

**219 lines of LaTeX code**
- Ready to include in your document
- Fully formatted with captions and labels
- Properly escaped for LaTeX compilation

## Quick Usage

### To use in your LaTeX document:

```latex
\documentclass{article}
\usepackage{geometry}
\usepackage{booktabs}

\begin{document}

\section{LEA Cryptanalysis Results}

\input{lea_tables.tex}

\end{document}
```

### To compile:

```bash
pdflatex your_document.tex
```

## To Regenerate Tables

If new test logs are added:

```bash
cd /raid/homespace/rocbrunelli/claasp_x_boomerang/claasp
python3 generate_lea_latex_tables.py
```

The script automatically:
- Finds all test directories under `test_operation_modadd/test_lea/`
- Parses all `.log` files
- Extracts parameters and weights
- Calculates probabilities
- Generates formatted LaTeX tables

## Data Included

| Config | Seeds | Rounds |
|--------|-------|--------|
| test_10r_4_1_5 | 10 | 10 |
| test_11r_5_1_5 | 10 | 11 |
| test_12r_5_1_6 | 10 | 12 |
| test_13r_6_1_6 | 10 | 13 |
| test_14r_7_1_6 | 11 | 14 |
| test_16r_8_1_7 | 10 | 16 |
| test_16r_8_1_7_for_2_days | 10 | 16 |
| test_16r_8_1_7_time_1week_threads_24 | 10 | 16 |

**Total: 81 log entries processed**

## Table Columns

### Overview Table
- **R** - Number of rounds
- **r₀, rₘ, r₁** - Test parameters
- **p** - 2^(-upper) probability
- **q** - 2^(-lower) probability
- **r** - 2^(-middle) probability
- **p²q²r** - Combined probability
- **Seed** - Random seed used
- **Time** - Execution time (seconds)

### Per-Configuration Tables
Same columns minus R (which is constant per table)

## Number Formatting

- **Times**: 2 decimal places (86408.55 s)
- **Large probabilities**: Decimal (0.9202)
- **Small probabilities**: Scientific (2.14e-10)

## Key Features

✅ Automatic extraction from log files
✅ Robust error handling for missing files
✅ Proper LaTeX formatting with math mode
✅ Professional table layout with borders
✅ Auto-calculated probabilities
✅ Descriptive captions and labels
✅ Sorted by seed for easy comparison
✅ Best result selection by probability

## Probability Calculation

For each test result:

```
Upper weight = U
Lower weight = L
Middle weight = M

p = 2^(-U)
q = 2^(-L)
r = 2^(-M)
total = p² × q² × r
```

This represents the differential probability in the cryptanalysis.

## Example: Using a Table in a Document

```latex
\documentclass{article}
\begin{document}

\section{Best Differential Trails}

Table~\ref{tab:lea-best-probability} shows the best differential trail found 
for each LEA configuration tested.

\input{lea_tables.tex}

\section{Detailed Results}

For detailed results per seed, see Tables~\ref{tab:lea-test_10r_4_1_5} 
through \ref{tab:lea-test_16r_8_1_7_time_1week_threads_24}.

\end{document}
```

## Support & Notes

- All times are absolute (includes MiniZinc solver overhead)
- Scientific notation used for very small values (< 0.001)
- Trail weights extracted but not displayed in tables
- Automatically handles missing or incomplete log files
- Parameters extracted from directory structure, no manual input needed

## Questions?

Refer to:
- `LEA_TABLES_README.md` for detailed documentation
- `GENERATION_SUMMARY.txt` for complete statistics
- `generate_lea_latex_tables.py` source code for implementation details

---

**Generated**: November 9, 2026
**Total Entries**: 81 from 8 test configurations
**Status**: Ready to use ✅
