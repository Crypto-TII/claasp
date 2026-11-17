#!/usr/bin/env python3
"""
Script to generate LaTeX tables from LEA test logs.
Extracts data from log files and creates formatted LaTeX tables.
"""

import re
import os
import sys
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional


@dataclass
class TestData:
    """Data extracted from a single log file"""
    round_num: int  # Round (R)
    r_0: int  # Round e0
    r_m: int  # Round em
    r_1: int  # Round e1
    upper: float  # Upper weight
    lower: float  # Lower weight
    middle: float  # Middle weight
    trail: float  # Trail weight
    seed: int  # Seed number
    time: float  # Overall time in seconds
    
    @property
    def p(self) -> float:
        """2^-upper probability"""
        return 2.0 ** (-self.upper)
    
    @property
    def q(self) -> float:
        """2^-lower probability"""
        return 2.0 ** (-self.lower)
    
    @property
    def r_prob(self) -> float:
        """2^-middle probability"""
        return 2.0 ** (-self.middle)
    
    @property
    def total_prob(self) -> float:
        """2^-total probability (p^2 * q^2 * r)"""
        return (self.p ** 2) * (self.q ** 2) * self.r_prob
    
    @property
    def trail_weight_display(self) -> float:
        """2^-trail weight"""
        return 2.0 ** (-self.trail)


def extract_test_params_from_dirname(dirname: str) -> Tuple[int, int, int, int]:
    """
    Extract R, r_0, r_m, r_1 from directory name like 'test_10r_4_1_5'
    Returns: (R, r_0, r_m, r_1)
    """
    # Pattern: test_XrY_Z_W where X=R, Y=r_0, Z=r_m, W=r_1
    match = re.search(r'test_(\d+)r_(\d+)_(\d+)_(\d+)', dirname)
    if match:
        R = int(match.group(1))
        r_0 = int(match.group(2))
        r_m = int(match.group(3))
        r_1 = int(match.group(4))
        return R, r_0, r_m, r_1
    raise ValueError(f"Cannot parse directory name: {dirname}")


def extract_seed_from_filename(filename: str) -> int:
    """Extract seed number from filename like 'test_lea_10r_4_1_5_seed_0.log'"""
    match = re.search(r'seed_(\d+)', filename)
    if match:
        return int(match.group(1))
    raise ValueError(f"Cannot extract seed from: {filename}")


def test_directory_sort_key(name: str) -> Tuple[int, str]:
    """Sort test configurations by round count, then by name."""
    return extract_test_params_from_dirname(name)[0], name


def parse_log_file(filepath: str) -> Dict[str, float]:
    """
    Parse the end of a log file to extract weights and time.
    Returns dict with keys: upper, lower, middle, trail, time
    """
    result = {}
    
    try:
        with open(filepath, 'r') as f:
            content = f.read()
        
        # Extract Upper weight
        match = re.search(r'Upper weight = ([\d.]+)', content)
        if match:
            result['upper'] = float(match.group(1))
        
        # Extract Lower weight
        match = re.search(r'Lower weight = ([\d.]+)', content)
        if match:
            result['lower'] = float(match.group(1))
        
        # Extract Middle weight
        match = re.search(r'Middle weight = ([\d.]+)', content)
        if match:
            result['middle'] = float(match.group(1))
        
        # Extract Trail weight
        match = re.search(r'Trail weight = ([\d.]+)', content)
        if match:
            result['trail'] = float(match.group(1))
        
        # Extract overall time from "Done (overall time XXX s)"
        match = re.search(r'Done \(overall time ([\d.]+) s\)', content)
        if match:
            result['time'] = float(match.group(1))
        
    except Exception as e:
        print(f"Error parsing file {filepath}: {e}")
    
    return result


def round_to_two_decimals(value: float) -> str:
    """Round value to 2 decimal places and return as string"""
    return f"{value:.2f}"


def format_probability_exponent(weight: float) -> str:
    """Format probability as 2^{-weight}"""
    # Round weight to 2 decimal places
    rounded_weight = round(weight, 2)
    return f"$2^{{-{rounded_weight}}}$"


def best_test_result(results: List[TestData]) -> TestData:
    """Choose the highest P_boom, then the shortest time and lowest seed."""
    return min(results, key=lambda result: (result.trail, result.time, result.seed))


def bold_latex_cell(value: str) -> str:
    """Bold a text or math-mode table cell."""
    if value.startswith("$") and value.endswith("$"):
        return r"$\mathbf{" + value[1:-1] + "}$"
    return r"\textbf{" + value + "}"


def collect_all_test_data(base_path: str, cipher: str = "lea") -> Dict[str, List[TestData]]:
    """
    Collect all test data from the base directory.
    Returns: dict mapping test_name -> list of TestData objects
    """
    data_by_test = defaultdict(list)
    base = Path(base_path)
    
    if not base.exists():
        print(f"Error: Base path does not exist: {base_path}")
        return data_by_test
    
    # Iterate through each test subdirectory
    for test_dir in sorted(base.iterdir()):
        if not test_dir.is_dir() or not test_dir.name.startswith('test_'):
            continue
        
        try:
            # Extract parameters from directory name
            R, r_0, r_m, r_1 = extract_test_params_from_dirname(test_dir.name)
            test_name = test_dir.name
            
            # Iterate through log files in this directory
            for log_file in sorted(test_dir.glob('*.log')):
                if not log_file.name.startswith(f'test_{cipher}_'):
                    continue
                
                # Extract seed from filename
                seed = extract_seed_from_filename(log_file.name)
                
                # Parse the log file
                weights = parse_log_file(str(log_file))
                
                # Check if we have all required data
                if all(k in weights for k in ['upper', 'lower', 'middle', 'trail', 'time']):
                    test_data = TestData(
                        round_num=R,
                        r_0=r_0,
                        r_m=r_m,
                        r_1=r_1,
                        upper=weights['upper'],
                        lower=weights['lower'],
                        middle=weights['middle'],
                        trail=weights['trail'],
                        seed=seed,
                        time=weights['time']
                    )
                    data_by_test[test_name].append(test_data)
                else:
                    missing = [key for key in ('upper', 'lower', 'middle', 'trail', 'time')
                               if key not in weights]
                    print(f"Incomplete log {log_file}: missing {', '.join(missing)}",
                          file=sys.stderr)
        
        except Exception as e:
            print(f"Error processing directory {test_dir.name}: {e}")
            continue
    
    return data_by_test


def create_latex_table_best_probability(
    data_by_test: Dict[str, List[TestData]], cipher: str = "lea"
) -> str:
    """
    Create a LaTeX table with only the entry with the best (highest) total probability
    for each test configuration.
    """
    latex = []
    latex.append(r"\begin{table}[h!]")
    latex.append(r"\centering")
    latex.append(f"\\caption{{{cipher.upper()} Test Results - Best Probability}}")
    latex.append(f"\\label{{tab:{cipher}-best-probability}}")
    latex.append(r"\small")
    latex.append(r"\begin{tabular}{|c|c|c|c|c|c|c|c|c|c|}")
    latex.append(r"\hline")
    latex.append(r"R & $r_0$ & $r_m$ & $r_1$ & $p$ & $q$ & $r$ & $P_{boom}$ & Seed & Time (s) \\")
    latex.append(r"\hline")
    
    # For each test, find the entry with the highest total probability
    for test_name in sorted(data_by_test, key=test_directory_sort_key):
        test_results = data_by_test[test_name]
        if not test_results:
            continue
        
        best_result = best_test_result(test_results)
        
        # Format the row - using exponent notation
        p = format_probability_exponent(best_result.upper)
        q = format_probability_exponent(best_result.lower)
        r = format_probability_exponent(best_result.middle)
        trail = format_probability_exponent(best_result.trail)
        time_str = round_to_two_decimals(best_result.time)
        
        latex.append(
            f"{best_result.round_num} & {best_result.r_0} & {best_result.r_m} & "
            f"{best_result.r_1} & {p} & {q} & {r} & {trail} & "
            f"{best_result.seed} & {time_str} \\\\"
        )
    
    latex.append(r"\hline")
    latex.append(r"\end{tabular}")
    latex.append(r"\end{table}")
    
    return "\n".join(latex)


def create_latex_table_all_seeds(
    test_name: str, results: List[TestData], cipher: str = "lea"
) -> str:
    """
    Create a LaTeX table for a specific test configuration with all seeds.
    """
    latex = []
    latex.append(r"\begin{table}[h!]")
    latex.append(r"\centering")
    
    # Create caption from test name: test_10r_4_1_5 -> 10 rounds, r0=4, rm=1, r1=5
    match = re.search(r'test_(\d+)r_(\d+)_(\d+)_(\d+)(.*)', test_name)
    if match:
        r = match.group(1)
        r0 = match.group(2)
        rm = match.group(3)
        r1 = match.group(4)
        extra = match.group(5).replace('_', ' ').strip() if match.group(5) else ""
        if extra:
            caption = f"{cipher.upper()} {r} rounds ($r_0$={r0}, $r_m$={rm}, $r_1$={r1}) - {extra} - All Seeds"
        else:
            caption = f"{cipher.upper()} {r} rounds ($r_0$={r0}, $r_m$={rm}, $r_1$={r1}) - All Seeds"
    else:
        caption = f"{cipher.upper()} {test_name} - All Seeds"
    
    latex.append(f"\\caption{{{caption}}}")
    latex.append(f"\\label{{tab:{cipher}-{test_name}}}")
    latex.append(r"\small")
    latex.append(r"\begin{tabular}{|c|c|c|c|c|c|c|c|c|}")
    latex.append(r"\hline")
    latex.append(r"$r_0$ & $r_m$ & $r_1$ & $p$ & $q$ & $r$ & $P_{boom}$ & Seed & Time (s) \\")
    latex.append(r"\hline")
    
    best_result = best_test_result(results) if results else None

    # Sort by seed
    for result in sorted(results, key=lambda x: x.seed):
        p = format_probability_exponent(result.upper)
        q = format_probability_exponent(result.lower)
        r = format_probability_exponent(result.middle)
        trail = format_probability_exponent(result.trail)
        time_str = round_to_two_decimals(result.time)
        
        cells = [str(result.r_0), str(result.r_m), str(result.r_1), p, q, r,
                 trail, str(result.seed), time_str]
        if result is best_result:
            cells = [bold_latex_cell(cell) for cell in cells]
        latex.append(" & ".join(cells) + r" \\")
    
    latex.append(r"\hline")
    latex.append(r"\end{tabular}")
    latex.append(r"\end{table}")
    
    return "\n".join(latex)


def main():
    """Main function"""
    base_path = "/raid/homespace/rocbrunelli/claasp_x_boomerang/claasp/test_operation_modadd/test_lea"
    
    print(f"Collecting test data from {base_path}...")
    data_by_test = collect_all_test_data(base_path)
    
    if not data_by_test:
        print("Error: No test data found!")
        return
    
    print(f"Found {len(data_by_test)} test configurations")
    
    # Generate output
    output_lines = []
    output_lines.append("% LEA Test LaTeX Tables")
    output_lines.append("% Auto-generated by generate_lea_latex_tables.py")
    output_lines.append("")
    
    # Table 1: Best probability for each configuration
    output_lines.append("% Table 1: Best Probability Results")
    output_lines.append(create_latex_table_best_probability(data_by_test))
    output_lines.append("")
    output_lines.append("")
    
    # Tables for each test configuration with all seeds
    output_lines.append("% Tables 2+: All Seeds by Configuration")
    for test_name in sorted(data_by_test, key=test_directory_sort_key):
        results = data_by_test[test_name]
        output_lines.append(create_latex_table_all_seeds(test_name, results))
        output_lines.append("")
        output_lines.append("")
    
    # Write to file
    output_file = "/raid/homespace/rocbrunelli/claasp_x_boomerang/claasp/lea_tables.tex"
    with open(output_file, 'w') as f:
        f.write("\n".join(output_lines))
    
    print(f"LaTeX tables written to {output_file}")
    
    # Also print summary
    total_entries = sum(len(v) for v in data_by_test.values())
    print(f"Total entries processed: {total_entries}")
    for test_name in sorted(data_by_test.keys()):
        print(f"  {test_name}: {len(data_by_test[test_name])} seeds")


if __name__ == "__main__":
    main()
