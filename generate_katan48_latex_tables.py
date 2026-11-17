#!/usr/bin/env python3
"""Generate a single KATAN48 results table from AND-operation logs."""

from pathlib import Path

from generate_katan32_latex_tables import collect_results, render_table


def main() -> None:
    root = Path(__file__).resolve().parent
    data = collect_results(root / "test_operation_and" / "test_katan48", "katan48")
    output = root / "katan48_tables.tex"
    output.write_text(render_table(data, "katan48"), encoding="utf-8")
    print(f"Generated 1 table from {sum(map(len, data.values()))} logs "
          f"and {len(data)} configurations: {output}")


if __name__ == "__main__":
    main()
