#!/usr/bin/env python3
"""Generate a single SIMON32 results table from AND-operation logs."""

from pathlib import Path

from generate_katan32_latex_tables import collect_results, render_table


def main() -> None:
    root = Path(__file__).resolve().parent
    data = collect_results(root / "test_operation_and" / "test_simon32", "simon32")
    output = root / "simon32_tables.tex"
    output.write_text(render_table(data, "simon32"), encoding="utf-8")
    print(f"Generated 1 table from {sum(map(len, data.values()))} logs "
          f"and {len(data)} configurations: {output}")


if __name__ == "__main__":
    main()
