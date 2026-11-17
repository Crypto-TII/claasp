#!/usr/bin/env python3
"""Generate Chaskey16 LaTeX tables from test_operation_modadd/test_new_chaskey16."""

from pathlib import Path

from generate_single_key_chacha_latex_tables import collect_runs, render_tables


def main() -> None:
    root = Path(__file__).resolve().parent
    data = collect_runs(root / "test_operation_modadd" / "test_new_chaskey16", "chaskey")
    output = root / "chaskey16_tables.tex"
    output.write_text(
        render_tables(data, "CHASKEY16", "chaskey16", Path(__file__).name),
        encoding="utf-8",
    )
    print(f"Generated {len(data) + 1} tables from "
          f"{sum(len(runs) for runs in data.values())} logs: {output}")


if __name__ == "__main__":
    main()
