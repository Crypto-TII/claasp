import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import generate_speck32_latex_tables

from generate_lea_latex_tables import (
    TestData,
    best_test_result,
    collect_all_test_data,
    create_latex_table_all_seeds,
    create_latex_table_best_probability,
    extract_test_params_from_dirname,
    test_directory_sort_key,
)


class LeaLatexTablesTest(unittest.TestCase):
    def setUp(self):
        self.result = TestData(
            round_num=10, r_0=4, r_m=1, r_1=5, upper=6, lower=10,
            middle=0.12, trail=32.12, seed=3, time=10,
        )

    def test_selects_probability_then_time_then_seed(self):
        results = [
            replace(self.result, trail=32.13, time=1, seed=0),
            replace(self.result, time=11, seed=1),
            replace(self.result, time=10, seed=2),
            self.result,
        ]
        self.assertIs(best_test_result(results), results[2])

    def test_uses_unrounded_weight_and_time_without_probability_underflow(self):
        results = [
            replace(self.result, trail=2000.004, time=1, seed=0),
            replace(self.result, trail=2000.003, time=10.004, seed=1),
            replace(self.result, trail=2000.003, time=10.003, seed=2),
        ]
        self.assertIs(best_test_result(results), results[2])

    def test_only_best_row_is_bold_and_overview_uses_same_result(self):
        results = [
            replace(self.result, seed=0, time=12),
            replace(self.result, seed=2, time=10),
            replace(self.result, seed=1, time=10),
        ]
        table = create_latex_table_all_seeds("test_10r_4_1_5", results)
        rows = [line for line in table.splitlines() if line.endswith(r" \\")][1:]
        self.assertEqual(len(rows), 3)
        self.assertEqual(sum(r"\textbf{" in row for row in rows), 1)
        self.assertIn(r"\textbf{1} & \textbf{10.00}", rows[1])
        self.assertIn(r"$\mathbf{2^{-32.12}}$", rows[1])
        self.assertNotIn(r"\textbf{", rows[0])
        self.assertNotIn(r"\textbf{", rows[2])
        overview = create_latex_table_best_probability({"test_10r_4_1_5": results})
        self.assertIn(r"& 1 & 10.00 \\", overview)

    def test_empty_seed_table(self):
        table = create_latex_table_all_seeds("test_10r_4_1_5", [])
        self.assertNotIn(r"\textbf{", table)

    def test_middle_round_is_integer_in_both_tables(self):
        parameters = extract_test_params_from_dirname("test_8r_2_3_3")
        self.assertIs(type(parameters[2]), int)
        result = replace(self.result, round_num=8, r_0=2, r_m=parameters[2], r_1=3)
        overview = create_latex_table_best_probability({"test_8r_2_3_3": [result]})
        details = create_latex_table_all_seeds("test_8r_2_3_3", [result])
        self.assertIn("8 & 2 & 3 & 3 &", overview)
        self.assertIn(r"\textbf{2} & \textbf{3} & \textbf{3}", details)

    def test_rounds_sorted_numerically_in_overview(self):
        names = ["test_10r_4_1_5", "test_9r_4_1_4", "test_8r_3_1_4"]
        self.assertEqual(sorted(names, key=test_directory_sort_key), names[::-1])
        data = {
            name: [replace(self.result, round_num=round_num)]
            for name, round_num in zip(names, (10, 9, 8))
        }
        table = create_latex_table_best_probability(data, "speck32")
        rows = [line for line in table.splitlines()
                if line.endswith(r" \\") and line[0].isdigit()]
        self.assertEqual([int(row.split(" & ")[0]) for row in rows], [8, 9, 10])

    def test_speck32_logs_and_captions(self):
        with TemporaryDirectory() as tmp:
            test_dir = Path(tmp) / "test_10r_4_1_5"
            test_dir.mkdir()
            log = (
                "Upper weight = 6.0\nLower weight = 10.0\n"
                "Middle weight = 0.12\nTrail weight = 32.12\n"
                "Done (overall time 12.34 s).\n"
            )
            (test_dir / "test_speck32_10r_4_1_5_seed_0.log").write_text(log)
            (test_dir / "test_speck32_10r_4_1_5_seed_0_for_2_days.log").write_text(
                log.replace("12.34", "10.00")
            )
            (test_dir / "test_lea_10r_4_1_5_seed_1.log").write_text(log)
            data = collect_all_test_data(tmp, cipher="speck32")

        results = data["test_10r_4_1_5"]
        self.assertEqual(len(results), 2)
        self.assertEqual(best_test_result(results).time, 10.0)
        table = create_latex_table_all_seeds("test_10r_4_1_5", results, "speck32")
        overview = create_latex_table_best_probability(data, "speck32")
        self.assertIn(r"\caption{SPECK32 10 rounds", table)
        self.assertIn(r"\label{tab:speck32-test_10r_4_1_5}", table)
        self.assertIn(r"\textbf{0} & \textbf{10.00}", table)
        self.assertIn(r"\label{tab:speck32-best-probability}", overview)
        self.assertIn(r"& 0 & 10.00 \\", overview)

    def test_speck48_generator_includes_all_logs_in_numerical_order(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("test_12r_5_1_6", "test_9r_4_1_4"):
                directory = root / "test_operation_modadd" / "test_speck48" / name
                directory.mkdir(parents=True)
                log = ("Upper weight = 6.0\nLower weight = 10.0\n"
                       "Middle weight = 0.12\nTrail weight = 32.12\n"
                       "Done (overall time 12.34 s).\n")
                (directory / "test_speck48_example_seed_0.log").write_text(log)
                (directory / "test_speck48_example_seed_1.log").write_text(
                    log.replace("12.34", "10.00")
                )
            with patch.object(generate_speck32_latex_tables, "__file__", str(root / "generator.py")):
                generate_speck32_latex_tables.main("speck48")
            output = (root / "speck48_tables.tex").read_text()

        self.assertIn(r"\caption{SPECK48 Test Results - Best Probability}", output)
        self.assertIn(r"\label{tab:speck48-best-probability}", output)
        self.assertLess(output.index("9 & 4 & 1 & 4"), output.index("12 & 5 & 1 & 6"))
        self.assertLess(output.index("SPECK48 9 rounds"), output.index("SPECK48 12 rounds"))
        self.assertEqual(output.count(r"\textbf{1} & \textbf{10.00}"), 2)


if __name__ == "__main__":
    unittest.main()
