import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from generate_single_key_chacha_latex_tables import (
    Run,
    best_run,
    collect_runs,
    parse_run,
    render_tables,
)


SOLUTION = (
    "Upper weight = 6.0\nLower weight = 10.0\n"
    "Middle weight = 0.12\nTrail weight = 32.12\n"
)


class SingleKeyChachaTablesTest(unittest.TestCase):
    def test_log_states_and_selection(self):
        with TemporaryDirectory() as tmp:
            directory = Path(tmp) / "test_7r_10_2_16"
            directory.mkdir()
            contents = {
                0: SOLUTION + "Done (overall time 12.34 s).\n",
                1: SOLUTION + "Done (overall time 10.00 s).\n",
                2: "=====UNKNOWN=====\n%%%mzn-stat: nSolutions=0\n"
                   "Done (overall time 86439.21 s).\n",
                3: "Solver is still running\n",
                4: SOLUTION,
                5: "=====UNSATISFIABLE=====\n%%%mzn-stat: nSolutions=0\n"
                   "Done (overall time 100.00 s).\n",
            }
            for seed, content in contents.items():
                (directory / f"test_chacha_7r_10_2_16_seed_{seed}.log").write_text(content)
            data = collect_runs(Path(tmp))

        runs = data["test_7r_10_2_16"]
        self.assertEqual(len(runs), 6)
        self.assertEqual(best_run(runs).seed, 1)
        output = render_tables(data)
        self.assertIn(r"\textbf{1} & \textbf{10.00}", output)
        self.assertIn(r"- & - & - & - & 2 & 86439.21 \\", output)
        self.assertIn(r"- & - & - & - & 3 & in course \\", output)
        self.assertIn(r"$2^{-32.12}$ & 4 & in course \\", output)
        self.assertIn(r"- & - & - & - & 5 & 100.00 \\", output)

    def test_no_solution_configuration_remains_in_overview(self):
        runs = [Run(7, None, 100.0), Run(8, None, None)]
        output = render_tables({"test_7r_10_2_16": runs})
        self.assertIn(r"7 & 10 & 2 & 16 & - & - & - & - & - & - \\", output)
        self.assertNotIn(r"\textbf{", output)

    def test_selection_probability_time_and_seed(self):
        weights = (1.0, 2.0, 3.0, 9.0)
        runs = [Run(0, (1.0, 2.0, 3.0, 10.0), 1.0),
                Run(2, weights, 3.0), Run(1, weights, 3.0),
                Run(3, weights, None)]
        self.assertEqual(best_run(runs).seed, 1)
        self.assertIsNone(best_run([]))

    def test_completed_invalid_log_reports_error(self):
        with TemporaryDirectory() as tmp:
            log = Path(tmp) / "test_chacha_7r_10_2_16_seed_0.log"
            log.write_text("Done (overall time 10.00 s).\n")
            with self.assertRaisesRegex(ValueError, "No solution or no-solution marker"):
                parse_run(log)

    def test_rounds_sorted(self):
        run = Run(0, (1.0, 2.0, 3.0, 9.0), 2.0)
        output = render_tables({"test_10r_1_1_8": [run], "test_4r_1_1_2": [run]})
        self.assertLess(output.index("4 & 1 & 1 & 2 &"), output.index("10 & 1 & 1 & 8 &"))
        self.assertLess(output.index("CHACHA SINGLE KEY 4 rounds"),
                        output.index("CHACHA SINGLE KEY 10 rounds"))

    def test_chaskey16_uses_chaskey_log_names_and_distinct_labels(self):
        with TemporaryDirectory() as tmp:
            directory = Path(tmp) / "test_4r_3_2_3"
            directory.mkdir()
            (directory / "test_chaskey_4r_3_2_3_seed_1.log").write_text(
                SOLUTION + "Done (overall time 12.34 s).\n"
            )
            (directory / "test_chaskey_4r_3_2_3_seed_2.log").write_text("Running\n")
            (directory / "test_chacha_4r_3_2_3_seed_3.log").write_text("Running\n")
            data = collect_runs(Path(tmp), "chaskey")
        output = render_tables(data, "CHASKEY16", "chaskey16", "generate_chaskey16_latex_tables.py")
        self.assertEqual(len(data["test_4r_3_2_3"]), 2)
        self.assertIn(r"\caption{CHASKEY16 Test Results - Best Probability}", output)
        self.assertIn(r"\label{tab:chaskey16-test_4r_3_2_3}", output)
        self.assertIn(r"\textbf{1} & \textbf{12.34}", output)
        self.assertIn(r"- & - & - & - & 2 & in course \\", output)


if __name__ == "__main__":
    unittest.main()
