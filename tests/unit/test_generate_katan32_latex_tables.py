import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from generate_katan32_latex_tables import collect_results, render_table


SOLUTION = (
    "Upper weight = 3.0\nLower weight = 3.0\n"
    "Middle weight = 0.0\nTrail weight = 12.0\n"
)


class Katan32TablesTest(unittest.TestCase):
    def test_collection_and_round_winners(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("test_40r_19_1_20", "test_40r_19_2_19", "test_40r_18_3_19",
                         "test_80r_39_1_40"):
                (root / name).mkdir()
            (root / "test_40r_19_1_20" / "test_katan32_40r_19_1_20.log").write_text(
                SOLUTION + "Done (overall time 4.00 s).\n"
            )
            (root / "test_40r_19_2_19" / "test_katan32_40r_19_2_19.log").write_text(
                SOLUTION + "Done (overall time 3.00 s).\n"
            )
            (root / "test_40r_18_3_19" / "test_katan32_40r_18_3_19.log").write_text(
                "=====UNSATISFIABLE=====\nDone (overall time 1.00 s).\n"
            )
            (root / "test_80r_39_1_40" / "test_katan32_80r_39_1_40.log").write_text("")
            (root / "test_katan32_83r_39_4_40.log").write_text(
                SOLUTION + "Done (overall time 10.00 s).\n"
            )
            data = collect_results(root)
        output = render_table(data)
        self.assertEqual(len(data), 5)
        self.assertEqual(output.count(r"\begin{table}"), 1)
        self.assertNotIn("Seed", output)
        self.assertIn(r"40 & 18 & 3 & 19 & - & - & - & - & 1.00 \\", output)
        self.assertIn(r"80 & 39 & 1 & 40 & - & - & - & - & in course \\", output)
        self.assertIn(r"\textbf{40} & \textbf{19} & \textbf{2}", output)
        self.assertIn(r"\textbf{83} & \textbf{39} & \textbf{4}", output)
        self.assertNotIn(r"\textbf{1.00}", output)

    def test_multiple_logs_choose_lowest_weight_then_time(self):
        with TemporaryDirectory() as tmp:
            directory = Path(tmp) / "test_60r_28_3_29"
            directory.mkdir()
            for seed, trail, time in [(0, "12.0", "7"), (1, "11.0", "9"),
                                      (2, "11.0", "8")]:
                text = SOLUTION.replace("12.0", trail)
                (directory / f"test_katan_60r_28_3_29_seed_{seed}.log").write_text(
                    text + f"Done (overall time {time} s).\n"
                )
            output = render_table(collect_results(Path(tmp)))
        self.assertIn(r"$\mathbf{2^{-11.0}}$ & \textbf{8.00}", output)

    def test_completed_unrecognized_result_is_not_silently_discarded(self):
        with TemporaryDirectory() as tmp:
            directory = Path(tmp) / "test_40r_19_1_20"
            directory.mkdir()
            (directory / "test_katan32_40r_19_1_20.log").write_text(
                "Error\nDone (overall time 1.00 s).\n"
            )
            with self.assertRaises(ValueError):
                collect_results(Path(tmp))

    def test_katan48_names_and_labels(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / "test_80r_39_1_40"
            directory.mkdir()
            (directory / "test_katan48_80r_39_1_40.log").write_text(
                SOLUTION + "Done (overall time 4.00 s).\n"
            )
            (root / "test_katan48_81r_39_2_40.log").write_text(
                "=====UNSATISFIABLE=====\nDone (overall time 2.00 s).\n"
            )
            data = collect_results(root, "katan48")
        output = render_table(data, "katan48")
        self.assertEqual(len(data), 2)
        self.assertIn(r"\caption{KATAN48 Test Results - Best Probability}", output)
        self.assertIn(r"\label{tab:katan48-best-probability}", output)
        self.assertIn(r"\textbf{80} & \textbf{39} & \textbf{1}", output)
        self.assertIn(r"81 & 39 & 2 & 40 & - & - & - & - & 2.00 \\", output)

    def test_simon32_results_and_round_winner(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("test_10r_3_3_4", "test_10r_4_2_4"):
                (root / name).mkdir()
            (root / "test_10r_3_3_4" / "test_simon32_10r_3_3_4.log").write_text(
                SOLUTION + "Done (overall time 3.00 s).\n"
            )
            (root / "test_10r_4_2_4" / "test_simon32_10r_4_2_4.log").write_text(
                SOLUTION.replace("12.0", "11.0") + "Done (overall time 4.00 s).\n"
            )
            data = collect_results(root, "simon32")
        output = render_table(data, "simon32")
        self.assertEqual(len(data), 2)
        self.assertEqual(output.count(r"\begin{table}"), 1)
        self.assertNotIn("Seed", output)
        self.assertIn(r"\caption{SIMON32 Test Results - Best Probability}", output)
        self.assertIn(r"\label{tab:simon32-best-probability}", output)
        self.assertIn(r"\textbf{10} & \textbf{4} & \textbf{2}", output)
        self.assertIn(r"10 & 3 & 3 & 4", output)

    def test_simon48_alias_and_duplicate_configuration(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / "test_15r_6_3_6"
            directory.mkdir()
            (directory / "test_simon48_15r_6_3_6.log").write_text(
                SOLUTION + "Done (overall time 4.00 s).\n"
            )
            (directory / "test_simon_15r_6_3_6.log").write_text(
                SOLUTION + "Done (overall time 3.00 s).\n"
            )
            data = collect_results(root, "simon48")
        output = render_table(data, "simon48")
        self.assertEqual(len(data["test_15r_6_3_6"]), 2)
        self.assertIn(r"\caption{SIMON48 Test Results - Best Probability}", output)
        self.assertIn(r"\label{tab:simon48-best-probability}", output)
        self.assertIn(r"\textbf{15} & \textbf{6} & \textbf{3}", output)
        self.assertIn(r"\textbf{3.00}", output)
        self.assertNotIn("Seed", output)


if __name__ == "__main__":
    unittest.main()
