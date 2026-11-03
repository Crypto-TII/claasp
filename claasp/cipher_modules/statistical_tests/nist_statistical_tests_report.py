# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# ****************************************************************************


import math
import os
from datetime import datetime

import matplotlib.pyplot as plt


class NISTStatisticalTestsReport:
    """
    Build NIST-like report text files and charts from nist_statistical_tests() output.

    EXAMPLES::

        sage: import shutil
        sage: import tempfile
        sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
        sage: from claasp.cipher_modules.statistical_tests.nist_statistical_tests import NISTStatisticalTests
        sage: from claasp.cipher_modules.statistical_tests.nist_statistical_tests_report import NISTStatisticalTestsReport
        sage: cipher = SimonBlockCipher(number_of_rounds=2)
        sage: results = NISTStatisticalTests(cipher).nist_statistical_tests(
        ....:     test_type='avalanche',
        ....:     bits_in_one_sequence=1024,
        ....:     number_of_sequences=2,
        ....:     round_start=0,
        ....:     round_end=2,
        ....:     statistical_test_option_list='100000000000000',
        ....: )
        sage: reporter = NISTStatisticalTestsReport(results)
        sage: tmpdir = tempfile.mkdtemp()
        sage: report_dir = reporter.generate_all(output_dir=tmpdir)
        sage: shutil.rmtree(tmpdir)
    """

    _HEADER_LINE = "------------------------------------------------------------------------------"
    _FOOTER_LINE = "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"

    def __init__(self, nist_results, output_dir=None, generator_label=None):
        self.nist_results = nist_results or {}
        self.output_dir = output_dir
        self.generator_label = generator_label

    def generate_all(self, output_dir=None, generate_charts=True, generate_reports=True):
        output_dir = output_dir or self._resolve_output_dir()
        if generate_reports:
            self.generate_reports(output_dir=output_dir)
        if generate_charts:
            self.generate_charts(output_dir=output_dir)
        return output_dir

    def generate_reports(self, output_dir=None):
        output_dir = output_dir or self._resolve_output_dir()
        report_groups = self._group_reports_by_data_type()
        for data_type, reports in report_groups.items():
            dataset_dir = os.path.join(output_dir, self._safe_dir_name(data_type))
            os.makedirs(dataset_dir, exist_ok=True)
            for report in reports:
                self._write_round_report(report, dataset_dir)
        return output_dir

    def generate_charts(self, output_dir=None):
        output_dir = output_dir or self._resolve_output_dir()
        report_groups = self._group_reports_by_data_type()
        for data_type, reports in report_groups.items():
            dataset_dir = os.path.join(output_dir, self._safe_dir_name(data_type))
            os.makedirs(dataset_dir, exist_ok=True)
            for report in reports:
                self._generate_chart_round(report, dataset_dir, show_graph=False)
            self._generate_chart_all(reports, dataset_dir, show_graph=False)
        return output_dir

    @staticmethod
    def _generate_chart_round(report_dict, output_dir='', show_graph=False):
        if len(report_dict['randomness_test']) == 1:
            return
        print(f'Drawing round {report_dict["round"]} is in progress.')
        x = [test['test_id'] for test in report_dict['randomness_test']]
        y = [test['passed_proportion'] for test in report_dict['randomness_test']]

        plt.clf()
        for i in range(len(report_dict["number_of_sequences_threshold"])):
            rate = report_dict["number_of_sequences_threshold"][i]["passed"] / \
                   report_dict["number_of_sequences_threshold"][i]["total"]
            if i == 0:
                plt.hlines(rate, 0, 159, color="olive", linestyle="dashed")
                plt.hlines(rate, 186, 188, color="olive", linestyle="dashed")
            elif i == 1:
                plt.hlines(rate, 160, 185, color="olive", linestyle="dashed")

        plt.scatter(x, y, color="cadetblue")
        plt.title(
            f'{report_dict["cipher_name"]}:{report_dict["data_type"]}, Round " {report_dict["round"]+1}|{report_dict["rounds"]}')
        plt.xlabel('Test ID')
        plt.ylabel('Passing Rate')

        if show_graph == False:
            if output_dir == '':
                output_dir = f'nist_{report_dict["data_type"]}_{report_dict["cipher_name"]}_round_{report_dict["round"]+1}.png'
                plt.savefig(output_dir)
            else:
                plt.savefig(
                    output_dir + '/' + f'nist_{report_dict["data_type"]}_{report_dict["cipher_name"]}_round_{report_dict["round"]+1}.png')
        else:
            plt.show()
            plt.clf()
            plt.close()
        print(f'Drawing round {report_dict["round"]} is finished.')

    @staticmethod
    def _generate_chart_all(report_dict_list, report_folder="", show_graph=False):
        x = [i + 1 for i in range(report_dict_list[0]["round"], report_dict_list[-1]["round"] + 1)]
        y = [report_dict_list[i]["passed_tests"] for i in range(len(report_dict_list))]

        random_round = -1
        for r in range(report_dict_list[0]["rounds"]):
            if report_dict_list[r]["passed_tests"] > len(report_dict_list[0]['randomness_test']) * 0.98:
                random_round = report_dict_list[r]["round"]
                break

        plt.clf()
        plt.scatter(x, y, color="cadetblue")
        plt.hlines(len(report_dict_list[0]['randomness_test']) * 0.98, 1, report_dict_list[0]["rounds"],
                   color="darkorange", linestyle="dotted", linewidth=2,
                   label=str(math.ceil(len(report_dict_list[0]['randomness_test']) * 0.98)))
        plt.plot(x, y, 'o--', color='olive', alpha=0.4)
        if random_round > -1:
            plt.title(
                f'{report_dict_list[0]["cipher_name"]}: {report_dict_list[0]["data_type"]}, Random at {random_round+1}|{report_dict_list[0]["rounds"]}')
        else:
            plt.title(f'{report_dict_list[0]["cipher_name"]}: {report_dict_list[0]["data_type"]}')
        plt.xlabel('Round')
        plt.ylabel('Tests passed')
        plt.xticks([i * 2 + 1 for i in range(int(report_dict_list[0]["rounds"] / 2) + 1)],
                   [i * 2 + 1 for i in range(int(report_dict_list[0]["rounds"] / 2 + 1))])
        plt.yticks(list(range(math.ceil(len(report_dict_list[0]['randomness_test']) * 0.98))))
        chart_filename = f'nist_{report_dict_list[0]["data_type"]}_{report_dict_list[0]["cipher_name"]}.png'

        if show_graph == False:
            plt.savefig(os.path.join(report_folder, chart_filename))
        else:
            plt.show()
            plt.clf()
            plt.close()

    def _resolve_output_dir(self):
        if self.output_dir:
            os.makedirs(self.output_dir, exist_ok=True)
            return self.output_dir
        base_dir = os.path.join(os.getcwd(), "test_reports", "nist_statistics_report")
        time_date = "date:" + "time:".join(str(datetime.now()).split(" "))
        output_dir = os.path.join(base_dir, f"report_{time_date}")
        os.makedirs(output_dir, exist_ok=True)
        return output_dir

    def _group_reports_by_data_type(self):
        results = self.nist_results.get("test_results", []) or []
        grouped = {}
        for report in results:
            data_type = report.get("data_type", "unknown")
            grouped.setdefault(data_type, []).append(report)
        for reports in grouped.values():
            reports.sort(key=lambda item: item.get("round", 0))
        return grouped

    def _write_round_report(self, report, dataset_dir):
        round_number = report.get("round", 0)
        round_label = f"round_{round_number + 1}"
        round_dir = os.path.join(dataset_dir, round_label)
        os.makedirs(round_dir, exist_ok=True)

        report_path = os.path.join(round_dir, "finalAnalysisReport.txt")
        generator_label = self._generator_label(report)
        report_text = self._format_report_text(report, generator_label)
        with open(report_path, "w", encoding="utf-8") as report_file:
            report_file.write(report_text)

    def _generator_label(self, report):
        if self.generator_label:
            return self.generator_label
        input_params = self.nist_results.get("input_parameters", {})
        cipher = input_params.get("cipher")
        cipher_id = getattr(cipher, "id", None) or "cipher"
        test_type = input_params.get("test_type", "test")
        data_type = report.get("data_type", "dataset")
        return f"{cipher_id}:{test_type}:{data_type}"

    def _format_report_text(self, report, generator_label):
        lines = [
            self._HEADER_LINE,
            "RESULTS FOR THE UNIFORMITY OF P-VALUES AND THE PROPORTION OF PASSING SEQUENCES",
            self._HEADER_LINE,
            f"   generator is <{generator_label}>",
            self._HEADER_LINE,
            " C1  C2  C3  C4  C5  C6  C7  C8  C9 C10  P-VALUE   PROPORTION  STATISTICAL TEST",
            self._HEADER_LINE,
        ]

        thresholds = report.get("number_of_sequences_threshold", []) or []
        base_threshold = thresholds[0] if thresholds else None
        re_threshold = thresholds[1] if len(thresholds) > 1 else None

        for test in report.get("randomness_test", []) or []:
            lines.append(self._format_test_line(test, base_threshold, re_threshold))

        lines.append("")
        lines.append(self._FOOTER_LINE)
        lines.extend(self._format_threshold_lines(base_threshold, re_threshold))
        lines.append(self._FOOTER_LINE)
        lines.append("")
        return "\n".join(lines)

    def _format_test_line(self, test, base_threshold, re_threshold):
        c_cols = [self._format_count(test.get(f"C{i}", 0)) for i in range(1, 11)]
        c_part = " ".join(c_cols)
        test_name = test.get("test_name", "")
        total_seqs = int(test.get("total_seqs", 0) or 0)
        passed_seqs = int(test.get("passed_seqs", 0) or 0)

        p_value = test.get("p-value")
        if total_seqs == 0:
            p_value_str = "----"
            proportion_str = "------"
            p_value_mark = " "
            proportion_mark = " "
        else:
            p_value_str = self._format_p_value(p_value)
            threshold = self._threshold_for_test(test_name, base_threshold, re_threshold)
            p_value_mark = "*" if self._p_value_failed(p_value) else " "
            proportion_mark = "*" if self._proportion_failed(passed_seqs, threshold) else " "
            proportion_str = f"{passed_seqs}/{total_seqs}"

        return (
            f"{c_part}  {p_value_str:>8}{p_value_mark}"
            f"  {proportion_str:>8}{proportion_mark}  {test_name}"
        )

    def _format_threshold_lines(self, base_threshold, re_threshold):
        if base_threshold:
            base_passed = int(base_threshold.get("passed", 0))
            base_total = int(base_threshold.get("total", 0))
        else:
            base_passed = 0
            base_total = 0

        lines = [
            "The minimum pass rate for each statistical test with the exception of the",
            f"random excursion (variant) test is approximately = {base_passed} for a",
            f"sample size = {base_total} binary sequences.",
            "",
        ]

        if re_threshold:
            re_passed = int(re_threshold.get("passed", 0))
            re_total = int(re_threshold.get("total", 0))
            lines.extend([
                "The minimum pass rate for the random excursion (variant) test",
                f"is approximately = {re_passed} for a sample size = {re_total} binary sequences.",
                "",
            ])
        else:
            lines.extend([
                "The minimum pass rate for the random excursion (variant) test is undefined.",
                "",
            ])

        lines.extend([
            "For further guidelines construct a probability table using the MAPLE program",
            "provided in the addendum section of the documentation.",
        ])
        return lines

    def _threshold_for_test(self, test_name, base_threshold, re_threshold):
        if "RandomExcursions" in test_name:
            return re_threshold
        if "RandomExcursionsVariant" in test_name:
            return re_threshold
        return base_threshold

    @staticmethod
    def _safe_dir_name(name):
        if not name:
            return "unknown"
        return name.replace(os.sep, "_").replace(" ", "_")

    @staticmethod
    def _format_count(value):
        try:
            count = int(value)
        except (TypeError, ValueError):
            count = 0
        return f"{count:>3}"

    @staticmethod
    def _format_p_value(p_value):
        if p_value is None:
            return "----"
        try:
            value = float(p_value)
        except (TypeError, ValueError):
            return "----"
        return f"{value:0.6f}"

    @staticmethod
    def _p_value_failed(p_value):
        try:
            value = float(p_value)
        except (TypeError, ValueError):
            return False
        return value < 0.0001

    @staticmethod
    def _proportion_failed(passed_seqs, threshold):
        if not threshold:
            return False
        try:
            passed = int(passed_seqs)
            required = int(threshold.get("passed", 0))
        except (TypeError, ValueError):
            return False
        return passed < required
