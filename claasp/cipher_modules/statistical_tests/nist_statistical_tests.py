
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


import os
import math
import time
import shutil
import pathlib
from datetime import timedelta
import matplotlib.pyplot as plt


from claasp.cipher_modules.statistical_tests.dataset_generator import DatasetGenerator, DatasetType

reports_path = "test_reports/statistical_tests/nist_statistics_report"

class StatisticalTests:

    def __init__(self, cipher):
        cipher.sort_cipher()
        self.cipher = cipher
        self.data_generator = DatasetGenerator(cipher)
        str_of_inputs_bit_size = list(map(str, cipher.inputs_bit_size))
        self._cipher_primitive = cipher.id + "_" + "_".join(str_of_inputs_bit_size)

    @staticmethod
    def run_nist_statistical_tests_tool_interactively(input_file, bit_stream_length, number_of_bit_streams,
                                                      input_file_format,
                                                      statistical_test_option_list=15 * '1'):
        """
        Run statistical tests using the NIST test suite [1]. The result will be in experiments folder.
        Be aware that the NIST STS suits needed to be installed in /usr/local/bin in the docker image.

        [1] https://csrc.nist.gov/Projects/Random-Bit-Generation/Documentation-and-Software

        INPUT:

        - ``input_file`` -- **str**; file containing the bit streams
        - ``bit_stream_length`` -- **integer**; bit stream length (See [1])
        - ``number_of_bit_streams`` -- **integer**; number of bit streams in `input_file`
        - ``input_file_format`` -- **integer**; `input_file` format. Set to 0 to indicate a file containing a binary
          string in ASCII, or 1 to indicate a binary file
        - ``test_type`` -- **str**; the type of the test to run
        - ``statistical_test_option_list`` -- **str** (default: `15 * '1'`); a binary string of size 15. This string is
          used to specify a set of statistical tests we want to run (See [1])

        OUTPUT:

        - The result of the NIST statistical tests is in file test_reports/statistical_tests/experiments/AlgorithmTesting/finalAnalysisReport.txt

        EXAMPLES::

            sage: import os
            sage: from claasp.cipher_modules.statistical_tests.nist_statistical_tests import StatisticalTests
            sage: if not os.path.exists(f'test_reports/statistical_tests/experiments'):
            ....:     os.makedirs(f'test_reports/statistical_tests/experiments')
            sage: result = StatisticalTests.run_nist_statistical_tests_tool_interactively(
            ....:     f'claasp/cipher_modules/statistical_tests/input_data_example',
            ....:     10000, 10, 1)
                 Statistical Testing In Progress.........
                 Statistical Testing Complete!!!!!!!!!!!!

            sage: result
            True
        """
        def mkdir_folder_experiment(path_prefix, folder_experiment):
            path_folder_experiment = os.path.join(path_prefix, folder_experiment)
            if not os.path.exists(path_folder_experiment):
                pathlib.Path(path_folder_experiment).mkdir(parents=True, exist_ok=False, mode=0o777)

        folder_experiments = [
            "Frequency",
            "BlockFrequency",
            "Runs",
            "LongestRun",
            "Rank",
            "FFT",
            "NonOverlappingTemplate",
            "OverlappingTemplate",
            "Universal",
            "LinearComplexity",
            "Serial",
            "ApproximateEntropy",
            "CumulativeSums",
            "RandomExcursions",
            "RandomExcursionsVariant"
        ]

        nist_local_experiment_folder = f"/usr/local/bin/sts-2.1.2/experiments/"
        for directory in ["AlgorithmTesting", "BBS", "CCG", "G-SHA1", "LCG", "MODEXP", "MS", "QCG1", "QCG2", "XOR"]:
            path_prefix = os.path.join(nist_local_experiment_folder, directory)
            for experiment_name in folder_experiments:
                mkdir_folder_experiment(path_prefix, experiment_name)
        os.system(f'chmod -R 777 {nist_local_experiment_folder}')

        input_file = os.path.abspath(input_file)
        output_code = os.system(f'niststs {input_file} {bit_stream_length} {number_of_bit_streams} {input_file_format} '
                                f'{statistical_test_option_list}')
        if output_code != 256:
            return output_code
        else:
            os.system(f'chmod -R 777 {nist_local_experiment_folder}')
            return True

    @staticmethod
    def parse_report(report_filename):
        """
        Parse the nist statistical tests report. It will return the parsed result in a dictionary format.

        INPUT:

        - ``report_filename`` -- **str**; the filename of the report you need to parse

        OUTPUT:

        - ``report_dict`` -- return the parsed result in a dictionary format

        EXAMPLES::

            sage: from claasp.cipher_modules.statistical_tests.nist_statistical_tests import StatisticalTests
            sage: dict = StatisticalTests.parse_report(f'claasp/cipher_modules/statistical_tests/finalAnalysisReportExample.txt')
            Parsing claasp/cipher_modules/statistical_tests/finalAnalysisReportExample.txt is in progress.
            Parsing claasp/cipher_modules/statistical_tests/finalAnalysisReportExample.txt is finished.
        """
        print(f'Parsing {report_filename} is in progress.')
        with open(report_filename, 'r') as f:
            lines = f.readlines()
        report_dict = {"passed_tests": 0}

        # if the sts_test failed, this file will be empty
        if len(lines) == 0:
            print(f'{report_filename} is empty.')
            report_dict["number_of_sequences_threshold"] = []
            test_list = []
            for i in range(188):
                test_dict = {
                    "test_id": i + 1,
                    "passed": False,
                    "p-value": 0,
                    "passed_seqs": 0,
                    "total_seqs": 0,
                    "passed_proportion": 0
                }
                test_list.append(test_dict)
            report_dict["randomness_test"] = test_list
            return report_dict

        # retrieve pass standard
        threshold_rate = []
        seqs = lines[199].split("=")
        seqs_1 = seqs[1].split()
        seqs = lines[200].split("=")
        seqs_2 = seqs[1].split()
        threshold_rate.append({
            "total": int(seqs_2[0]),
            "passed": int(seqs_1[0])})
        seqs = lines[203].split("=")
        if len(seqs) != 1:
            seqs_1 = seqs[1].split()
            seqs_2 = seqs[2].split()
            threshold_rate.append({
                "total": int(seqs_2[0]),
                "passed": int(seqs_1[0])})
        report_dict["number_of_sequences_threshold"] = threshold_rate

        # retrieve test
        lines_test = lines[7:195]
        test_list = []
        for i in range(188):
            test_dict = {}
            test_dict["test_id"] = i + 1

            # check passed
            if lines_test[i].find('*') != -1 or lines_test[i].find('-') != -1:
                test_dict["passed"] = False
                line = lines_test[i].replace("*", " ")
            else:
                test_dict["passed"] = True
                line = lines_test[i]
                report_dict["passed_tests"] += 1

            # retrieve experimental results
            seqs = line.split()
            for i in range(10):
                test_dict["C" + str(i + 1)] = seqs[i]
            if seqs[10].find("--") != -1 or seqs[11].find("--") != -1:
                test_dict["p-value"] = 0
                test_dict["passed_seqs"] = 0
                test_dict["total_seqs"] = 0
                test_dict["passed_proportion"] = 0
            else:
                test_dict["p-value"] = float(seqs[10])
                nums = seqs[11].split("/")
                if test_dict["p-value"] == 0:
                    test_dict["passed_seqs"] = 0
                    test_dict["total_seqs"] = int(nums[1])
                    test_dict["passed_proportion"] = 0
                else:
                    test_dict["passed_seqs"] = int(nums[0])
                    test_dict["total_seqs"] = int(nums[1])
                    test_dict["passed_proportion"] = test_dict["passed_seqs"] / test_dict["total_seqs"]
            test_dict["test_name"] = seqs[12]
            test_list.append(test_dict)
        report_dict["randomness_test"] = test_list
        f.close()
        print(f'Parsing {report_filename} is finished.')
        return report_dict

    @staticmethod
    def generate_chart_round(report_dict, report_folder=""):
        """
        Generate the corresponding chart based on the parsed report dictionary.

        INPUT:

        - ``report_dict`` -- **dictionary**; the parsed result in a dictionary format

        OUTPUT:

        - save the chart with filename
          f'nist_{report_dict["data_type"]}_{report_dict["cipher_name"]}_round_{report_dict["round"]}.png'

        EXAMPLES::

            sage: from claasp.cipher_modules.statistical_tests.nist_statistical_tests import StatisticalTests
            sage: dict = StatisticalTests.parse_report(f'claasp/cipher_modules/statistical_tests/finalAnalysisReportExample.txt')
            Parsing claasp/cipher_modules/statistical_tests/finalAnalysisReportExample.txt is in progress.
            Parsing claasp/cipher_modules/statistical_tests/finalAnalysisReportExample.txt is finished.

            sage: dict['data_type'] = 'random'
            sage: dict['cipher_name'] = 'toy_cipher'
            sage: dict['round'] = 1
            sage: dict['rounds'] = 1
            sage: StatisticalTests.generate_chart_round(dict)
            Drawing round 1 is in progress.
            Drawing round 1 is finished.
        """
        print(f'Drawing round {report_dict["round"]} is in progress.')
        x = [i for i in range(1, 189)]
        y = [0 for _ in range(188)]
        for item in report_dict["randomness_test"]:
            y[item["test_id"] - 1] = item["passed_proportion"]

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
        plt.title(f'{report_dict["cipher_name"]}:{report_dict["data_type"]}, Round " {report_dict["round"]}|{report_dict["rounds"]}')
        plt.xlabel('Test ID')
        plt.ylabel('Passing Rate')
        chart_filename = f'nist_{report_dict["data_type"]}_{report_dict["cipher_name"]}_round_{report_dict["round"]}.png'
        plt.savefig(os.path.join(report_folder, chart_filename))
        print(f'Drawing round {report_dict["round"]} is finished.')

    @staticmethod
    def generate_chart_all(report_dict_list, report_folder=""):
        """
        Generate the corresponding chart based on the list of parsed report dictionary for all rounds.

        INPUT:

        - ``report_dict_list`` -- **list**; the list of the parsed result in a dictionary format for all rounds

        OUTPUT:

        - save the chart with filename f'nist_{data_type}_{cipher_name}.png'

        EXAMPLES::

            sage: from claasp.cipher_modules.statistical_tests.nist_statistical_tests import StatisticalTests
            sage: dict = StatisticalTests.parse_report(f'claasp/cipher_modules/statistical_tests/finalAnalysisReportExample.txt')
            Parsing claasp/cipher_modules/statistical_tests/finalAnalysisReportExample.txt is in progress.
            Parsing claasp/cipher_modules/statistical_tests/finalAnalysisReportExample.txt is finished.

            sage: dict['data_type'] = 'random'
            sage: dict['cipher_name'] = 'toy_cipher'
            sage: dict['round'] = 1
            sage: dict['rounds'] = 1
            sage: dict_list = [dict]
            sage: StatisticalTests.generate_chart_all(dict_list)
            Drawing chart for all rounds is in progress.
            Drawing chart for all rounds is in finished.
        """
        print("Drawing chart for all rounds is in progress.")
        x = [i + 1 for i in range(report_dict_list[0]["rounds"])]
        y = [0 for _ in range(report_dict_list[0]["rounds"])]
        for i in range(len(report_dict_list)):
            y[report_dict_list[i]["round"] - 1] = report_dict_list[i]["passed_tests"]

        random_round = -1
        for r in range(report_dict_list[0]["rounds"]):
            if report_dict_list[r]["passed_tests"] > 185:
                random_round = report_dict_list[r]["round"]
                break

        plt.clf()
        plt.scatter(x, y, color="cadetblue")
        plt.hlines(186, 1, report_dict_list[0]["rounds"], color="darkorange", linestyle="dotted", linewidth=2,
                   label="186")
        plt.plot(x, y, 'o--', color='olive', alpha=0.4)
        if random_round > -1:
            plt.title(f'{report_dict_list[0]["cipher_name"]}: {report_dict_list[0]["data_type"]}, Random at {random_round}|{report_dict_list[0]["rounds"]}')
        else:
            plt.title(f'{report_dict_list[0]["cipher_name"]}: {report_dict_list[0]["data_type"]}')
        plt.xlabel('Round')
        plt.ylabel('Tests passed')
        plt.xticks([i * 2 + 1 for i in range(int(report_dict_list[0]["rounds"] / 2) + 1)],
                   [i * 2 + 1 for i in range(int(report_dict_list[0]["rounds"] / 2 + 1))])
        plt.yticks([i * 20 for i in range(1, 11)], [i * 20 for i in range(1, 11)])
        chart_filename = f'nist_{report_dict_list[0]["data_type"]}_{report_dict_list[0]["cipher_name"]}.png'
        plt.savefig(os.path.join(report_folder, chart_filename))
        print(f'Drawing chart for all rounds is in finished.')

    def _create_report_folder(self):
        self.report_folder = os.path.join(self.folder_prefix,
                                          f'{self._cipher_primitive}_{self.dataset_type.name}_index{self.input_index}_{self.number_of_lines}lines_{self.bits_in_one_line}bits')
        try:
            os.makedirs(self.report_folder)
        except OSError:
            pass

    def _write_execution_time(self, execution_description, execution_time):
        try:
            f_out = open(os.path.join(self.report_folder, "execution_time.txt"), "a")
            f_out.write(f'{execution_description}: {timedelta(seconds=execution_time)}\n')
            f_out.close()
        except Exception as e:
            print(f'Error: {e.strerror}')

    def _generate_sts_dicts(self, dataset, round_start, round_end, test_type, flag_chart=False):
        # seems that the statistical tools cannot change the default folder 'experiments'
        nist_local_experiment_folder = f"/usr/local/bin/sts-2.1.2/experiments/"
        dataset_folder = 'dataset'
        dataset_filename = f'nist_input_{self._cipher_primitive}'
        dataset_filename = os.path.join(dataset_folder, dataset_filename)
        sts_report_dicts = []

        if not os.path.exists(dataset_folder):
            try:
                os.makedirs(dataset_folder)
            except OSError as e:
                print(f'Error: {e.strerror}')
                return

        for round_number in range(round_start, round_end):
            # initialize the directory environment
            if os.path.exists(nist_local_experiment_folder):
                try:
                    shutil.rmtree(nist_local_experiment_folder)
                except OSError as e:
                    print(f'Error: {e.strerror}')
                    return

            report_folder_round = os.path.abspath(os.path.join(self.report_folder, f'round_{round_number}'))
            dataset[round_number].tofile(dataset_filename)

            sts_execution_time = time.time()
            self.run_nist_statistical_tests_tool_interactively(dataset_filename, self.bits_in_one_line,
                                                               self.number_of_lines, 1)
            sts_execution_time = time.time() - sts_execution_time
            try:
                shutil.move(nist_local_experiment_folder, report_folder_round)
            except OSError as e:
                print(f'Error: {e.strerror}')
                print(
                    f'Please remove the existed folder {report_folder_round} '
                    f'or indicate another folder for saving the NIST STS reports.')
                continue
            self._write_execution_time(f'Compute round {round_number}', sts_execution_time)

            try:
                # generate report
                sts_report_dict = self.parse_report(
                    os.path.join(report_folder_round, "AlgorithmTesting/finalAnalysisReport.txt"))
                sts_report_dict['data_type'] = f'{self.cipher.inputs[self.input_index]}_{self.dataset_type.value}'
                sts_report_dict["cipher_name"] = self.cipher.id
                sts_report_dict["round"] = round_number
                sts_report_dict["rounds"] = self.cipher.number_of_rounds
                sts_report_dicts.append(sts_report_dict)
                # generate round chart
                if flag_chart:
                    self.generate_chart_round(sts_report_dict, self.report_folder)
            except OSError:
                print(f"Error in parsing report for round {round_number}.")

        self.generate_chart_for_all_rounds(flag_chart, sts_report_dicts)

        print("Finished.")
        return sts_report_dicts

    def generate_chart_for_all_rounds(self, flag_chart, sts_report_dicts):
        if flag_chart:
            try:
                self.generate_chart_all(sts_report_dicts, self.report_folder)
            except OSError:
                print("Error in generating all round chart.")

    def run_avalanche_nist_statistics_test(
            self, input_index, number_of_samples_in_one_line, number_of_lines, round_start=0, round_end=0,
            nist_sts_report_folder_prefix=reports_path, flag_chart=False):
        r"""
        Run the avalanche test using NIST statistical tools.

        INPUT:

        - ``input_index`` -- **integer**; the index of inputs to generate testing data. For example,
          inputs=[key, plaintext], input_index=0 means it will generate the key avalanche dataset. if input_index=1
          means it will generate the plaintext avalanche dataset
        - ``number_of_samples_in_one_line`` -- **integer**; how many testing data should be generated in one line should
          be passed to the statistical test tool
        - ``number_of_lines`` -- **integer**; how many lines should be passed to the statistical test tool
        - ``round_start`` -- **integer** (default: `0`); the round that the statistical test starts (includes, index
          starts from 0)
        - ``round_end`` -- **integer** (default: `0`); the round that the statistical test ends (excludes, index starts
          from 0), if set to 0, means run to the last round
        - ``nist_sts_report_folder_prefix`` -- **string**
          (default: `test_reports/statistical_tests/nist_statistics_report`); the folder to save the generated
          statistics report from NIST STS
        - ``flag_chart`` -- **boolean** (default: `False`); draw the chart from nist statistical test if set to True


        OUTPUT:

        - ``nist_sts_report_dicts`` -- Dictionary-structure result parsed from nist statistical report. One could also
          see the corresponding report generated under the folder nist_statistics_report folder

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.statistical_tests.nist_statistical_tests import StatisticalTests
            sage: F = StatisticalTests(SpeckBlockCipher(number_of_rounds=3))
            sage: result = F.run_avalanche_nist_statistics_test(0, 10, 10, round_end=2)
                 Statistical Testing In Progress.........
            ...
            Finished.
        """
        self.dataset_type = DatasetType.avalanche
        self.input_index = input_index
        if round_end == 0:
            round_end = self.cipher.number_of_rounds
        self.number_of_lines = number_of_lines
        block_size = self.cipher.output_bit_size
        self.number_of_blocks_in_one_sample = self.cipher.inputs_bit_size[self.input_index]
        self.number_of_samples_in_one_line = number_of_samples_in_one_line
        self.number_of_samples = self.number_of_samples_in_one_line * (self.number_of_lines + 1)
        self.bits_in_one_line = self.number_of_blocks_in_one_sample * block_size * self.number_of_samples_in_one_line
        self.folder_prefix = nist_sts_report_folder_prefix

        self._create_report_folder()

        dataset_generate_time = time.time()
        dataset = self.data_generator.generate_avalanche_dataset(input_index=self.input_index,
                                                                 number_of_samples=self.number_of_samples)
        dataset_generate_time = time.time() - dataset_generate_time
        if not dataset:
            return
        self._write_execution_time(f'Compute {self.dataset_type.value}', dataset_generate_time)

        return self._generate_sts_dicts(dataset, round_start, round_end, "avalanche", flag_chart)

    def run_correlation_nist_statistics_test(
            self, input_index, number_of_samples_in_one_line, number_of_lines,
            number_of_blocks_in_one_sample=8128, round_start=0, round_end=0,
            nist_sts_report_folder_prefix=reports_path, flag_chart=False):
        r"""
        Run the correlation test using NIST statistical tools.

        INPUT:

        - ``input_index`` -- **integer**; the index of inputs to generate testing data. For example,
          inputs=[key, plaintext], input_index=0 means it will generate the key avalanche dataset. if input_index=1
          means it will generate the plaintext avalanche dataset
        - ``number_of_samples_in_one_line`` -- **integer**; how many testing data should be generated in one line should
          be passed to the statistical test tool
        - ``number_of_lines`` -- **integer**; how many lines should be passed to the statistical test tool
        - ``number_of_blocks_in_one_sample`` -- **integer** (default: `8128`); how many blocks should be generated in
          one test sequence
        - ``round_start`` -- **integer** (default: `0`); the round that the statistical test starts (includes, index
          starts from 0)
        - ``round_end`` -- the round that the statistical test ends (excludes, index starts from 0), if set to 0, means
          run to the last round.
        - ``nist_sts_report_folder_prefix`` -- **string**
          (default: `test_reports/statistical_tests/nist_statistics_report`); the folder to save the generated
          statistics report from NIST STS
        - ``flag_chart`` -- **boolean** (default: `False`); draw the chart from nist statistical test if set to True

        OUTPUT:

        - ``nist_sts_report_dicts`` -- Dictionary-structure result parsed from nist statistical report. One could also
          see the corresponding report generated under the folder nist_statistics_report folder

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.statistical_tests.nist_statistical_tests import StatisticalTests
            sage: F = StatisticalTests(SpeckBlockCipher(number_of_rounds=3))
            sage: result = F.run_correlation_nist_statistics_test(0, 10, 10, round_end=2)
                 Statistical Testing In Progress.........
            ...
            Finished.
        """
        self.dataset_type = DatasetType.correlation
        self.input_index = input_index
        if round_end == 0:
            round_end = self.cipher.number_of_rounds
        self.number_of_lines = number_of_lines
        block_size = self.cipher.output_bit_size
        self.number_of_blocks_in_one_sample = number_of_blocks_in_one_sample
        self.number_of_samples_in_one_line = number_of_samples_in_one_line
        self.number_of_samples = self.number_of_samples_in_one_line * (self.number_of_lines + 1)
        self.bits_in_one_line = self.number_of_blocks_in_one_sample * block_size * self.number_of_samples_in_one_line
        self.folder_prefix = nist_sts_report_folder_prefix

        self._create_report_folder()

        dataset_generate_time = time.time()
        dataset = self.data_generator.generate_correlation_dataset(
            input_index=self.input_index, number_of_samples=self.number_of_samples,
            number_of_blocks_in_one_sample=self.number_of_blocks_in_one_sample)
        dataset_generate_time = time.time() - dataset_generate_time
        if not dataset:
            return
        self._write_execution_time(f'Compute {self.dataset_type.value}', dataset_generate_time)

        return self._generate_sts_dicts(dataset, round_start, round_end, "correlation", flag_chart)

    def run_CBC_nist_statistics_test(
            self, input_index, number_of_samples_in_one_line, number_of_lines,
            number_of_blocks_in_one_sample=8192, round_start=0, round_end=0,
            nist_sts_report_folder_prefix=reports_path, flag_chart=False):
        r"""
        Run the CBC test using NIST statistical tools.

        INPUT:

        - ``input_index`` -- **integer**; the index of inputs to generate testing data. For example,
          inputs=[key, plaintext], input_index=0 means it will generate the key avalanche dataset. if input_index=1
          means it will generate the plaintext avalanche dataset
        - ``number_of_samples_in_one_line`` -- **integer**; how many testing data should be generated in one line should
          be passed to the statistical test tool
        - ``number_of_lines`` -- **integer**; how many lines should be passed to the statistical test tool
        - ``number_of_blocks_in_one_sample`` -- **integer** (default: `8192`); how many blocks should be generated in
          one test sequence
        - ``round_start`` -- **integer** (default: `0`); the round that the statistical test starts (includes, index
          starts from 0)
        - ``round_end`` -- **integer** (default: `0`); the round that the statistical test ends (excludes, index starts
          from 0), if set to 0, means run to the last round
        - ``nist_sts_report_folder_prefix`` -- **string**
          (default: `test_reports/statistical_tests/nist_statistics_report`); the folder to save the generated
          statistics report from NIST STS
        - ``flag_chart`` -- **boolean** (default: `False`); draw the chart from nist statistical test if set to True

        OUTPUT:

        - ``nist_sts_report_dicts`` -- Dictionary-structure result parsed from nist statistical report. One could also
          see the corresponding report generated under the folder nist_statistics_report folder

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.statistical_tests.nist_statistical_tests import StatisticalTests
            sage: F = StatisticalTests(SpeckBlockCipher(number_of_rounds=3))
            sage: result = F.run_CBC_nist_statistics_test(0, 2, 2, round_end=2) # long time
                 Statistical Testing In Progress.........
            ...
            Finished.
        """
        self.dataset_type = DatasetType.cbc
        self.input_index = input_index
        if round_end == 0:
            round_end = self.cipher.number_of_rounds
        self.number_of_lines = number_of_lines
        block_size = self.cipher.output_bit_size
        self.number_of_blocks_in_one_sample = number_of_blocks_in_one_sample
        self.number_of_samples_in_one_line = number_of_samples_in_one_line
        self.number_of_samples = self.number_of_samples_in_one_line * (self.number_of_lines + 1)
        self.bits_in_one_line = self.number_of_blocks_in_one_sample * block_size * self.number_of_samples_in_one_line
        self.folder_prefix = nist_sts_report_folder_prefix

        self._create_report_folder()

        dataset_generate_time = time.time()
        dataset = self.data_generator.generate_cbc_dataset(
            input_index=input_index, number_of_samples=self.number_of_samples,
            number_of_blocks_in_one_sample=self.number_of_blocks_in_one_sample)

        dataset_generate_time = time.time() - dataset_generate_time
        if not dataset:
            return
        self._write_execution_time(f'Compute {self.dataset_type.value}', dataset_generate_time)

        return self._generate_sts_dicts(dataset, round_start, round_end, "CBC", flag_chart)

    def run_random_nist_statistics_test(
            self, input_index, number_of_samples_in_one_line, number_of_lines,
            number_of_blocks_in_one_sample=8128, round_start=0, round_end=0,
            nist_sts_report_folder_prefix=reports_path, flag_chart=False):
        r"""
        Run the random test using NIST statistical tools.

        INPUT:

        - ``input_index`` -- **integer**; the index of inputs to generate testing data. For example,
          inputs=[key, plaintext], input_index=0 means it will generate the key avalanche dataset. if input_index=1
          means it will generate the plaintext avalanche dataset
        - ``number_of_samples_in_one_line`` -- **integer**; how many testing data should be generated in one line should
          be passed to the statistical test tool
        - ``number_of_lines`` -- **integer**; how many lines should be passed to the statistical test tool
        - ``number_of_blocks_in_one_sample`` -- **integer** (default: `8128`); how many blocks should be generated in
          one test sequence
        - ``round_start`` -- **integer** (default: `0`); the round that the statistical test starts (includes, index
          starts from 0)
        - ``round_end`` -- **integer** (default: `0`); the round that the statistical test ends (excludes, index starts
          from 0), if set to 0, means run to the last round
        - ``nist_sts_report_folder_prefix`` -- **string**
          (default: `test_reports/statistical_tests/nist_statistics_report`); The folder to save the generated
          statistics report from NIST STS
        - ``flag_chart`` -- **boolean** (default: `False`); draw the chart from nist statistical test if set to True

        OUTPUT:

        - ``nist_sts_report_dicts`` -- Dictionary-structure result parsed from nist statistical report. One could also
          see the corresponding report generated under the folder nist_statistics_report folder

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.statistical_tests.nist_statistical_tests import StatisticalTests
            sage: F = StatisticalTests(SpeckBlockCipher(number_of_rounds=3))
            sage: result = F.run_random_nist_statistics_test(0, 10, 10, round_end=2)
                 Statistical Testing In Progress.........
            ...
            Finished.
        """
        self.dataset_type = DatasetType.random
        self.input_index = input_index
        if round_end == 0:
            round_end = self.cipher.number_of_rounds
        self.number_of_lines = number_of_lines
        block_size = self.cipher.output_bit_size
        self.number_of_blocks_in_one_sample = number_of_blocks_in_one_sample
        self.number_of_samples_in_one_line = number_of_samples_in_one_line
        self.number_of_samples = self.number_of_samples_in_one_line * (self.number_of_lines + 1)
        self.bits_in_one_line = self.number_of_blocks_in_one_sample * block_size * self.number_of_samples_in_one_line
        self.folder_prefix = nist_sts_report_folder_prefix

        self._create_report_folder()

        dataset_generate_time = time.time()
        dataset = self.data_generator.generate_random_dataset(
            input_index=input_index, number_of_samples=self.number_of_samples,
            number_of_blocks_in_one_sample=self.number_of_blocks_in_one_sample)
        dataset_generate_time = time.time() - dataset_generate_time
        if not dataset:
            return
        self._write_execution_time(f'Compute {self.dataset_type.value}', dataset_generate_time)

        return self._generate_sts_dicts(dataset, round_start, round_end, "random", flag_chart)

    def run_low_density_nist_statistics_test(
            self, input_index, number_of_samples_in_one_line,
            number_of_lines, ratio=1, round_start=0, round_end=0,
            nist_sts_report_folder_prefix=reports_path, flag_chart=False):
        r"""
        Run the low density test using NIST statistical tools.

        INPUT:

        - ``input_index`` -- **integer**; the index of inputs to generate testing data. For example,
          inputs=[key, plaintext], input_index=0 means it will generate the key avalanche dataset. if input_index=1
          means it will generate the plaintext avalanche dataset
        - ``number_of_samples_in_one_line`` -- **integer**; how many testing data should be generated in one line should
          be passed to the statistical test tool
        - ``number_of_lines`` -- **integer**; how many lines should be passed to the statistical test tool
        - ``ratio`` -- **integer** (default: `1`); the ratio of weight 2 (that is, two 1 in the input) as low density
          inputs, range in [0, 1]. For example, if ratio = 0.5, means half of the weight 2 low density inputs will be
          taken as inputs
        - ``round_start`` -- **integer** (default: `0`); the round that the statistical test starts (includes, index
          starts from 0)
        - ``round_end`` -- **integer** (default: `0`); the round that the statistical test ends (excludes, index starts
          from 0), if set to 0, means run to the last round
        - ``nist_sts_report_folder_prefix`` -- **string**
          (default: `test_reports/statistical_tests/nist_statistics_report`); the folder to save the generated
          statistics report from NIST STS
        - ``flag_chart`` -- **boolean** (default: `False`); draw the chart from nist statistical test if set to True

        OUTPUT:

        - ``nist_sts_report_dicts`` -- Dictionary-structure result parsed from nist statistical report. One could also
          see the corresponding report generated under the folder nist_statistics_report folder

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.statistical_tests.nist_statistical_tests import StatisticalTests
            sage: F = StatisticalTests(SpeckBlockCipher(number_of_rounds=3))
            sage: result = F.run_low_density_nist_statistics_test(0, 10, 10, round_end=2)
                 Statistical Testing In Progress.........
            ...
            Finished.
        """
        self.dataset_type = DatasetType.low_density
        self.input_index = input_index
        if round_end == 0:
            round_end = self.cipher.number_of_rounds
        self.number_of_lines = number_of_lines
        block_size = self.cipher.output_bit_size
        self.number_of_blocks_in_one_sample = int(
            1 + self.cipher.inputs_bit_size[input_index] + math.ceil(
                self.cipher.inputs_bit_size[input_index] * (
                            self.cipher.inputs_bit_size[input_index] - 1) * ratio / 2))
        self.number_of_samples_in_one_line = number_of_samples_in_one_line
        self.number_of_samples = self.number_of_samples_in_one_line * (self.number_of_lines + 1)
        self.bits_in_one_line = self.number_of_blocks_in_one_sample * block_size * self.number_of_samples_in_one_line
        self.folder_prefix = nist_sts_report_folder_prefix

        self._create_report_folder()

        dataset_generate_time = time.time()
        dataset = self.data_generator.generate_low_density_dataset(input_index=input_index,
                                                                   number_of_samples=self.number_of_samples,
                                                                   ratio=ratio)
        dataset_generate_time = time.time() - dataset_generate_time
        if not dataset:
            return
        self._write_execution_time(f'Compute {self.dataset_type.value}', dataset_generate_time)

        return self._generate_sts_dicts(dataset, round_start, round_end, "low_density", flag_chart)

    def run_high_density_nist_statistics_test(
            self, input_index, number_of_samples_in_one_line, number_of_lines,
            ratio=1, round_start=0, round_end=0,
            nist_sts_report_folder_prefix=reports_path, flag_chart=False):
        r"""
        Run the high density test using NIST statistical tools.

        INPUT:

        - ``input_index`` -- **integer**; the index of inputs to generate testing data. For example,
          inputs=[key, plaintext], input_index=0 means it will generate the key avalanche dataset. if input_index=1
          means it will generate the plaintext avalanche dataset
        - ``number_of_samples_in_one_line`` -- **integer**; how many testing data should be generated in one line should
          be passed to the statistical test tool
        - ``number_of_lines`` -- **integer**; how many lines should be passed to the statistical test tool
        - ``ratio`` -- **integer** (default: `1`); the ratio of weight 2 (that is, two 1 in the input) as high density
          inputs, range in [0, 1]. For example, if ratio = 0.5, means half of the weight 2 high density inputs will be
          taken as inputs
        - ``round_start`` -- **integer** (default: `0`); the round that the statistical test starts (includes, index
          starts from 0)
        - ``round_end`` -- **integer** (default: `0`); the round that the statistical test ends (excludes, index starts
          from 0), if set to 0, means run to the last round
        - ``nist_sts_report_folder_prefix`` -- **string**
          (default: `test_reports/statistical_tests/nist_statistics_report`); the folder to save the
          generated statistics report from NIST STS
        - ``flag_chart`` -- **boolean** (default: `False`); draw the chart from nist statistical test if set to True

        OUTPUT:

        - ``nist_sts_report_dicts`` -- Dictionary-structure result parsed from nist statistical report. One could also
          see the corresponding report generated under the folder nist_statistics_report folder

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.statistical_tests.nist_statistical_tests import StatisticalTests
            sage: F = StatisticalTests(SpeckBlockCipher(number_of_rounds=3))
            sage: result = F.run_high_density_nist_statistics_test(0, 10, 10, round_end=2)
                 Statistical Testing In Progress.........
            ...
            Finished.
        """
        self.dataset_type = DatasetType.high_density
        self.input_index = input_index
        if round_end == 0:
            round_end = self.cipher.number_of_rounds
        self.number_of_lines = number_of_lines
        block_size = self.cipher.output_bit_size
        self.number_of_blocks_in_one_sample = int(
            1 + self.cipher.inputs_bit_size[input_index] + math.ceil(
                self.cipher.inputs_bit_size[input_index] * (
                        self.cipher.inputs_bit_size[input_index] - 1) * ratio / 2))
        self.number_of_samples_in_one_line = number_of_samples_in_one_line
        self.number_of_samples = self.number_of_samples_in_one_line * (self.number_of_lines + 1)
        self.bits_in_one_line = self.number_of_blocks_in_one_sample * block_size * self.number_of_samples_in_one_line
        self.folder_prefix = nist_sts_report_folder_prefix

        self._create_report_folder()

        dataset_generate_time = time.time()
        dataset = self.data_generator.generate_high_density_dataset(input_index=input_index,
                                                                    number_of_samples=self.number_of_samples,
                                                                    ratio=ratio)
        dataset_generate_time = time.time() - dataset_generate_time
        if not dataset:
            return
        self._write_execution_time(f'Compute {self.dataset_type.value}', dataset_generate_time)

        return self._generate_sts_dicts(dataset, round_start, round_end, "high_density", flag_chart)
