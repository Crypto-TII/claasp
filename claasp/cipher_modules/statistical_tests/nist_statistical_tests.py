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
from datetime import timedelta, datetime
import matplotlib.pyplot as plt

from claasp.cipher_modules.statistical_tests.dataset_generator import DatasetGenerator, DatasetType


TEST_ID_TABLE = {

    'Frequency': 1,
    'BlockFrequency': 2,
    'CumulativeSums': 3,
    'Runs': 5,
    'LongestRun': 6,
    'Rank': 7,
    'FFT': 8,
    'NonOverlappingTemplate': 9,
    'OverlappingTemplate': 157,
    'Universal': 158,
    'ApproximateEntropy': 159,
    'RandomExcursions': 160,
    'RandomExcursionsVariant': 168,
    'Serial': 186,
    'LinearComplexity': 188

}


class NISTStatisticalTests:

    def __init__(self, cipher):
        cipher.sort_cipher()
        self.cipher = cipher
        self.data_generator = DatasetGenerator(cipher)
        str_of_inputs_bit_size = list(map(str, cipher.inputs_bit_size))
        self._cipher_primitive = cipher.id + "_" + "_".join(str_of_inputs_bit_size)

    def nist_statistical_tests(self, test_type,
                               bits_in_one_sequence='default',
                               number_of_sequences='default',
                               input_index=0,
                               round_start=0,
                               round_end=0,
                               nist_report_folder_prefix="nist_statistics_report",
                               statistical_test_option_list='1' + 14 * '0'
                               ):
        """

         Run the nist statistical tests.

         INPUT:

             - ``test_type`` -- string describing which test to run
             - ``bits_in_one_sequence`` -- integer parameter used to run the nist tests
             - ``number_of_sequences`` -- integer parameter used to run the nist tests
             - ``input_index`` -- cipher input index
             - ``round_start`` -- first round to be considered in the cipher
             - ``round_end`` -- last round to be considered in the cipher
             - ``nist_report_folder_prefix`` - prefix for the unparsed nist tests output folder

         OUTPUT:

             - The results are going to be saved in a dictionary format compatible with the Report class

         EXAMPLE:

             from claasp.cipher_modules.statistical_tests.nist_statistical_tests import StatisticalTests
             from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
             speck = SpeckBlockCipher(number_of_rounds=5)
             nist_tests = StatisticalTests(speck)
             nist_avalanche_test_results = nist_tests.nist_statistical_tests('avalanche')

         """

        time_date = 'date:'+'time:'.join(str(datetime.now()).split(' '))
        nist_test = {

            'input_parameters': {
                'test_name': 'nist_statistical_tests',
                'cipher': self.cipher,
                'test_type': test_type,
                'round_start': round_start,
                'round_end': round_end,
                'input': self.cipher.inputs[input_index]
            },
            'test_results': None
        }

        dataset_generate_time = time.time()

        self.folder_prefix = os.getcwd() + '/test_reports/' + nist_report_folder_prefix

        if round_end == 0:
            round_end = self.cipher.number_of_rounds

        if test_type == 'avalanche':

            self.dataset_type = DatasetType.avalanche
            self.input_index = input_index

            if bits_in_one_sequence == 'default':
                bits_in_one_sequence = 1048576
            if number_of_sequences == 'default':
                number_of_sequences = 384

            sample_size = self.cipher.inputs_bit_size[input_index] * self.cipher.output_bit_size
            number_of_samples_in_one_sequence = math.ceil(bits_in_one_sequence / sample_size)
            self.number_of_sequences = number_of_sequences
            self.number_of_samples_in_one_sequence = number_of_samples_in_one_sequence
            self.number_of_samples = self.number_of_samples_in_one_sequence * (self.number_of_sequences + 1)
            self.bits_in_one_sequence = sample_size * self.number_of_samples_in_one_sequence

            self._create_report_folder(time_date,statistical_test_option_list)

            dataset = self.data_generator.generate_avalanche_dataset(input_index=self.input_index,
                                                                     number_of_samples=self.number_of_samples)

        elif test_type == 'correlation':

            self.dataset_type = DatasetType.correlation
            self.input_index = input_index

            if bits_in_one_sequence == 'default':
                bits_in_one_sequence = 1048576
            if number_of_sequences == 'default':
                number_of_sequences = 384

            number_of_blocks_in_one_sample = math.ceil(bits_in_one_sequence / self.cipher.output_bit_size)
            self.number_of_sequences = number_of_sequences
            self.number_of_samples = self.number_of_sequences + 1
            self.bits_in_one_sequence = number_of_blocks_in_one_sample * self.cipher.output_bit_size
            self._create_report_folder(time_date,statistical_test_option_list)

            dataset = self.data_generator.generate_correlation_dataset(input_index=self.input_index,
                                                                       number_of_samples=self.number_of_samples,
                                                                       number_of_blocks_in_one_sample=number_of_blocks_in_one_sample)

        elif test_type == 'cbc':

            self.dataset_type = DatasetType.cbc
            self.input_index = input_index
            if bits_in_one_sequence == 'default':
                bits_in_one_sequence = 1048576
            if number_of_sequences == 'default':
                number_of_sequences = 384

            number_of_blocks_in_one_sample = math.ceil(bits_in_one_sequence / self.cipher.output_bit_size)
            self.number_of_sequences = number_of_sequences
            self.number_of_samples = self.number_of_sequences + 1
            self.bits_in_one_sequence = number_of_blocks_in_one_sample * self.cipher.output_bit_size
            self._create_report_folder(time_date,statistical_test_option_list)

            dataset = self.data_generator.generate_cbc_dataset(input_index=self.input_index,
                                                               number_of_samples=self.number_of_samples,
                                                               number_of_blocks_in_one_sample=number_of_blocks_in_one_sample)

        elif test_type == 'random':
            self.dataset_type = DatasetType.random
            self.input_index = input_index
            if bits_in_one_sequence == 'default':
                bits_in_one_sequence = 1040384
            if number_of_sequences == 'default':
                number_of_sequences = 128

            self.number_of_blocks_in_one_sample = math.ceil(bits_in_one_sequence / self.cipher.output_bit_size)
            self.number_of_sequences = number_of_sequences
            self.number_of_samples = self.number_of_sequences + 1
            self.bits_in_one_sequence = self.number_of_blocks_in_one_sample * self.cipher.output_bit_size
            self._create_report_folder(time_date,statistical_test_option_list)

            dataset = self.data_generator.generate_random_dataset(input_index=self.input_index,
                                                                  number_of_samples=self.number_of_samples,
                                                                  number_of_blocks_in_one_sample=self.number_of_blocks_in_one_sample)

        elif test_type == 'low_density':
            self.dataset_type = DatasetType.low_density
            self.input_index = input_index
            if bits_in_one_sequence == 'default':
                bits_in_one_sequence = 1056896
            if number_of_sequences == 'default':
                number_of_sequences = 1

            number_of_blocks_in_one_sample = math.ceil(bits_in_one_sequence / self.cipher.output_bit_size)
            self.number_of_sequences = number_of_sequences
            self.number_of_samples = self.number_of_sequences + 1
            n = self.cipher.inputs_bit_size[self.input_index]
            ratio = min(1, (number_of_blocks_in_one_sample - 1 - n) / math.comb(n, 2))
            self.number_of_blocks_in_one_sample = int(1 + n + math.ceil(math.comb(n, 2) * ratio))
            self.bits_in_one_sequence = self.number_of_blocks_in_one_sample * self.cipher.output_bit_size
            self._create_report_folder(time_date,statistical_test_option_list)

            dataset = self.data_generator.generate_low_density_dataset(input_index=self.input_index,
                                                                       number_of_samples=self.number_of_samples,
                                                                       ratio=ratio)
        elif test_type == 'high_density':
            self.dataset_type = DatasetType.high_density
            self.input_index = input_index
            if bits_in_one_sequence == 'default':
                bits_in_one_sequence = 1056896
            if number_of_sequences == 'default':
                number_of_sequences = 1

            number_of_blocks_in_one_sample = math.ceil(bits_in_one_sequence / self.cipher.output_bit_size)
            self.number_of_sequences = number_of_sequences
            self.number_of_samples = self.number_of_sequences + 1
            n = self.cipher.inputs_bit_size[self.input_index]
            ratio = min(1, (number_of_blocks_in_one_sample - 1 - n) / math.comb(n, 2))
            self.number_of_blocks_in_one_sample = int(1 + n + math.ceil(math.comb(n, 2) * ratio))
            self.bits_in_one_sequence = self.number_of_blocks_in_one_sample * self.cipher.output_bit_size
            self._create_report_folder(time_date,statistical_test_option_list)

            dataset = self.data_generator.generate_high_density_dataset(input_index=self.input_index,
                                                                        number_of_samples=self.number_of_samples,
                                                                        ratio=ratio)
        else:
            # maybe print the enum value of Dataset.type
            print(
                'Invalid test_type choice. Choose among the following: avalanche, correlation, cbc, random, low_density, high_density')
            return

        dataset_generate_time = time.time() - dataset_generate_time
        if not dataset:
            return
        self._write_execution_time(f'Compute {self.dataset_type.value}', dataset_generate_time)
        nist_test['test_results'] = self._generate_nist_dicts(time_date=time_date, dataset=dataset, round_start=round_start,
                                                              round_end=round_end,
                                                              statistical_test_option_list=statistical_test_option_list)
        nist_test['input_parameters']['bits_in_one_sequence'] = bits_in_one_sequence
        nist_test['input_parameters']['number_of_sequences'] = number_of_sequences

        return nist_test

    @staticmethod
    def _run_nist_statistical_tests_tool(input_file, bit_stream_length=10000, number_of_bit_streams=10,
                                         input_file_format=1,
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
            sage: from claasp.cipher_modules.statistical_tests.nist_statistical_tests import NISTStatisticalTests
            sage: if not os.path.exists(f'test_reports/statistical_tests/experiments'):
            ....:     os.makedirs(f'test_reports/statistical_tests/experiments')
            sage: result = NISTStatisticalTests._run_nist_statistical_tests_tool(
            ....:     f'claasp/cipher_modules/statistical_tests/input_data_example',
            ....:     10000, 10, 1)
                 Statistical Testing In Progress.........
                 Statistical Testing Complete!!!!!!!!!!!!

            sage: result
            True
        """

        def _mkdir_folder_experiment(path_prefix, folder_experiment):
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
                _mkdir_folder_experiment(path_prefix, experiment_name)
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
    def _parse_report(report_filename, statistical_test_option_list='1' + 14 * '0'):
        """
        Parse the nist statistical tests report. It will return the parsed result in a dictionary format.

        INPUT:

        - ``report_filename`` -- **str**; the filename of the report you need to parse

        OUTPUT:

        - ``report_dict`` -- return the parsed result in a dictionary format

        EXAMPLES::

            sage: from claasp.cipher_modules.statistical_tests.nist_statistical_tests import NISTStatisticalTests
            sage: dict = NISTStatisticalTests._parse_report(f'claasp/cipher_modules/statistical_tests/finalAnalysisReportExample.txt')
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
        passed_line_1 = [line for line in lines if 'random excursion (variant) test is approximately' in line][0]
        passed_1 = int([x for x in passed_line_1.split(' ') if x.isnumeric()][0])
        total_line_1 = [line for line in lines if 'sample size' in line and 'binary sequences.' in line][0]
        total_1 = int([x for x in total_line_1.split(' ') if x.isnumeric()][0])
        threshold_rate.append({
            "total": total_1,
            "passed": passed_1})
        try:
            total_passed_line_2 = \
                [line for line in lines if 'is approximately =' in line and 'for a sample size' in line][0]
            total_passed = [int(x) for x in total_passed_line_2 if x.isdigit()]
            if len(total_passed) != 1:
                total_2 = total_passed[1]
                passed_2 = total_passed[0]
                threshold_rate.append({
                    "total": total_2,
                    "passed": passed_2})
        except IndexError:
            pass

        report_dict["number_of_sequences_threshold"] = threshold_rate
        test_line_index = lines.index(
            '- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n') - 2
        # retrieve test
        lines_test = lines[7:test_line_index]
        test_list = []
        for i in range(test_line_index - 7):
            test_dict = {}

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

            test_dict['test_id'] = TEST_ID_TABLE[seqs[12]] + len(
                [test for test in test_list if test['test_name'] == test_dict['test_name']])

            test_list.append(test_dict)
        report_dict["randomness_test"] = test_list
        f.close()
        print(f'Parsing {report_filename} is finished.')
        return report_dict

    @staticmethod
    def _generate_chart_round(report_dict, output_dir='', show_graph=False):
        """
        Generate the corresponding chart based on the parsed report dictionary.

        INPUT:

        - ``report_dict`` -- **dictionary**; the parsed result in a dictionary format

        OUTPUT:

        - save the chart with filename
          f'nist_{report_dict["data_type"]}_{report_dict["cipher_name"]}_round_{report_dict["round"]}.png'

        """

        if len(report_dict['randomness_test']) == 1:
            return
        print(f'Drawing round {report_dict["round"]} is in progress.')
        x = [test['test_id'] for test in report_dict['randomness_test']]
        y = [0 for _ in range(len(x))]
        for i in range(len(y)):
            y[i] = [test['passed_proportion'] for test in report_dict['randomness_test'] if test['test_id'] == x[i]][0]

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
            f'{report_dict["cipher_name"]}:{report_dict["data_type"]}, Round " {report_dict["round"]}|{report_dict["rounds"]}')
        plt.xlabel('Test ID')
        plt.ylabel('Passing Rate')

        if show_graph == False:
            if output_dir == '':
                output_dir = f'nist_{report_dict["data_type"]}_{report_dict["cipher_name"]}_round_{report_dict["round"]}.png'
                plt.savefig(output_dir)
            else:
                plt.savefig(
                    output_dir + '/' + f'nist_{report_dict["data_type"]}_{report_dict["cipher_name"]}_round_{report_dict["round"]}.png')
        else:
            plt.show()
            plt.clf()
            plt.close()
        print(f'Drawing round {report_dict["round"]} is finished.')

    @staticmethod
    def _generate_chart_all(report_dict_list, report_folder="", show_graph=False):
        """
        Generate the corresponding chart based on the list of parsed report dictionary for all rounds.

        INPUT:

        - ``report_dict_list`` -- **list**; the list of the parsed result in a dictionary format for all rounds

        OUTPUT:

        - save the chart with filename f'nist_{data_type}_{cipher_name}.png'

        """
        print("Drawing chart for all rounds is in progress.")
        x = [i + 1 for i in range(report_dict_list[0]["round"], report_dict_list[-1]["round"]+1)]
        y = [0 for _ in range(len(x))]
        for i in range(len(report_dict_list)):
            y[i] = report_dict_list[i]["passed_tests"]


        random_round = -1
        for r in range(report_dict_list[0]["rounds"]):
            if report_dict_list[r]["passed_tests"] > len(report_dict_list[0]['randomness_test'])*0.98:
                random_round = report_dict_list[r]["round"] + 1
                break

        plt.clf()
        plt.scatter(x, y, color="cadetblue")
        plt.hlines(len(report_dict_list[0]['randomness_test'])*0.98, 1, report_dict_list[0]["rounds"], color="darkorange", linestyle="dotted", linewidth=2,
                   label=str(math.ceil(len(report_dict_list[0]['randomness_test'])*0.98)))
        plt.plot(x, y, 'o--', color='olive', alpha=0.4)
        if random_round > -1:
            plt.title(
                f'{report_dict_list[0]["cipher_name"]}: {report_dict_list[0]["data_type"]}, Random at {random_round}|{report_dict_list[0]["rounds"]}')
        else:
            plt.title(f'{report_dict_list[0]["cipher_name"]}: {report_dict_list[0]["data_type"]}')
        plt.xlabel('Round')
        plt.ylabel('Tests passed')
        plt.xticks([i * 2 + 1 for i in range(int(report_dict_list[0]["rounds"] / 2) + 1)],
                   [i * 2 + 1 for i in range(int(report_dict_list[0]["rounds"] / 2 + 1))])
        plt.yticks([i * 10 for i in range(int(len(report_dict_list[0]["randomness_test"]) / 10) + 1)],
                   [i * 10 for i in range(int(len(report_dict_list[0]["randomness_test"]) / 10 + 1))])
        chart_filename = f'nist_{report_dict_list[0]["data_type"]}_{report_dict_list[0]["cipher_name"]}.png'

        if show_graph == False:
            plt.savefig(os.path.join(report_folder, chart_filename))
        else:
            plt.show()
            plt.clf()
            plt.close()
        print(f'Drawing chart for all rounds is in finished.')

    def _create_report_folder(self,time_date,statistical_test_option_list):
        self.report_folder = os.path.join(self.folder_prefix,
                                          f'{self._cipher_primitive}_{self.dataset_type.name}_index{self.input_index}_{self.number_of_sequences}lines_{self.bits_in_one_sequence}bits_{statistical_test_option_list}test_option_list_{time_date}time')
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

    def _generate_nist_dicts(self,time_date, dataset, round_start, round_end, statistical_test_option_list='1' + 14 * '0'):
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

            report_folder_round = os.path.abspath(os.path.join(self.report_folder, f'round_{round_number}_{time_date}time'))
            dataset[round_number].tofile(dataset_filename)

            sts_execution_time = time.time()
            self._run_nist_statistical_tests_tool(dataset_filename, self.bits_in_one_sequence,
                                                  self.number_of_sequences, 1,
                                                  statistical_test_option_list=statistical_test_option_list)
            sts_execution_time = time.time() - sts_execution_time
            try:
                shutil.move(nist_local_experiment_folder, report_folder_round)
            except OSError:
                shutil.rmtree(report_folder_round)
                shutil.move(nist_local_experiment_folder, report_folder_round)

            self._write_execution_time(f'Compute round {round_number}', sts_execution_time)

            try:
                # generate report
                sts_report_dict = self._parse_report(
                    os.path.join(report_folder_round, "AlgorithmTesting/finalAnalysisReport.txt"))
                sts_report_dict['data_type'] = f'{self.cipher.inputs[self.input_index]}_{self.dataset_type.value}'
                sts_report_dict["cipher_name"] = self.cipher.id
                sts_report_dict["round"] = round_number
                sts_report_dict["rounds"] = self.cipher.number_of_rounds
                sts_report_dicts.append(sts_report_dict)
            except OSError:
                print(f"Error in parsing report for round {round_number}.")

        print("Finished.")
        return sts_report_dicts

    def _generate_chart_for_all_rounds(self, flag_chart, sts_report_dicts):
        if flag_chart:
            try:
                self._generate_chart_all(sts_report_dicts, self.report_folder)
            except OSError:
                print("Error in generating all round chart.")
