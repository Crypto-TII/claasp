
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
from datetime import timedelta
import matplotlib.pyplot as plt

from claasp.cipher_modules.statistical_tests.dataset_generator import DatasetGenerator, DatasetType


class DieharderTests:
    _DIEHARDER_OUTPUT = "dieharder_test_output.txt"

    def __init__(self, cipher):
        cipher.sort_cipher()
        self.cipher = cipher
        self.data_generator = DatasetGenerator(cipher)
        str_of_inputs_bit_size = list(map(str, cipher.inputs_bit_size))
        self._cipher_primitive = cipher.id + "_" + "_".join(str_of_inputs_bit_size)

    @staticmethod
    def run_dieharder_statistical_tests_tool_interactively(input_file):
        """
        Run dieharder tests using the Dieharder library [1]. The result will be in dieharder_test_output.txt.

        [1] https://webhome.phy.duke.edu/~rgb/General/dieharder.php

        INPUT:

        - ``input_file`` -- file containing the bit streams

        OUTPUT:

        - the result would be saved as ``dieharder_test_output.txt``

        EXAMPLES::

            sage: from claasp.cipher_modules.statistical_tests.dieharder_statistical_tests import DieharderTests
            sage: result = DieharderTests.run_dieharder_statistical_tests_tool_interactively( # doctest: +SKIP
            ....:     f'claasp/cipher_modules/statistical_tests/input_data_example', # doctest: +SKIP
            ....: ) # long time # doctest: +SKIP
            ...
            Dieharder Tests Finished!!!
        """
        print("Dieharder Tests Started...")
        os.system(f'dieharder -g 201 -f {input_file}  -a > {__class__._DIEHARDER_OUTPUT}')
        print(f'Dieharder Tests Finished!!!')

    @staticmethod
    def parse_report(report_filename):
        """
        Parse the dieharder statistical tests report. It will return the parsed result in a dictionary format.

        INPUT:

        - ``report_filename`` -- the filename of the report you need to parse

        OUTPUT:

        - ``report_dict`` -- return the parsed result in a dictionary format

        EXAMPLES::

            sage: from claasp.cipher_modules.statistical_tests.dieharder_statistical_tests import DieharderTests
            sage: result = DieharderTests.run_dieharder_statistical_tests_tool_interactively( # doctest: +SKIP
            ....:     f'claasp/cipher_modules/statistical_tests/input_data_example', # doctest: +SKIP
            ....: ) # long time # doctest: +SKIP
            ...
            Dieharder Tests Finished!!!

            sage: dict = DieharderTests.parse_report(f'dieharder_test_output.txt') # doctest: +SKIP
            Parsing dieharder_test_output.txt is in progress.
            Parsing dieharder_test_output.txt is finished.
        """
        print(f'Parsing {report_filename} is in progress.')
        report_dict = {}
        with open(report_filename, 'r') as f:
            lines = f.readlines()
        # if the sts_test failed, this file will be empty
        if len(lines) == 0:
            print(report_filename + " is empty.")
            report_dict["passed_tests"] = 0
            report_dict["weak_tests"] = 0
            report_dict["failed_tests"] = 0
            report_dict["total_tests"] = 0
            test_list = [{}]
            report_dict["randomness_test"] = test_list
            return report_dict

        # retrieve results
        lines_test = lines[8:]
        total_tests = 0
        passed_tests = 0
        weak_tests = 0
        failed_tests = 0
        test_list = []
        for line in lines_test:
            test_dict = {}
            if line.find('|') == -1:
                continue
            total_tests += 1
            test_dict["test_id"] = total_tests

            seqs = line.split("|")
            test_dict["test_name"] = seqs[0].replace(" ", "")
            test_dict["ntup"] = int(seqs[1])
            test_dict["tsamples"] = int(seqs[2])
            test_dict["psamples"] = int(seqs[3])
            test_dict["p-value"] = float(seqs[4])
            test_dict["assessment"] = seqs[5].replace(" ", "").replace("\n", "")
            # check passed
            if test_dict["assessment"] == "PASSED":
                passed_tests += 1
            elif test_dict["assessment"] == "WEAK":
                weak_tests += 1
            elif test_dict["assessment"] == "FAILED":
                failed_tests += 1
            test_list.append(test_dict)
        report_dict["randomness_test"] = test_list
        report_dict["passed_tests"] = passed_tests
        report_dict["weak_tests"] = weak_tests
        report_dict["failed_tests"] = failed_tests
        report_dict["passed_tests_proportion"] = passed_tests / total_tests
        report_dict["total_tests"] = total_tests
        report_dict["test_name"] = "dieharder_statistical_tests"
        f.close()
        print(f'Parsing {report_filename} is finished.')
        return report_dict

    @staticmethod
    def generate_chart_round(report_dict):
        """
        Generate the corresponding chart based on the parsed report dictionary.

        INPUT:

        - ``report_dict`` -- the parsed result in a dictionary format

        OUTPUT:

        - save the chart with filename
          f'dieharder_{report_dict["data_type"]}_{report_dict["cipher_name"]}_round_{report_dict["round"]}.png'

        EXAMPLES::

            sage: from claasp.cipher_modules.statistical_tests.dieharder_statistical_tests import DieharderTests
            sage: result = DieharderTests.run_dieharder_statistical_tests_tool_interactively( # doctest: +SKIP
            ....:     f'claasp/cipher_modules/statistical_tests/input_data_example', # doctest: +SKIP
            ....: ) # long time # doctest: +SKIP
            ...
            Dieharder Tests Finished!!!

            sage: from claasp.cipher_modules.statistical_tests.dieharder_statistical_tests import DieharderTests
            sage: dict = DieharderTests.parse_report(f'dieharder_test_output.txt') # doctest: +SKIP
            Parsing dieharder_test_output.txt is in progress.
            Parsing dieharder_test_output.txt is finished.

            sage: dict['data_type'] = 'random' # doctest: +SKIP
            sage: dict['data_type'] = 'random' # doctest: +SKIP
            sage: dict['cipher_name'] = 'toy_cipher' # doctest: +SKIP
            sage: dict['round'] = 1 # doctest: +SKIP
            sage: dict['rounds'] = 1 # doctest: +SKIP
            sage: DieharderTests.generate_chart_round(dict) # doctest: +SKIP
            Drawing round 1 is in progress.
            Drawing round 1 is finished. Please find the chart in file dieharder_random_toy_cipher_round_1.png.
        """
        print(f'Drawing round {report_dict["round"]} is in progress.')
        x = [i for i in range(len(report_dict['randomness_test']))]
        y = [0 for _ in range(len(report_dict['randomness_test']))]
        label_y = {
            "PASSED": 1,
            "WEAK": 0,
            "FAILED": -1
        }
        for item in report_dict["randomness_test"]:
            y[item["test_id"] - 1] = label_y[item["assessment"]]

        plt.clf()
        plt.scatter(x, y, color="cadetblue")
        plt.title(
            f'{report_dict["cipher_name"]}: {report_dict["data_type"]}, Round {report_dict["round"]}|{report_dict["rounds"]}')
        plt.xlabel('Tests')
        plt.yticks([-1, 0, 1], ['FAILED', 'WEAK', 'PASSED'])
        chart_filename = f'dieharder_{report_dict["data_type"]}_{report_dict["cipher_name"]}_round_{report_dict["round"]}.png'
        plt.savefig(chart_filename)
        print(f'Drawing round {report_dict["round"]} is finished. Please find the chart in file {chart_filename}.')

    @staticmethod
    def generate_chart_all(report_dict_list):
        """
        Generate the corresponding chart based on the parsed report dictionary.

        INPUT:

        - ``report_dict`` -- the parsed result in a dictionary format

        OUTPUT:

        - save the chart with filename
          f'dieharder_{report_dict["data_type"]}_{report_dict["cipher_name"]}_round_{report_dict["round"]}.png'

        EXAMPLES::

            sage: from claasp.cipher_modules.statistical_tests.dieharder_statistical_tests import DieharderTests
            sage: result = DieharderTests.run_dieharder_statistical_tests_tool_interactively( # doctest: +SKIP
            ....:     f'claasp/cipher_modules/statistical_tests/input_data_example', # doctest: +SKIP
            ....: ) # long time # doctest: +SKIP
            ...
            Dieharder Tests Finished!!!

            sage: from claasp.cipher_modules.statistical_tests.dieharder_statistical_tests import DieharderTests
            sage: dict = DieharderTests.parse_report(f'dieharder_test_output.txt') # doctest: +SKIP
            Parsing dieharder_test_output.txt is in progress.
            Parsing dieharder_test_output.txt is finished.

            sage: dict['data_type'] = 'random' # doctest: +SKIP
            sage: dict['cipher_name'] = 'toy_cipher' # doctest: +SKIP
            sage: dict['round'] = 1 # doctest: +SKIP
            sage: dict['rounds'] = 1 # doctest: +SKIP
            sage: dict_list = [dict] # doctest: +SKIP
            sage: DieharderTests.generate_chart_all(dict_list) # doctest: +SKIP
            Drawing chart for all rounds is in progress.
            Drawing chart for all rounds is in finished. Please find the chart in file dieharder_random_toy_cipher.png.
        """
        print("Drawing chart for all rounds is in progress.")
        x = [i + 1 for i in range(report_dict_list[0]["rounds"])]
        y = [0 for _ in range(report_dict_list[0]["rounds"])]
        for i in range(len(report_dict_list)):
            y[report_dict_list[i]["round"] - 1] = report_dict_list[i]["passed_tests_proportion"]

        plt.clf()
        plt.scatter(x, y, color="cadetblue")
        plt.plot(x, y, 'o--', color='olive', alpha=0.4)
        plt.title(report_dict_list[0]["cipher_name"] + ': ' + report_dict_list[0]["data_type"])
        plt.xlabel('Round')
        plt.ylabel('Tests passed proportion')
        plt.xticks([i * 2 + 1 for i in range(int(report_dict_list[0]["rounds"] / 2) + 1)],
                   [i * 2 + 1 for i in range(int(report_dict_list[0]["rounds"] / 2 + 1))])
        # plt.grid(True)
        chart_filename = f'dieharder_{report_dict_list[0]["data_type"]}_{report_dict_list[0]["cipher_name"]}.png'
        plt.savefig(chart_filename)
        print(f'Drawing chart for all rounds is in finished. Please find the chart in file {chart_filename}.')

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

    def _generate_dieharder_dicts(self, dataset, round_start, round_end, FLAG_CHART=False):
        dataset_folder = 'dataset'
        dataset_filename = 'dieharder_input_' + self._cipher_primitive
        dataset_filename = os.path.join(dataset_folder, dataset_filename)
        dieharder_report_dicts = []

        if not os.path.exists(dataset_folder):
            try:
                os.makedirs(dataset_folder)
            except OSError as e:
                print(f'Error: {e.strerror}')
                return

        for round_number in range(round_start, round_end):
            report_round = os.path.join(self.report_folder, f'round{round_number}_{self._DIEHARDER_OUTPUT}')
            dataset[round_number].tofile(dataset_filename)

            dieharder_execution_time = time.time()
            self.run_dieharder_statistical_tests_tool_interactively(dataset_filename)
            dieharder_execution_time = time.time() - dieharder_execution_time
            try:
                os.rename(self._DIEHARDER_OUTPUT, report_round)
                print(f'Round {round_number} result is in file {report_round}')
            except OSError as e:
                print(f'Error: {e.strerror}')
                print(
                    f'Please remove the existed file {report_round} '
                    f'or indicate another filename for saving the Dieharder reports.')
                continue
            self._write_execution_time(f'Compute round {round_number}', dieharder_execution_time)

            try:
                # generate report
                dieharder_report_dict = self.parse_report(report_round)
                dieharder_report_dict[
                    'data_type'] = f'{self.cipher.inputs[self.input_index]}_{self.dataset_type.value}'
                dieharder_report_dict["cipher_name"] = self.cipher.id
                dieharder_report_dict["round"] = round_number
                dieharder_report_dict["rounds"] = self.cipher.number_of_rounds
                dieharder_report_dicts.append(dieharder_report_dict)
                # generate round chart
                if FLAG_CHART:
                    self.generate_chart_round(dieharder_report_dict)
            except OSError:
                print(f'Error in parsing report for round {round_number}.')

        # generate chart for all rounds
        if FLAG_CHART:
            try:
                self.generate_chart_all(dieharder_report_dicts)
            except OSError:
                print(f'Error in generating all round chart.')

        return dieharder_report_dicts

    def run_avalanche_dieharder_statistics_test(self, input_index, number_of_samples_in_one_line, number_of_lines,
                                                round_start=0, round_end=0,
                                                dieharder_report_folder_prefix="dieharder_statistics_report",
                                                FLAG_CHART=False):
        r"""
        Run the avalanche test.

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
          from 0). If set to 0, means run to the last round
        - ``dieharder_report_folder_prefix`` -- **string** (default: `dieharder_statistics_report`); the folder to save
          the generated statistics report from NIST STS
        - ``FLAG_CHART`` -- **boolean** (default: `False`); draw the chart from dieharder statistical test if set to
          True

        OUTPUT:

        - ``dieharder_report_dicts`` -- Dictionary-structure result parsed from dieharder statistical report. One could
          also see the corresponding report under the dieharder_statistics_report folder

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.statistical_tests.dieharder_statistical_tests import DieharderTests
            sage: F = DieharderTests(SpeckBlockCipher(number_of_rounds=3)) # doctest: +SKIP
            sage: result = F.run_avalanche_dieharder_statistics_test(0, 5, 5, round_end=1) # long time # doctest: +SKIP
            ...
            Dieharder Tests Finished!!!
            ...
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
        self.folder_prefix = dieharder_report_folder_prefix

        self._create_report_folder()

        dataset_generate_time = time.time()
        dataset = self.data_generator.generate_avalanche_dataset(input_index=self.input_index,
                                                                 number_of_samples=self.number_of_samples)
        dataset_generate_time = time.time() - dataset_generate_time
        if not dataset:
            return
        self._write_execution_time(f'Compute {self.dataset_type.value}', dataset_generate_time)

        return self._generate_dieharder_dicts(dataset, round_start, round_end, FLAG_CHART)

    def run_correlation_dieharder_statistics_test(self, input_index, number_of_samples_in_one_line, number_of_lines,
                                                  number_of_blocks_in_one_sample=8128, round_start=0, round_end=0,
                                                  dieharder_report_folder_prefix="dieharder_statistics_report",
                                                  FLAG_CHART=False):
        r"""
        Run the correlation test.

        INPUT:

        - ``input_index`` -- **integer**; the index of inputs to generate testing data. For example, inputs=[key, plaintext],
          input_index=0 means it will generate the key avalanche dataset. if input_index=1 means it will generate the
          plaintext avalanche dataset
        - ``number_of_samples_in_one_line`` -- **integer**; how many testing data should be generated in one line should be
          passed to the statistical test tool
        - ``number_of_lines`` -- **integer**; how many lines should be passed to the statistical test tool
        - ``number_of_blocks_in_one_sample`` -- **integer** (default: ``8128); how many blocks should be generated in
          one test sequence
        - ``round_start`` -- **integer** (default: `0`); the round that the statistical test starts (includes, index
          starts from 0)
        - ``round_end`` --  **integer** (default: `0`); the round that the statistical test ends (excludes, index starts
          from 0), if set to 0, means run to the last round
        - ``dieharder_report_folder_prefix`` -- **string** (default: `dieharder_statistics_report`); the folder to save
          the generated statistics report from NIST STS
        - ``FLAG_CHART`` -- **boolean** (default: `False`); draw the chart from dieharder statistical test if set to
          True

        OUTPUT:

        - ``dieharder_report_dicts`` -- Dictionary-structure result parsed from dieharder statistical report. One could
          also see the corresponding report generated under the folder dieharder_statistics_report folder

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.statistical_tests.dieharder_statistical_tests import DieharderTests
            sage: F = DieharderTests(SpeckBlockCipher(number_of_rounds=3)) # doctest: +SKIP
            sage: result = F.run_correlation_dieharder_statistics_test(0, 5, 5, round_end=1) # long time # doctest: +SKIP
            ...
            Dieharder Tests Finished!!!
            ...
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
        self.folder_prefix = dieharder_report_folder_prefix

        self._create_report_folder()

        dataset_generate_time = time.time()
        dataset = self.data_generator.generate_correlation_dataset(input_index=self.input_index,
                                                                   number_of_samples=self.number_of_samples,
                                                                   number_of_blocks_in_one_sample=self.number_of_blocks_in_one_sample)
        dataset_generate_time = time.time() - dataset_generate_time
        if not dataset:
            return
        self._write_execution_time(f'Compute {self.dataset_type.value}', dataset_generate_time)

        return self._generate_dieharder_dicts(dataset, round_start, round_end, FLAG_CHART)

    def run_CBC_dieharder_statistics_test(self, input_index, number_of_samples_in_one_line, number_of_lines,
                                          number_of_blocks_in_one_sample=8192, round_start=0, round_end=0,
                                          dieharder_report_folder_prefix="dieharder_statistics_report",
                                          FLAG_CHART=False):
        r"""
        Run the CBC test.

        INPUT:

        - ``input_index`` -- **integer**; the index of inputs to generate testing data. For example, inputs=[key, plaintext],
          input_index=0 means it will generate the key avalanche dataset. if input_index=1 means it will generate the
          plaintext avalanche dataset
        - ``number_of_samples_in_one_line`` -- **integer**; how many testing data should be generated in one line should be
          passed to the statistical test tool.
        - ``number_of_lines`` -- **integer**; how many lines should be passed to the statistical test tool
        - ``number_of_blocks_in_one_sample`` -- **integer** (default: `8192`); how many blocks should be generated in
          one test sequence
        - ``round_start`` -- **integer** (default: `0`); the round that the statistical test starts (includes, index
          starts from 0)
        - ``round_end`` -- **integer** (default: `0`); the round that the statistical test ends (excludes, index starts
          from 0), if set to 0, means run to the last round
        - ``dieharder_report_folder_prefix`` -- **string** (default: `dieharder_statistics_report`); the folder to save
          the generated statistics report from NIST STS
        - ``FLAG_CHART`` -- **boolean** (default: `False`); draw the chart from dieharder statistical test if set to
          True

        OUTPUT:

        - ``dieharder_report_dicts`` -- Dictionary-structure result parsed from dieharder statistical report. One could
          also see the corresponding report generated under the folder dieharder_statistics_report folder

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.statistical_tests.dieharder_statistical_tests import DieharderTests
            sage: F = DieharderTests(SpeckBlockCipher(number_of_rounds=3)) # doctest: +SKIP
            sage: result = F.run_CBC_dieharder_statistics_test(0, 5, 5, round_end=1) # long time # doctest: +SKIP
            ...
            Dieharder Tests Finished!!!
            ...
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
        self.folder_prefix = dieharder_report_folder_prefix

        self._create_report_folder()

        dataset_generate_time = time.time()
        dataset = self.data_generator.generate_cbc_dataset(input_index=input_index,
                                                           number_of_samples=self.number_of_samples,
                                                           number_of_blocks_in_one_sample=self.number_of_blocks_in_one_sample)

        dataset_generate_time = time.time() - dataset_generate_time
        if not dataset:
            return
        self._write_execution_time(f'Compute {self.dataset_type.value}', dataset_generate_time)

        return self._generate_dieharder_dicts(dataset, round_start, round_end, FLAG_CHART)

    def run_random_dieharder_statistics_test(self, input_index, number_of_samples_in_one_line, number_of_lines,
                                             number_of_blocks_in_one_sample=8128, round_start=0, round_end=0,
                                             dieharder_report_folder_prefix="dieharder_statistics_report",
                                             FLAG_CHART=False):
        r"""
        Run the random test.

        INPUT:

        - ``input_index`` -- **integer**; the index of inputs to generate testing data. For example, inputs=[key, plaintext],
          input_index=0 means it will generate the key avalanche dataset. if input_index=1 means it will generate the
          plaintext avalanche dataset
        - ``number_of_samples_in_one_line`` -- **integer**; how many testing data should be generated in one line should be
          passed to the statistical test tool
        - ``number_of_lines`` -- **integer**; how many lines should be passed to the statistical test tool
        - ``number_of_blocks_in_one_sample`` -- how many blocks should be generated in one test sequence
        - ``round_start`` -- **integer** (default: `0`); the round that the statistical test starts (includes, index
          starts from 0)
        - ``round_end`` -- **integer** (default: `0`); the round that the statistical test ends (excludes, index starts
          from 0), if set to 0, means run to the last round
        - ``dieharder_report_folder_prefix`` -- **string** (default: `dieharder_statistics_report`); the folder to save
          the generated statistics report from NIST STS
        - ``FLAG_CHART`` -- **boolean** (default: `False`); draw the chart from dieharder statistical test if set to
          True

        OUTPUT:

        - ``dieharder_report_dicts`` -- Dictionary-structure result parsed from dieharder statistical report. One could
          also see the corresponding report generated under the folder dieharder_statistics_report folder

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.statistical_tests.dieharder_statistical_tests import DieharderTests
            sage: F = DieharderTests(SpeckBlockCipher(number_of_rounds=3)) # doctest: +SKIP
            sage: result = F.run_random_dieharder_statistics_test(0, 5, 5, round_end=1) # long time # doctest: +SKIP
            ...
            Dieharder Tests Finished!!!
            ...
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
        self.folder_prefix = dieharder_report_folder_prefix

        self._create_report_folder()

        dataset_generate_time = time.time()
        dataset = self.data_generator.generate_random_dataset(input_index=input_index,
                                                              number_of_samples=self.number_of_samples,
                                                              number_of_blocks_in_one_sample=self.number_of_blocks_in_one_sample)
        dataset_generate_time = time.time() - dataset_generate_time
        if not dataset:
            return
        self._write_execution_time(f'Compute {self.dataset_type.value}', dataset_generate_time)

        return self._generate_dieharder_dicts(dataset, round_start, round_end, FLAG_CHART)

    def run_low_density_dieharder_statistics_test(self, input_index, number_of_samples_in_one_line, number_of_lines,
                                                  ratio=1, round_start=0, round_end=0,
                                                  dieharder_report_folder_prefix="dieharder_statistics_report",
                                                  FLAG_CHART=False):
        r"""
        Run the low density test.

        INPUT:

        - ``input_index`` -- **integer**; the index of inputs to generate testing data. For example, inputs=[key, plaintext],
          input_index=0 means it will generate the key avalanche dataset. if input_index=1 means it will generate the
          plaintext avalanche dataset
        - ``number_of_samples_in_one_line`` -- **integer**; how many testing data should be generated in one line should be
            passed to the statistical test tool
        - ``number_of_lines`` -- **integer**; how many lines should be passed to the statistical test tool
        - ``ratio`` -- **number** (default: `1`); the ratio of weight 2 (that is, two 1 in the input) as low density
          inputs, range in [0, 1]. For example, if ratio = 0.5, means half of the weight 2 low density inputs will be
          taken as inputs
        - ``round_start`` -- **integer** (default: `0`); the round that the statistical test starts (includes, index
          starts from 0)
        - ``round_end`` -- **integer** (default: `0`); the round that the statistical test ends (excludes, index starts
          from 0), if set to 0, means run to the last round
        - ``dieharder_report_folder_prefix`` -- **string** (default: `dieharder_statistics_report`); the folder to save
          the generated statistics report from NIST STS
        - ``FLAG_CHART`` -- **boolean** (default: `False`); draw the chart from dieharder statistical test if set to
          True

        OUTPUT:

        - ``dieharder_report_dicts`` -- Dictionary-structure result parsed from dieharder statistical report. One could
          also see the corresponding report generated under the folder dieharder_statistics_report folder

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.statistical_tests.dieharder_statistical_tests import DieharderTests
            sage: F = DieharderTests(SpeckBlockCipher(number_of_rounds=3)) # doctest: +SKIP
            sage: result = F.run_low_density_dieharder_statistics_test(0, 5, 5, round_end=1) # long time # doctest: +SKIP
            ...
            Dieharder Tests Finished!!!
            ...
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
        self.folder_prefix = dieharder_report_folder_prefix

        self._create_report_folder()

        dataset_generate_time = time.time()
        dataset = self.data_generator.generate_low_density_dataset(input_index=input_index,
                                                                   number_of_samples=self.number_of_samples,
                                                                   ratio=ratio)
        dataset_generate_time = time.time() - dataset_generate_time
        if not dataset:
            return
        self._write_execution_time(f'Compute {self.dataset_type.value}', dataset_generate_time)

        return self._generate_dieharder_dicts(dataset, round_start, round_end, FLAG_CHART)

    def run_high_density_dieharder_statistics_test(self, input_index, number_of_samples_in_one_line, number_of_lines,
                                                   ratio=1, round_start=0, round_end=0,
                                                   dieharder_report_folder_prefix="dieharder_statistics_report",
                                                   FLAG_CHART=False):
        r"""
        Run the high density test.

        INPUT:

        - ``input_index`` -- **integer**; the index of inputs to generate testing data. For example,
          inputs=[key, plaintext], input_index=0 means it will generate the key avalanche dataset. if input_index=1
          means it will generate the plaintext avalanche dataset
        - ``number_of_samples_in_one_line`` -- **integer**; how many testing data should be generated in one line should
          be passed to the statistical test tool.
        - ``number_of_lines`` -- **integer**; how many lines should be passed to the statistical test tool
        - ``ratio`` -- the ratio of weight 2 (that is, two 1 in the input) as high density inputs, range in [0, 1].
            For example, if ratio = 0.5, means half of the weight 2 high density inputs will be taken as inputs.
        - ``round_start`` -- **integer** (default: `0`); the round that the statistical test starts
          (includes, index starts from 0)
        - ``round_end`` -- **integer** (default: `0`); the round that the statistical test ends
          (excludes, index starts from 0), if set to 0,
          means run to the last round.
        - ``dieharder_report_folder_prefix`` -- **string** (default: `dieharder_statistics_report`); The folder to save
          the generated statistics report from NIST STS
        - ``FLAG_CHART`` -- **boolean** (default: `False`); draw the chart from dieharder statistical test if set to
          True

        OUTPUT:

        - ``dieharder_report_dicts`` -- Dictionary-structure result parsed from dieharder statistical report. One could
          also see the corresponding report generated under the folder dieharder_statistics_report folder

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.statistical_tests.dieharder_statistical_tests import DieharderTests
            sage: F = DieharderTests(SpeckBlockCipher(number_of_rounds=3)) # doctest: +SKIP
            sage: result = F.run_high_density_dieharder_statistics_test(0, 5, 5, round_end=1) # long time # doctest: +SKIP
            ...
            Dieharder Tests Finished!!!
            ...
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
        self.folder_prefix = dieharder_report_folder_prefix

        self._create_report_folder()

        dataset_generate_time = time.time()
        dataset = self.data_generator.generate_high_density_dataset(input_index=input_index,
                                                                    number_of_samples=self.number_of_samples,
                                                                    ratio=ratio)
        dataset_generate_time = time.time() - dataset_generate_time
        if not dataset:
            return
        self._write_execution_time(f'Compute {self.dataset_type.value}', dataset_generate_time)

        return self._generate_dieharder_dicts(dataset, round_start, round_end, FLAG_CHART)
