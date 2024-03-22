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


class DieharderTests:
    _DIEHARDER_OUTPUT = "dieharder_test_output.txt"

    def __init__(self, cipher):
        cipher.sort_cipher()
        self.cipher = cipher
        self.data_generator = DatasetGenerator(cipher)
        str_of_inputs_bit_size = list(map(str, cipher.inputs_bit_size))
        self._cipher_primitive = cipher.id + "_" + "_".join(str_of_inputs_bit_size)

    def dieharder_statistical_tests(self, test_type,
                                    bits_in_one_sequence_dieharder='default',
                                    number_of_sequences_dieharder='default',
                                    input_index=0,
                                    round_start=0,
                                    round_end=0,
                                    dieharder_report_folder_prefix="dieharder_statistics_report",
                                    dieharder_test_option=None
                                    ):

        """

        Run the Dieharder statistical tests.

        INPUT:

            - ``test_type`` -- string describing which test to run
            - ``bits_in_one_sequence_dieharder`` -- integer parameter used to run the dieharder tests
            - ``number_of_sequences_dieharder`` -- integer parameter used to run the dieharder tests
            - ``input_index`` -- cipher input index
            - ``round_start`` -- first round to be considered in the cipher
            - ``round_end`` -- last round to be considered in the cipher
            - ``dieharder_report_folder_prefix`` - prefix for the unparsed dieharder tests output folder

        OUTPUT:

            - The results are going to be saved in a dictionary format compatible with the Report class

        EXAMPLE:

            from claasp.cipher_modules.statistical_tests.dieharder_statistical_tests import DieharderTests
            from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            speck = SpeckBlockCipher(number_of_rounds=5)
            dieharder_tests = DieharderTests(speck)
            dieharder_avalanche_test_results = dieharder_tests.dieharder_statistical_tests('avalanche')

        """

        dieharder_test = {

            'input_parameters': {
                'test_name': 'dieharder_statistical_tests',
                'cipher': self.cipher,
                'test_type': test_type,
                'round_start': round_start,
                'round_end': round_end,
                'input': self.cipher.inputs[input_index]
            },
            'test_results': None
        }

        dataset_generate_time = time.time()
        self.folder_prefix = os.getcwd() + '/test_reports/' + dieharder_report_folder_prefix

        if round_end == 0:
            round_end = self.cipher.number_of_rounds

        if test_type == 'avalanche':

            self.dataset_type_dieharder = DatasetType.avalanche
            self.input_index = input_index

            if bits_in_one_sequence_dieharder == 'default':
                bits_in_one_sequence_dieharder = 1048576
            if number_of_sequences_dieharder == 'default':
                number_of_sequences_dieharder = 384

            sample_size = self.cipher.inputs_bit_size[input_index] * self.cipher.output_bit_size
            number_of_samples_dieharder = math.ceil(bits_in_one_sequence_dieharder / sample_size)
            self.number_of_sequences_dieharder = number_of_sequences_dieharder
            self.number_of_samples_dieharder = number_of_samples_dieharder
            self.number_of_samples_dieharder = self.number_of_samples_dieharder * (
                        self.number_of_sequences_dieharder + 1)
            self.bits_in_one_sequence_dieharder = sample_size * self.number_of_samples_dieharder

            self._create_report_folder()
            dataset = self.data_generator.generate_avalanche_dataset(input_index=self.input_index,
                                                                     number_of_samples=self.number_of_samples_dieharder)

        elif test_type == 'correlation':

            self.dataset_type_dieharder = DatasetType.correlation
            self.input_index = input_index

            if bits_in_one_sequence_dieharder == 'default':
                bits_in_one_sequence_dieharder = 1048576
            if number_of_sequences_dieharder == 'default':
                number_of_sequences_dieharder = 384

            number_of_blocks_in_one_sample_dieharder = math.ceil(
                bits_in_one_sequence_dieharder / self.cipher.output_bit_size)
            self.number_of_sequences_dieharder = number_of_sequences_dieharder
            self.number_of_samples_dieharder = self.number_of_sequences_dieharder + 1
            self.bits_in_one_sequence_dieharder = number_of_blocks_in_one_sample_dieharder * self.cipher.output_bit_size

            self._create_report_folder()

            dataset = self.data_generator.generate_correlation_dataset(input_index=self.input_index,
                                                                       number_of_samples=self.number_of_samples_dieharder,
                                                                       number_of_blocks_in_one_sample=number_of_blocks_in_one_sample_dieharder)

        elif test_type == 'cbc':

            self.dataset_type_dieharder = DatasetType.cbc
            self.input_index = input_index
            if bits_in_one_sequence_dieharder == 'default':
                bits_in_one_sequence_dieharder = 1048576
            if number_of_sequences_dieharder == 'default':
                number_of_sequences_dieharder = 384

            number_of_blocks_in_one_sample_dieharder = math.ceil(
                bits_in_one_sequence_dieharder / self.cipher.output_bit_size)
            self.number_of_sequences_dieharder = number_of_sequences_dieharder
            self.number_of_samples_dieharder = self.number_of_sequences_dieharder + 1
            self.bits_in_one_sequence_dieharder = number_of_blocks_in_one_sample_dieharder * self.cipher.output_bit_size

            self._create_report_folder()

            dataset = self.data_generator.generate_cbc_dataset(input_index=self.input_index,
                                                               number_of_samples=self.number_of_samples_dieharder,
                                                               number_of_blocks_in_one_sample=number_of_blocks_in_one_sample_dieharder)

        elif test_type == 'random':
            self.dataset_type_dieharder = DatasetType.random
            self.input_index = input_index
            if bits_in_one_sequence_dieharder == 'default':
                bits_in_one_sequence_dieharder = 1040384
            if number_of_sequences_dieharder == 'default':
                number_of_sequences_dieharder = 128

            number_of_blocks_in_one_sample_dieharder = math.ceil(
                bits_in_one_sequence_dieharder / self.cipher.output_bit_size)
            self.number_of_sequences_dieharder = number_of_sequences_dieharder
            self.number_of_samples_dieharder = self.number_of_sequences_dieharder + 1
            self.bits_in_one_sequence_dieharder = number_of_blocks_in_one_sample_dieharder * self.cipher.output_bit_size

            self._create_report_folder()

            dataset = self.data_generator.generate_random_dataset(input_index=self.input_index,
                                                                  number_of_samples=self.number_of_samples_dieharder,
                                                                  number_of_blocks_in_one_sample=number_of_blocks_in_one_sample_dieharder)

        elif 'density' in test_type:
            self.dataset_type_dieharder = DatasetType.low_density
            self.input_index = input_index
            if bits_in_one_sequence_dieharder == 'default':
                bits_in_one_sequence_dieharder = 1056896
            if number_of_sequences_dieharder == 'default':
                number_of_sequences_dieharder = 1

            number_of_blocks_in_one_sample_dieharder = math.ceil(
                bits_in_one_sequence_dieharder / self.cipher.output_bit_size)
            self.number_of_sequences_dieharder = number_of_sequences_dieharder
            self.number_of_samples_dieharder = self.number_of_sequences_dieharder + 1
            n = self.cipher.inputs_bit_size[self.input_index]
            ratio = min(1, (number_of_blocks_in_one_sample_dieharder - 1 - n) / math.comb(n, 2))
            self.number_of_blocks_in_one_sample_dieharder = int(1 + n + math.ceil(math.comb(n, 2) * ratio))
            self.bits_in_one_sequence_dieharder = self.number_of_blocks_in_one_sample_dieharder * self.cipher.output_bit_size

            self._create_report_folder()

            if test_type == 'low_density':
                dataset = self.data_generator.generate_low_density_dataset(input_index=self.input_index,
                                                                       number_of_samples=self.number_of_samples_dieharder,
                                                                       ratio=ratio)
            elif test_type == 'high_density':
                dataset = self.data_generator.generate_high_density_dataset(input_index=self.input_index,
                                                                        number_of_samples=self.number_of_samples_dieharder,
                                                                        ratio=ratio)
        else:
            # maybe print the enum value of Dataset.type
            print(
                'Invalid test_type choice. Choose among the following: avalanche, correlation, cbc, random, '
                'low_density, high_density')
            return

        dataset_generate_time = time.time() - dataset_generate_time
        if not dataset:
            return
        self._write_execution_time(f'Compute {self.dataset_type_dieharder.value}', dataset_generate_time)
        dieharder_test['test_results'] = self._generate_dieharder_dicts(dataset, round_start, round_end,
                                                                        FLAG_CHART=False,
                                                                        dieharder_test_option=dieharder_test_option)
        dieharder_test['input_parameters']['bits_in_one_sequence_dieharder'] = bits_in_one_sequence_dieharder
        dieharder_test['input_parameters']['number_of_sequences_dieharder'] = number_of_sequences_dieharder

        return dieharder_test

    @staticmethod
    def _run_dieharder_statistical_tests_tool(input_file, dieharder_test_option):
        """
        Run dieharder tests using the Dieharder library [1]. The result will be in dieharder_test_output.txt.

        [1] https://webhome.phy.duke.edu/~rgb/General/dieharder.php

        INPUT:

        - ``input_file`` -- file containing the bit streams

        OUTPUT:

        - the result would be saved as ``dieharder_test_output.txt``

        EXAMPLES::

            sage: from claasp.cipher_modules.statistical_tests.dieharder_statistical_tests import DieharderTests
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.statistical_tests.dataset_generator import DatasetGenerator
            sage: dataset_generator = DatasetGenerator(SpeckBlockCipher(number_of_rounds=3))
            sage: dataset = dataset_generator.generate_random_dataset(input_index=0, number_of_samples=100, number_of_blocks_in_one_sample=30000)
            sage: dataset[0].tofile(f'claasp/cipher_modules/statistical_tests/input_data_example')
            sage: result = DieharderTests.run_dieharder_statistical_tests_tool( # doctest: +SKIP
            ....:     f'claasp/cipher_modules/statistical_tests/input_data_example', # doctest: +SKIP
            ....: ) # long time # doctest: +SKIP
            ...
            Dieharder Tests Finished!!!
        """
        print("Dieharder Tests Started...")
        if dieharder_test_option is None:
            os.system(f'dieharder -g 201 -f {input_file} -a > {__class__._DIEHARDER_OUTPUT}')
        else:
            os.system(f'dieharder -g 201 -f {input_file} -d {dieharder_test_option} > {__class__._DIEHARDER_OUTPUT}')
        print(f'Dieharder Tests Finished!!!')

    @staticmethod
    def _parse_report(report_filename):
        """
        Parse the dieharder statistical tests report. It will return the parsed result in a dictionary format.

        INPUT:

        - ``report_filename`` -- the filename of the report you need to parse

        OUTPUT:

        - ``report_dict`` -- return the parsed result in a dictionary format

        EXAMPLES::

            sage: from claasp.cipher_modules.statistical_tests.dieharder_statistical_tests import DieharderTests
            sage: result = DieharderTests.run_dieharder_statistical_tests_tool( # doctest: +SKIP
            ....:     f'claasp/cipher_modules/statistical_tests/input_data_example', # doctest: +SKIP
            ....: ) # long time # doctest: +SKIP
            ...
            Dieharder Tests Finished!!!

            sage: dict = DieharderTests._parse_report(f'dieharder_test_output.txt') # doctest: +SKIP
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
        f.close()
        print(f'Parsing {report_filename} is finished.')
        return report_dict

    @staticmethod
    def _generate_chart_round(report_dict, output_dir='', show_graph=False):
        """
        Generate the corresponding chart based on the parsed report dictionary.

        INPUT:

        - ``report_dict`` -- the parsed result in a dictionary format

        OUTPUT:

        - save the chart with filename
          f'dieharder_{report_dict["data_type"]}_{report_dict["cipher_name"]}_round_{report_dict["round"]}.png'

        """
        print(f'Drawing round {report_dict["round"]} is in progress')
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
        if len(report_dict['randomness_test'])==1:
            plt.title(
            f'{report_dict["cipher_name"]}: {report_dict["data_type"]}, Round {report_dict["round"]}|{report_dict["rounds"]}|{report_dict["randomness_test"][0]["test_name"]}')
        else:
            plt.title(
                f'{report_dict["cipher_name"]}: {report_dict["data_type"]}, Round {report_dict["round"]}|{report_dict["rounds"]}')
        plt.xlabel('Tests')
        plt.yticks([-1, 0, 1], ['FAILED', 'WEAK', 'PASSED'])

        if show_graph == False:
            if output_dir == '':
                output_dir = f'dieharder_{report_dict["data_type"]}_{report_dict["cipher_name"]}_round_{report_dict["round"]}.png'
                plt.savefig(output_dir)
            else:
                plt.savefig(
                    output_dir + '/' + f'dieharder_{report_dict["data_type"]}_{report_dict["cipher_name"]}_round_{report_dict["round"]}.png')
        else:
            plt.show()
            plt.clf()
            plt.close()
        print(f'Drawing round {report_dict["round"]} is finished')

    @staticmethod
    def _generate_chart_all(report_dict_list, output_dir='', show_graph=False):
        """
        Generate the corresponding chart based on the parsed report dictionary.

        INPUT:

        - ``report_dict`` -- the parsed result in a dictionary format

        OUTPUT:

        - save the chart with filename
          f'dieharder_{report_dict["data_type"]}_{report_dict["cipher_name"]}_round_{report_dict["round"]}.png'

        """
        print("Drawing chart for all rounds is in progress.")
        x = [i + 1 for i in range(report_dict_list[0]["round"], report_dict_list[-1]["round"]+1)]
        y = [0 for _ in range(len(x))]
        for i in range(len(report_dict_list)):
            y[i] = report_dict_list[i]["passed_tests_proportion"]

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

        if show_graph == False:
            if output_dir == '':
                output_dir = f'dieharder_{report_dict_list[0]["data_type"]}_{report_dict_list[0]["cipher_name"]}.png'
                plt.savefig(output_dir)
            else:
                plt.savefig(
                    output_dir + '/' + f'dieharder_{report_dict_list[0]["data_type"]}_{report_dict_list[0]["cipher_name"]}.png')
        else:
            plt.show()
            plt.clf()
            plt.close()
        print(f'Drawing chart for all rounds is in finished.')

    def _create_report_folder(self):
        time_date = 'date:'+'time:'.join(str(datetime.now()).split(' '))
        self.report_folder = os.path.join(self.folder_prefix,
                                          f'{self._cipher_primitive}_{self.dataset_type_dieharder.name}_index{self.input_index}_{self.number_of_sequences_dieharder}lines_{self.bits_in_one_sequence_dieharder}bits_{time_date}time')
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

    def _generate_dieharder_dicts(self, dataset, round_start, round_end, dieharder_test_option, FLAG_CHART=False):
        dataset_folder = os.getcwd() + 'dieharder_dataset'
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
            self._run_dieharder_statistical_tests_tool(dataset_filename, dieharder_test_option)
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
                dieharder_report_dict = self._parse_report(report_round)
                dieharder_report_dict[
                    'data_type'] = f'{self.cipher.inputs[self.input_index]}_{self.dataset_type_dieharder.value}'
                dieharder_report_dict["cipher_name"] = self.cipher.id
                dieharder_report_dict["round"] = round_number
                dieharder_report_dict["rounds"] = self.cipher.number_of_rounds
                dieharder_report_dicts.append(dieharder_report_dict)
                # generate round chart
                if FLAG_CHART:
                    self._generate_chart_round(dieharder_report_dict)
            except OSError:
                print(f'Error in parsing report for round {round_number}.')

        # generate chart for all rounds
        if FLAG_CHART:
            try:
                self._generate_chart_all(dieharder_report_dicts)
            except OSError:
                print(f'Error in generating all round chart.')

        return dieharder_report_dicts
