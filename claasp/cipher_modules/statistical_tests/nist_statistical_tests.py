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
# # 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# ****************************************************************************


import os
import math
import time
from datetime import timedelta, datetime

import matplotlib.pyplot as plt
import numpy as np

from claasp.cipher_modules.statistical_tests.dataset_generator import DatasetGenerator, DatasetType
from claasp.cipher_modules.statistical_tests.nist_sts import NISTTests


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
    'LinearComplexity': 188,
}


class NISTStatisticalTests:
    """
    Wrapper for running NIST STS tests on cipher-generated datasets.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
        sage: from claasp.cipher_modules.statistical_tests.nist_statistical_tests import NISTStatisticalTests
        sage: cipher = SimonBlockCipher(number_of_rounds=3)
        sage: tester = NISTStatisticalTests(cipher)
        sage: tester.cipher is cipher
        True
    """
    def __init__(self, cipher):
        cipher.sort_cipher()
        self.cipher = cipher
        self.data_generator = DatasetGenerator(cipher)
        str_of_inputs_bit_size = list(map(str, cipher.inputs_bit_size))
        self._cipher_primitive = cipher.id + "_" + "_".join(str_of_inputs_bit_size)

    def nist_statistical_tests(
        self,
        test_type,
        bits_in_one_sequence='default',
        number_of_sequences='default',
        input_index=0,
        round_start=0,
        round_end=0,
        nist_report_folder_prefix="nist_statistics_report",
        statistical_test_option_list=15 * '1',
    ):
        """
        Run NIST STS tests for a dataset generated from the cipher.

        EXAMPLES::

            sage: import numpy as np
            sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
            sage: from claasp.cipher_modules.statistical_tests.nist_statistical_tests import NISTStatisticalTests
            sage: np.random.seed(0)
            sage: cipher = SimonBlockCipher(number_of_rounds=5)
            sage: tester = NISTStatisticalTests(cipher)
            sage: result = tester.nist_statistical_tests(
            ....:     test_type='avalanche',
            ....:     bits_in_one_sequence=1024,
            ....:     number_of_sequences=2,
            ....:     round_start=0,
            ....:     round_end=5,
            ....:     statistical_test_option_list='100000000000000',
            ....: )
            sage: sorted(result.keys())
            ['input_parameters', 'test_results']
            sage: freq_round0 = result['test_results'][0]['randomness_test'][0]
            sage: freq_round0['test_name']
            'Frequency'
            sage: round(freq_round0['p-value'], 16)
            0.0351735394669848
        """
        time_date = 'date:' + 'time:'.join(str(datetime.now()).split(' '))
        nist_test = {
            'input_parameters': {
                'test_name': 'nist_statistical_tests',
                'cipher': self.cipher,
                'test_type': test_type,
                'round_start': round_start,
                'round_end': round_end,
                'input': self.cipher.inputs[input_index],
            },
            'test_results': None,
        }

        dataset_generate_time = time.time()
        self.folder_prefix = os.getcwd() + '/test_reports/' + nist_report_folder_prefix

        if round_end == 0:
            round_end = self.cipher.number_of_rounds

        dataset = None
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
            self._create_report_folder(time_date, statistical_test_option_list)

            dataset = self.data_generator.generate_avalanche_dataset(
                input_index=self.input_index,
                number_of_samples=self.number_of_samples,
            )

        elif test_type == 'correlation':
            self.dataset_type = DatasetType.correlation
            self.input_index = input_index
            if bits_in_one_sequence == 'default':
                bits_in_one_sequence = 1048576
            if number_of_sequences == 'default':
                number_of_sequences = 128

            number_of_blocks_in_one_sample = math.ceil(bits_in_one_sequence / self.cipher.output_bit_size)
            self.number_of_sequences = number_of_sequences
            self.number_of_samples = self.number_of_sequences + 1
            self.bits_in_one_sequence = number_of_blocks_in_one_sample * self.cipher.output_bit_size
            self._create_report_folder(time_date, statistical_test_option_list)

            dataset = self.data_generator.generate_correlation_dataset(
                input_index=self.input_index,
                number_of_samples=self.number_of_samples,
                number_of_blocks_in_one_sample=number_of_blocks_in_one_sample,
            )

        elif test_type == 'cbc':
            self.dataset_type = DatasetType.cbc
            self.input_index = input_index
            if bits_in_one_sequence == 'default':
                bits_in_one_sequence = 1048576
            if number_of_sequences == 'default':
                number_of_sequences = 300

            number_of_blocks_in_one_sample = math.ceil(bits_in_one_sequence / self.cipher.output_bit_size)
            self.number_of_sequences = number_of_sequences
            self.number_of_samples = self.number_of_sequences + 1
            self.bits_in_one_sequence = number_of_blocks_in_one_sample * self.cipher.output_bit_size
            self._create_report_folder(time_date, statistical_test_option_list)

            dataset = self.data_generator.generate_cbc_dataset(
                input_index=self.input_index,
                number_of_samples=self.number_of_samples,
                number_of_blocks_in_one_sample=number_of_blocks_in_one_sample,
            )

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
            self._create_report_folder(time_date, statistical_test_option_list)

            dataset = self.data_generator.generate_random_dataset(
                input_index=self.input_index,
                number_of_samples=self.number_of_samples,
                number_of_blocks_in_one_sample=self.number_of_blocks_in_one_sample,
            )

        elif test_type == 'low_density':
            self.dataset_type = DatasetType.low_density
            self.input_index = input_index
            if bits_in_one_sequence == 'default':
                bits_in_one_sequence = 1056896
            if number_of_sequences == 'default':
                number_of_sequences = 128

            number_of_blocks_in_one_sample = math.ceil(bits_in_one_sequence / self.cipher.output_bit_size)
            self.number_of_sequences = number_of_sequences
            self.number_of_samples = self.number_of_sequences + 1
            n = self.cipher.inputs_bit_size[self.input_index]
            ratio = min(1, (number_of_blocks_in_one_sample - 1 - n) / math.comb(n, 2))
            self.number_of_blocks_in_one_sample = int(1 + n + math.ceil(math.comb(n, 2) * ratio))
            self.bits_in_one_sequence = self.number_of_blocks_in_one_sample * self.cipher.output_bit_size
            self._create_report_folder(time_date, statistical_test_option_list)

            dataset = self.data_generator.generate_low_density_dataset(
                input_index=self.input_index,
                number_of_samples=self.number_of_samples,
                ratio=ratio,
            )

        elif test_type == 'high_density':
            self.dataset_type = DatasetType.high_density
            self.input_index = input_index
            if bits_in_one_sequence == 'default':
                bits_in_one_sequence = 1056896
            if number_of_sequences == 'default':
                number_of_sequences = 128

            number_of_blocks_in_one_sample = math.ceil(bits_in_one_sequence / self.cipher.output_bit_size)
            self.number_of_sequences = number_of_sequences
            self.number_of_samples = self.number_of_sequences + 1
            n = self.cipher.inputs_bit_size[self.input_index]
            ratio = min(1, (number_of_blocks_in_one_sample - 1 - n) / math.comb(n, 2))
            self.number_of_blocks_in_one_sample = int(1 + n + math.ceil(math.comb(n, 2) * ratio))
            self.bits_in_one_sequence = self.number_of_blocks_in_one_sample * self.cipher.output_bit_size
            self._create_report_folder(time_date, statistical_test_option_list)

            dataset = self.data_generator.generate_high_density_dataset(
                input_index=self.input_index,
                number_of_samples=self.number_of_samples,
                ratio=ratio,
            )
        else:
            print(
                'Invalid test_type choice. Choose among the following: avalanche, correlation, cbc, random, low_density, high_density'
            )
            return

        dataset_generate_time = time.time() - dataset_generate_time
        if not dataset:
            return
        self._write_execution_time(f'Compute {self.dataset_type.value}', dataset_generate_time)

        nist_test['test_results'] = self._generate_nist_dicts(
            time_date=time_date,
            dataset=dataset,
            round_start=round_start,
            round_end=round_end,
            statistical_test_option_list=statistical_test_option_list,
        )
        nist_test['input_parameters']['bits_in_one_sequence'] = bits_in_one_sequence
        nist_test['input_parameters']['number_of_sequences'] = number_of_sequences

        return nist_test

    @staticmethod
    def _normalize_test_option_list(statistical_test_option_list):
        if statistical_test_option_list is None:
            return 15 * '1'
        option = str(statistical_test_option_list)
        if len(option) < 15:
            option = option.ljust(15, '0')
        return option[:15]

    @staticmethod
    def _test_name_map():
        return [
            'frequency',
            'block_frequency',
            'cumulative_sums',
            'runs',
            'longest_run',
            'rank',
            'dft',
            'non_overlapping_template',
            'overlapping_template',
            'universal',
            'approximate_entropy',
            'random_excursions',
            'random_excursions_variant',
            'serial',
            'linear_complexity',
        ]

    @staticmethod
    def _format_test_name(raw_name):
        if raw_name.startswith('random_excursions_variant_'):
            return 'RandomExcursionsVariant'
        if raw_name.startswith('random_excursions_'):
            return 'RandomExcursions'
        if raw_name.startswith('cumulative_sums_'):
            return 'CumulativeSums'
        if raw_name.startswith('serial_'):
            return 'Serial'
        if raw_name.startswith('non_overlapping_template_'):
            return 'NonOverlappingTemplate'

        mapping = {
            'frequency': 'Frequency',
            'block_frequency': 'BlockFrequency',
            'cumulative_sums': 'CumulativeSums',
            'runs': 'Runs',
            'longest_run': 'LongestRun',
            'rank': 'Rank',
            'dft': 'FFT',
            'non_overlapping_template': 'NonOverlappingTemplate',
            'overlapping_template': 'OverlappingTemplate',
            'universal': 'Universal',
            'approximate_entropy': 'ApproximateEntropy',
            'random_excursions': 'RandomExcursions',
            'random_excursions_variant': 'RandomExcursionsVariant',
            'serial': 'Serial',
            'linear_complexity': 'LinearComplexity',
        }
        return mapping.get(raw_name, raw_name)

    @staticmethod
    def _build_report_from_results(results):
        test_list = []
        counts_by_base = {}
        for test in results.get('tests', []):
            raw_name = test.get('test_name', '')
            base_name = NISTStatisticalTests._format_test_name(raw_name)
            counts_by_base.setdefault(base_name, 0)
            test_id = TEST_ID_TABLE.get(base_name, 0) + counts_by_base[base_name]
            counts_by_base[base_name] += 1

            test_dict = {
                'test_id': test_id,
                'test_name': base_name,
                'passed': bool(test.get('passed', False)),
                'p-value': float(test.get('uniformity_p_value', 0.0)) if test.get('uniformity_p_value') is not None else 0.0,
                'passed_seqs': int(test.get('passed_sequences', 0)),
                'total_seqs': int(test.get('total_sequences', 0)),
                'passed_proportion': float(test.get('proportion', 0.0)),
            }
            for i in range(10):
                test_dict[f'C{i+1}'] = '0'
            test_list.append(test_dict)

        passed_tests = sum(1 for test in test_list if test['passed'])

        n = results.get('num_sequences', 0) or 0
        alpha = results.get('alpha', 0.01)
        thresholds = []
        if n > 0:
            p_hat = 1.0 - alpha
            threshold = int((p_hat - 3.0 * math.sqrt((p_hat * alpha) / n)) * n)
            thresholds.append({'total': n, 'passed': threshold})

        re_sample = None
        for test in results.get('tests', []):
            if 'random_excursions' in test.get('test_name', '') and test.get('total_sequences', 0) > 0:
                re_sample = int(test.get('total_sequences', 0))
                break
        if re_sample:
            p_hat = 1.0 - alpha
            threshold = int((p_hat - 3.0 * math.sqrt((p_hat * alpha) / re_sample)) * re_sample)
            thresholds.append({'total': re_sample, 'passed': threshold})

        return {
            'passed_tests': passed_tests,
            'number_of_sequences_threshold': thresholds,
            'randomness_test': test_list,
        }

    @staticmethod
    def _run_nist_statistical_tests_tool(
        input_file,
        bit_stream_length=10000,
        number_of_bit_streams=10,
        input_file_format=1,
        statistical_test_option_list=15 * '1',
    ):
        option = NISTStatisticalTests._normalize_test_option_list(statistical_test_option_list)
        test_names = [name for flag, name in zip(option, NISTStatisticalTests._test_name_map()) if flag == '1']

        if input_file_format == 0:
            binary = np.array(input_file, dtype=np.uint8).flatten()
            total_bits = bit_stream_length * number_of_bit_streams
            if len(binary) < total_bits:
                raise ValueError("Insufficient data")
            binary = binary[:total_bits]
            sequences = [
                binary[i * bit_stream_length:(i + 1) * bit_stream_length]
                for i in range(number_of_bit_streams)
            ]
        else:
            byte_data = input_file
            if isinstance(byte_data, np.ndarray):
                byte_data = byte_data.astype(np.uint8).tobytes()
            elif isinstance(byte_data, (list, tuple)):
                byte_data = bytes(byte_data)

            total_bits = bit_stream_length * number_of_bit_streams
            bits = np.unpackbits(np.frombuffer(byte_data, dtype=np.uint8))
            if len(bits) < total_bits:
                raise ValueError("Insufficient data")
            bits = bits[:total_bits]
            sequences = [
                bits[i * bit_stream_length:(i + 1) * bit_stream_length]
                for i in range(number_of_bit_streams)
            ]

        results = NISTTests.run_all_tests(sequences, test_names=test_names)
        return NISTStatisticalTests._build_report_from_results(results)

    @staticmethod
    def _convert_to_binary_array(data):
        if isinstance(data, np.ndarray):
            return data.astype(np.uint8)
        if isinstance(data, (bytes, bytearray)):
            return np.unpackbits(np.frombuffer(data, dtype=np.uint8))
        if isinstance(data, list):
            return np.array(data, dtype=np.uint8)
        raise ValueError("Unsupported input type for binary conversion")

    @staticmethod
    def _format_test_result(test_name, result, test_id, total_seqs):
        formatted = {
            'test_id': test_id,
            'test_name': test_name,
            'passed': result.get('passed', False),
        }
        if 'p_value' in result:
            formatted['p-value'] = result['p_value']
        elif 'p_value1' in result:
            formatted['p-value'] = result['p_value1']
        elif 'p_values' in result:
            formatted['p-value'] = float(np.mean(result['p_values']))
        else:
            formatted['p-value'] = 0.0

        formatted['passed_seqs'] = 1 if result.get('passed', False) else 0
        formatted['total_seqs'] = 1
        formatted['passed_proportion'] = 1.0 if result.get('passed', False) else 0.0
        for i in range(10):
            formatted[f'C{i+1}'] = '0'
        return formatted

    @staticmethod
    def _run_cumsum_both_modes(binary_data):
        return [
            NISTTests.cumulative_sums_test(binary_data, mode=0),
            NISTTests.cumulative_sums_test(binary_data, mode=1),
        ]

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

    def _create_report_folder(self, time_date, statistical_test_option_list):
        self.report_folder = os.path.join(
            self.folder_prefix,
            f'{self._cipher_primitive}_{self.dataset_type.name}_index{self.input_index}_{self.number_of_sequences}lines_{self.bits_in_one_sequence}bits_{statistical_test_option_list}test_option_list_{time_date}time',
        )
        try:
            os.makedirs(self.report_folder)
        except OSError:
            pass

    def _write_execution_time(self, execution_description, execution_time):
        try:
            with open(os.path.join(self.report_folder, 'execution_time.txt'), 'a') as f_out:
                f_out.write(f'{execution_description}: {timedelta(seconds=execution_time)}\n')
        except Exception as e:
            print(f'Error: {e.strerror}')

    def _generate_nist_dicts(self, time_date, dataset, round_start, round_end, statistical_test_option_list=15 * '1'):
        sts_report_dicts = []

        for round_number in range(round_start, round_end):
            raw_data = dataset[round_number]
            sts_execution_time = time.time()
            sts_report_dict = self._run_nist_statistical_tests_tool(
                raw_data,
                self.bits_in_one_sequence,
                self.number_of_sequences,
                1,
                statistical_test_option_list=statistical_test_option_list,
            )
            sts_execution_time = time.time() - sts_execution_time
            self._write_execution_time(f'Compute round {round_number}', sts_execution_time)

            sts_report_dict['data_type'] = f'{self.cipher.inputs[self.input_index]}_{self.dataset_type.value}'
            sts_report_dict['cipher_name'] = f'{self.cipher.id}'
            sts_report_dict['round'] = round_number
            sts_report_dict['rounds'] = self.cipher.number_of_rounds
            sts_report_dicts.append(sts_report_dict)

        return sts_report_dicts

    def _generate_chart_for_all_rounds(self, flag_chart, sts_report_dicts):
        if flag_chart:
            try:
                self._generate_chart_all(sts_report_dicts, self.report_folder)
            except OSError:
                print('Error in generating all round chart.')
