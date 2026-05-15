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


import math
import time
from datetime import datetime

import numpy as np

from claasp.cipher_modules.statistical_tests.dataset_generator import DatasetGenerator, DatasetType
from claasp.cipher_modules.statistical_tests.nist_sts import NISTTests

# NIST STS final report IDs; used to label rows and offset template variants.
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
    Run NIST STS-style tests on cipher-generated datasets and return structured JSON.

    INPUT:

    - ``cipher`` -- **cipher**; cipher instance used to generate datasets.

    OUTPUT:

    - A dictionary containing ``input_parameters``, ``execution_times``, and ``test_results``.
      Each entry in ``test_results`` is a per-round report with ``randomness_test`` entries
      for each statistical test.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
        sage: from claasp.cipher_modules.statistical_tests.nist_statistical_tests import NISTStatisticalTests
        sage: cipher = SimonBlockCipher(number_of_rounds=3)
        sage: tester = NISTStatisticalTests(cipher)
        sage: tester.cipher is cipher
        True
    """
    def __init__(self, cipher):
        """
        Initialize the tester and its dataset generator.

        INPUT:

        - ``cipher`` -- **cipher**; cipher instance used to generate datasets.
        """
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

        INPUT:

        - ``test_type`` -- **str**; one of ``avalanche``, ``correlation``, ``cbc``,
            ``random``, ``low_density``, ``high_density``.
        - ``bits_in_one_sequence`` -- **int** or ``'default'``; number of bits per sequence.
        - ``number_of_sequences`` -- **int** or ``'default'``; number of sequences.
        - ``input_index`` -- **int**; which cipher input to use.
        - ``round_start`` -- **int**; first round index (inclusive).
        - ``round_end`` -- **int**; last round index (exclusive). ``0`` means all rounds.
        - ``nist_report_folder_prefix`` -- **str**; preserved in ``input_parameters`` for traceability.
        - ``statistical_test_option_list`` -- **str**; 15-bit mask selecting tests.

        OUTPUT:

        - A dictionary with ``input_parameters``, ``execution_times`` and ``test_results``.
            ``execution_times`` includes dataset generation time and per-round execution times.
            ``test_results`` is a list of per-round reports; each report includes
            ``randomness_test`` entries with per-test p-values and pass/fail status.

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
            ['execution_times', 'input_parameters', 'test_results']
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
                'report_folder_prefix': nist_report_folder_prefix,
            },
            'execution_times': {
                'dataset_generation_seconds': 0.0,
                'rounds_seconds': {},
                'total_seconds': 0.0,
            },
            'test_results': None,
        }

        dataset_generate_time = time.time()

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
        nist_test['execution_times']['dataset_generation_seconds'] = dataset_generate_time

        nist_test['test_results'] = self._generate_nist_dicts(
            time_date=time_date,
            dataset=dataset,
            round_start=round_start,
            round_end=round_end,
            statistical_test_option_list=statistical_test_option_list,
            execution_times=nist_test['execution_times'],
        )
        nist_test['input_parameters']['bits_in_one_sequence'] = bits_in_one_sequence
        nist_test['input_parameters']['number_of_sequences'] = number_of_sequences
        nist_test['execution_times']['total_seconds'] = (
            nist_test['execution_times']['dataset_generation_seconds']
            + sum(nist_test['execution_times']['rounds_seconds'].values())
        )

        return nist_test

    @staticmethod
    def _build_report_from_results(results):
        """Build a report-style dict from NIST STS JSON results."""
        return NISTTests._build_report_from_results(results, TEST_ID_TABLE)

    @staticmethod
    def _run_nist_statistical_tests_tool(
        input_file,
        bit_stream_length=10000,
        number_of_bit_streams=10,
        input_file_format=1,
        statistical_test_option_list=15 * '1',
    ):
        """
        Run the NIST STS tests on packed or unpacked binary data.

        INPUT:

        - ``input_file`` -- **bytes|bytearray|list|np.ndarray**; binary input.
        - ``bit_stream_length`` -- **int**; number of bits per sequence.
        - ``number_of_bit_streams`` -- **int**; number of sequences to test.
        - ``input_file_format`` -- **int**; ``0`` for unpacked bits, ``1`` for packed bytes.
        - ``statistical_test_option_list`` -- **str**; 15-bit mask selecting tests.
        """
        option = NISTTests._normalize_test_option_list(statistical_test_option_list)
        test_names = [name for flag, name in zip(option, NISTTests._test_name_map()) if flag == '1']

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
    def _format_test_result(test_name, result, test_id, total_seqs):
        """Format a single test result into the report schema."""
        return NISTTests._format_test_result(test_name, result, test_id, total_seqs)

    @staticmethod
    def _run_cumsum_both_modes(binary_data):
        """Run cumulative sums in forward and backward modes."""
        return [
            NISTTests.cumulative_sums_test(binary_data, mode=0),
            NISTTests.cumulative_sums_test(binary_data, mode=1),
        ]

    def _generate_nist_dicts(
        self,
        time_date,
        dataset,
        round_start,
        round_end,
        statistical_test_option_list=15 * '1',
        execution_times=None,
    ):
        """Run the NIST STS tests per round and return report dictionaries."""
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
            if execution_times is not None:
                execution_times['rounds_seconds'][round_number] = sts_execution_time

            sts_report_dict['data_type'] = f'{self.cipher.inputs[self.input_index]}_{self.dataset_type.value}'
            sts_report_dict['cipher_name'] = f'{self.cipher.id}'
            sts_report_dict['round'] = round_number
            sts_report_dict['rounds'] = self.cipher.number_of_rounds
            sts_report_dicts.append(sts_report_dict)

        return sts_report_dicts

