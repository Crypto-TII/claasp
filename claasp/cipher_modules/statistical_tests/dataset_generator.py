
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


import random
import numpy as np
import math as math
from enum import Enum
from operator import xor
from copy import deepcopy


class DatasetType(Enum):
    avalanche = "avalanche"
    correlation = "correlation"
    cbc = "cipher_block_chaining_mode"
    random = "random"
    low_density = "low_density"
    high_density = "high_density"


def get_low_density_sequences(bit_length):
    seq_0 = np.zeros((1, bit_length), dtype=np.uint8)

    seq_1 = np.zeros((bit_length, bit_length), dtype=np.uint8)
    for i in range(bit_length):
        seq_1[i][i] = 1

    seq_2 = np.zeros((math.comb(bit_length, 2), bit_length), dtype=np.uint8)
    count = 0
    for i in range(bit_length):
        for j in range(i + 1, bit_length):
            seq_2[count][i] = 1
            seq_2[count][j] = 1
            count += 1

    return [seq_0, seq_1, seq_2]


def set_testing_data_amount(number_of_blocks_in_one_sample, number_of_samples):
    number_of_blocks_in_one_sample = number_of_blocks_in_one_sample * number_of_samples
    number_of_samples = 1
    print("The number of samples is forced to be 1, and the number of blocks in one sample is forced to be " +
          str(number_of_blocks_in_one_sample) + ".")

    return number_of_blocks_in_one_sample, number_of_samples


class DatasetGenerator:

    def __init__(self, cipher):
        self.cipher = cipher
        str_of_inputs_bit_size = list(map(str, cipher.inputs_bit_size))
        self._cipher_primitive = cipher.id + "_" + "_".join(str_of_inputs_bit_size)

    def generate_avalanche_dataset(self, input_index, number_of_samples, save_file=False, filename=""):
        r"""
        Generate the avalanche dataset.

        INPUT:

        - ``input_index`` -- **integer**; the index of inputs to generate testing data. For example, inputs=[key, plaintest],
          input_index=0 means it will generate the key avalanche dataset. If input_index=1 means it will generate
          the plaintext avalanche dataset
        - ``number_of_samples`` -- **integer**; how many testing data should be generated
        - ``save_file`` -- **boolean** (default: `False`); save the generated data to file if it is True
        - ``filename`` -- **string** (default: ``); the file name to save the generated data

        OUTPUT:

        - ``dataset`` -- output the dataset in bit_stream format

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.statistical_tests.dataset_generator import DatasetGenerator
            sage: dataset_generator = DatasetGenerator(SpeckBlockCipher(number_of_rounds=3))
            sage: dataset_generator.generate_avalanche_dataset(input_index=0, number_of_samples=2)  # random
            [array([0, 1, 0, ..., 0, 0, 0], dtype=uint8),
             ...
             array([6, 237, 14, ..., 0, 0, 0], dtype=uint8)]
        """
        # generate input
        inputs = []
        for i in range(len(self.cipher.inputs)):
            bit_size = self.cipher.inputs_bit_size[i]
            if i == input_index:
                inputs.append(np.random.randint(256, size=(bit_size // 8, number_of_samples), dtype=np.uint8))
            else:
                inputs.append(np.zeros(shape=(bit_size // 8, number_of_samples), dtype=np.uint8))

        # output of cipher
        outputs = self.cipher.evaluate_vectorized(inputs, intermediate_outputs=True)

        # avalanche output of cipher
        outputs_avanlanche_list = [
            np.zeros(shape=(number_of_samples,
                            (self.cipher.inputs_bit_size[input_index] *
                             self.cipher.output_bit_size) // 8),
                     dtype=np.uint8)
            for _ in range(self.cipher.number_of_rounds)]

        # mask to generate avalanche data
        mask = np.zeros(shape=(self.cipher.inputs_bit_size[input_index], 1), dtype=np.uint8)
        mask[-1] = 1

        for i in range(self.cipher.inputs_bit_size[input_index]):
            inputs_avalanche = deepcopy(inputs)
            inputs_avalanche[input_index] = xor(inputs_avalanche[input_index], np.packbits(mask, axis=0))
            outputs_avanlanche = self.cipher.evaluate_vectorized(inputs_avalanche, intermediate_outputs=True)
            for r in range(self.cipher.number_of_rounds - 1):
                outputs_avanlanche_list[r][:, i * self.cipher.output_bit_size //
                                           8:(i + 1) * self.cipher.output_bit_size // 8] = \
                    xor(outputs["round_output"][r], outputs_avanlanche["round_output"][r])
            outputs_avanlanche_list[-1][:, i * self.cipher.output_bit_size //
                                        8:(i + 1) * self.cipher.output_bit_size // 8] = \
                xor(outputs["cipher_output"][0], outputs_avanlanche["cipher_output"][0])
            mask = np.roll(mask, -1, axis=0)

        dataset = []
        for r in range(self.cipher.number_of_rounds):
            samples_r = np.unpackbits(outputs_avanlanche_list[r])
            samples_r = np.packbits(samples_r, axis=0)
            dataset.append(samples_r)

        if save_file:
            if filename == "":
                filename = self._cipher_primitive + "_avalanche_index_" + str(input_index)
            np.savez_compressed(filename, dataset=dataset)

        return dataset

    def generate_cbc_dataset(self, input_index, number_of_samples,
                             number_of_blocks_in_one_sample, save_file=False, filename=""):
        r"""
        Generate the CBC dataset.

        INPUT:

        - ``input_index`` -- **integer**; the index of inputs to generate testing data. For example, inputs=[key, plaintest],
          input_index=0 means it will generate the key CBC dataset. if input_index=1 means it will generate the
          plaintext CBC dataset
        - ``number_of_samples`` -- **integer**; how many testing data should be generated
        - ``number_of_blocks_in_one_sample`` -- **integer**; how many blocks should be generated in one test sequence
        - ``save_file`` -- **boolean** (default: `False`); save the generated data to file if it is True
        - ``filename`` -- **string** (default: ``); the file name to save the generated data

        OUTPUT:

        - ``dataset`` -- output the dataset in bit_stream format

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.statistical_tests.dataset_generator import DatasetGenerator
            sage: dataset_generator = DatasetGenerator(SpeckBlockCipher(number_of_rounds=3))
            sage: dataset_generator.generate_cbc_dataset(input_index=0, number_of_samples=2, number_of_blocks_in_one_sample=10) # random
            [array([163,  27,  29, 156, ...,  72,  33,  37,  90], dtype=uint8),
             ...
             array([ 80, 178,  59,  25, ..., 124,  47, 118, 221], dtype=uint8)]
        """
        if self.cipher.inputs_bit_size[input_index] != self.cipher.output_bit_size:
            print("Error: the bit size of inputs[input_index] is not equal to cipher_output_bit_size")
            return []

        if len(self.cipher.inputs) == 1 and number_of_samples != 1:
            number_of_blocks_in_one_sample, number_of_samples = \
                set_testing_data_amount(number_of_blocks_in_one_sample, number_of_samples)

        outputs_list = self.get_cipher_outputs_for_cbc_dataset(input_index, number_of_blocks_in_one_sample,
                                                               number_of_samples)

        dataset = []
        for round_number in range(self.cipher.number_of_rounds):
            samples_r = np.unpackbits(outputs_list[round_number])
            samples_r = np.packbits(samples_r, axis=0)
            dataset.append(samples_r)

        if save_file:
            if filename == "":
                filename = self._cipher_primitive + "_CBC_index_" + str(input_index)
            np.savez_compressed(filename, dataset=dataset)

        return dataset

    def get_cipher_outputs_for_cbc_dataset(self, input_index, number_of_blocks_in_one_sample, number_of_samples):
        outputs_list = [[] for _ in range(self.cipher.number_of_rounds)]
        for _ in range(number_of_samples):
            # generate input
            IV = np.zeros(
                (self.cipher.inputs_bit_size[input_index] // 8, self.cipher.number_of_rounds),
                dtype=np.uint8)
            PT = np.zeros(
                (self.cipher.inputs_bit_size[input_index] // 8, self.cipher.number_of_rounds),
                dtype=np.uint8)
            inputs = []
            for j in range(len(self.cipher.inputs)):
                bit_size = self.cipher.inputs_bit_size[j]
                if j == input_index:
                    inputs.append(xor(IV, PT))
                else:
                    rand_input = np.full((self.cipher.number_of_rounds, bit_size // 8),
                                         np.random.randint(256, size=(1, bit_size // 8)), dtype=np.uint8)
                    inputs.append(rand_input.transpose())

            for j in range(number_of_blocks_in_one_sample):
                # output of cipher
                outputs = self.cipher.evaluate_vectorized(inputs, intermediate_outputs=True)
                for round_number in range(self.cipher.number_of_rounds - 1):
                    outputs_list[round_number].append(outputs["round_output"][round_number][round_number])
                    inputs[input_index][:, round_number] = \
                        outputs["round_output"][round_number][round_number].transpose()
                outputs_list[-1].append(outputs["cipher_output"][0][-1])
                inputs[input_index][:, -1] = outputs["cipher_output"][0][-1].transpose()

        return outputs_list

    def generate_correlation_dataset(self, input_index, number_of_samples, number_of_blocks_in_one_sample,
                                     save_file=False, filename=""):
        r"""
        Generate the correlation dataset.

        INPUT:

        - ``input_index`` -- **integer**; the index of inputs to generate testing data. For example, inputs=[key, plaintest],
          input_index=0 means it will generate the key correlation dataset. If input_index=1 means it will generate
          the plaintext correlation dataset
        - ``number_of_samples`` -- **integer**; how many testing data should be generated
        - ``number_of_blocks_in_one_sample`` -- **integer**; how many blocks should be generated in one test sequence
        - ``save_file`` -- **boolean** (default: `False`); save the generated data to file if it is True
        - ``filename`` -- **string** (default: ``); the file name to save the generated data

        OUTPUT:

        - ``dataset`` -- output the dataset in bit_stream format

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.statistical_tests.dataset_generator import DatasetGenerator
            sage: dataset_generator = DatasetGenerator(SpeckBlockCipher(number_of_rounds=3))
            sage: dataset_generator.generate_correlation_dataset(input_index=0, number_of_samples=2, number_of_blocks_in_one_sample=10)  # random
            [array([163,  27,  29, 156, ...,  72,  33,  37,  90], dtype=uint8),
             ...
             array([ 80, 178,  59,  25, ..., 124,  47, 118, 221], dtype=uint8)]
        """
        if self.cipher.inputs_bit_size[input_index] != self.cipher.output_bit_size:
            print("Error: the bit size of inputs[input_index] is not equal to cipher_output_bit_size")
            return []

        if len(self.cipher.inputs) == 1 and number_of_samples != 1:
            number_of_blocks_in_one_sample, number_of_samples = \
                set_testing_data_amount(number_of_blocks_in_one_sample, number_of_samples)

        # generate input
        inputs_fixed = np.random.randint(256, size=(
            self.cipher.inputs_bit_size[input_index] // 8, number_of_blocks_in_one_sample),
            dtype=np.uint8)
        outputs_list = self.get_cipher_outputs_for_correlation_dataset(input_index, inputs_fixed,
                                                                       number_of_blocks_in_one_sample,
                                                                       number_of_samples)

        dataset = []
        for r in range(self.cipher.number_of_rounds):
            samples_r = np.unpackbits(outputs_list[r])
            samples_r = np.packbits(samples_r, axis=0)
            dataset.append(samples_r)

        if save_file:
            if filename == "":
                filename = self._cipher_primitive + "_correlation_index_" + str(input_index)
            np.savez_compressed(filename, dataset=dataset)

        return dataset

    def get_cipher_outputs_for_correlation_dataset(self, input_index, inputs_fixed,
                                                   number_of_blocks_in_one_sample,
                                                   number_of_samples):
        outputs_list = [[] for _ in range(self.cipher.number_of_rounds)]
        for _ in range(number_of_samples):
            inputs = []
            for j in range(len(self.cipher.inputs)):
                bit_size = self.cipher.inputs_bit_size[j]
                if j == input_index:
                    inputs.append(deepcopy(inputs_fixed))
                else:
                    rand_input = np.full((number_of_blocks_in_one_sample, bit_size // 8),
                                         np.random.randint(256, size=(1, bit_size // 8)), dtype=np.uint8)
                    inputs.append(rand_input.transpose())

            outputs = self.cipher.evaluate_vectorized(inputs, intermediate_outputs=True)
            for r in range(self.cipher.number_of_rounds - 1):
                outputs_list[r].append(xor(outputs["round_output"][r], inputs_fixed.transpose()))
            outputs_list[-1].append(xor(outputs["cipher_output"][0], inputs_fixed.transpose()))

        return outputs_list

    def generate_high_density_dataset(self, input_index, number_of_samples, ratio=1, save_file=False, filename=""):
        r"""
        Generate the high density dataset.

        INPUT:

        - ``input_index`` -- **integer**; the index of inputs to generate testing data. For example, inputs=[key, plaintest],
          input_index=0 means it will generate the key high density dataset. if input_index=1 means it will generate
          the plaintext high density dataset
        - ``number_of_samples`` -- **integer**; how many testing data should be generated
        - ``ratio`` -- **integer** (default: `1`); the ratio of weight 2 (that is, two 1 in the input) as high density
          inputs, range  in [0, 1]. For exmaple, if ratio = 0.5, means half of the weight 2 high density inputs will be
          taken as  inputs.
        - ``save_file`` -- **boolean** (default: `False`); save the generated data to file if it is True
        - ``filename`` -- **string** (default: ``); the file name to save the generated data

        OUTPUT:

        - ``dataset`` -- output the dataset in bit_stream format

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.statistical_tests.dataset_generator import DatasetGenerator
            sage: dataset_generator = DatasetGenerator(SpeckBlockCipher(number_of_rounds=3))
            sage: dataset_generator.generate_high_density_dataset(input_index=0, number_of_samples=2, ratio=0.5)  # random
            [array([163,  27,  29, 156, ...,  72,  33,  37,  90], dtype=uint8),
             ...
             array([ 80, 178,  59,  25, ..., 124,  47, 118, 221], dtype=uint8)]
        """
        # generate inputs
        low_density_seq = get_low_density_sequences(self.cipher.inputs_bit_size[input_index])
        inputs_low_density = np.append(low_density_seq[0], low_density_seq[1], axis=0)
        if ratio < 1:
            weight_two_size = math.ceil(len(low_density_seq[2]) * ratio)
            weight_two_seq_idx = set()
            while len(weight_two_seq_idx) < weight_two_size:
                weight_two_seq_idx.add(random.randint(0, weight_two_size - 1))
            for i in weight_two_seq_idx:
                inputs_low_density = np.append(inputs_low_density, [low_density_seq[2][i]], axis=0)
        else:
            inputs_low_density = np.append(inputs_low_density, low_density_seq[2], axis=0)

        inputs_mask = np.ones((1, self.cipher.inputs_bit_size[input_index]), dtype=np.uint8)
        inputs_high_density = xor(inputs_low_density, inputs_mask)
        inputs_high_density = np.packbits(inputs_high_density, axis=1)
        inputs_high_density = inputs_high_density.transpose()

        outputs_list = self.get_cipher_outputs_for_density_dataset(input_index, inputs_high_density,
                                                                   number_of_samples)

        dataset = []
        for r in range(self.cipher.number_of_rounds):
            samples_r = np.unpackbits(outputs_list[r])
            samples_r = np.packbits(samples_r, axis=0)
            dataset.append(samples_r)

        if save_file:
            if filename == "":
                filename = self._cipher_primitive + "_high_density_index_" + str(input_index)
            np.savez_compressed(filename, dataset=dataset)

        return dataset

    def get_cipher_outputs_for_density_dataset(self, input_index, inputs_density, number_of_samples):
        outputs_list = [[] for _ in range(self.cipher.number_of_rounds)]
        for _ in range(number_of_samples):
            inputs = []
            for j in range(len(self.cipher.inputs)):
                if j == input_index:
                    inputs.append(deepcopy(inputs_density))
                else:
                    bit_size = self.cipher.inputs_bit_size[j]
                    rand_input = np.random.randint(256, size=(1, bit_size // 8), dtype=np.uint8)
                    rand_input = np.full((inputs_density.shape[1], bit_size // 8), rand_input, dtype=np.uint8)
                    inputs.append(rand_input.transpose())

            # output of cipher
            outputs = self.cipher.evaluate_vectorized(inputs, intermediate_outputs=True)
            for r in range(self.cipher.number_of_rounds - 1):
                outputs_list[r].append(outputs["round_output"][r])
            outputs_list[-1].append(outputs["cipher_output"][0])

        return outputs_list

    def generate_low_density_dataset(self, input_index, number_of_samples, ratio=1, save_file=False, filename=""):
        r"""
        Generate the low density dataset.

        INPUT:

        - ``input_index`` -- **integer**; the index of inputs to generate testing data. For example, inputs=[key, plaintest],
          input_index=0 means it will generate the key low density dataset. if input_index=1 means it will generate
          the plaintext low density dataset
        - ``number_of_samples`` -- **integer**; how many testing data should be generated
        - ``ratio`` -- **integer** (default: `1`); the ratio of weight 2 (that is, two 1 in the input) as low density
          inputs, range in [0, 1]. For example, if ratio = 0.5, means half of the weight 2 low density inputs will be
          taken as inputs
        - ``save_file`` -- **boolean** (default: `False`); save the generated data to file if it is True
        - ``filename`` -- **string** (default: ``); the file name to save the generated data

        OUTPUT:

        - ``dataset`` -- output the dataset in bit_stream format

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.statistical_tests.dataset_generator import DatasetGenerator
            sage: dataset_generator = DatasetGenerator(SpeckBlockCipher(number_of_rounds=3))
            sage: dataset_generator.generate_low_density_dataset(input_index=0, number_of_samples=2, ratio=0.5)  # random
            [array([163,  27,  29, 156, ...,  72,  33,  37,  90], dtype=uint8),
             ...
             array([ 80, 178,  59,  25, ..., 124,  47, 118, 221], dtype=uint8)]
        """
        # generate inputs
        low_density_seq = get_low_density_sequences(self.cipher.inputs_bit_size[input_index])
        inputs_low_density = np.append(low_density_seq[0], low_density_seq[1], axis=0)
        if ratio < 1:
            weight_two_size = math.ceil(len(low_density_seq[2]) * ratio)
            weight_two_seq_idx = set()
            while len(weight_two_seq_idx) < weight_two_size:
                weight_two_seq_idx.add(random.randint(0, weight_two_size - 1))
            for i in weight_two_seq_idx:
                inputs_low_density = np.append(inputs_low_density, [low_density_seq[2][i]], axis=0)
        else:
            inputs_low_density = np.append(inputs_low_density, low_density_seq[2], axis=0)
        inputs_low_density = np.packbits(inputs_low_density, axis=1)
        inputs_low_density = inputs_low_density.transpose()

        outputs_list = self.get_cipher_outputs_for_density_dataset(input_index, inputs_low_density,
                                                                   number_of_samples)

        dataset = []
        for r in range(self.cipher.number_of_rounds):
            samples_r = np.unpackbits(outputs_list[r])
            samples_r = np.packbits(samples_r, axis=0)
            dataset.append(samples_r)

        if save_file:
            if filename == "":
                filename = self._cipher_primitive + "_low_density_index_" + str(input_index)
            np.savez_compressed(filename, dataset=dataset)

        return dataset

    def generate_random_dataset(self, input_index, number_of_samples,
                                number_of_blocks_in_one_sample, save_file=False, filename=""):
        r"""
        Generate the random dataset.

        INPUT:

        - ``input_index`` -- **integer**; the index of inputs to generate testing data. For example, inputs=[key, plaintest],
          input_index=0 means it will generate the key random dataset. if input_index=1 means it will generate
          the plaintext random dataset
        - ``number_of_samples`` -- **integer**; how many testing data should be generated
        - ``number_of_blocks_in_one_sample`` -- **integer** how many blocks should be generated in  one test sequence
        - ``save_file`` -- **boolean** (default: `False`); save the generated data to file if it is True
        - ``filename`` -- **string** (default: ``); the file name to save the generated data

        OUTPUT:

        - ``dataset`` -- output the dataset in bit_stream format

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.statistical_tests.dataset_generator import DatasetGenerator
            sage: dataset_generator = DatasetGenerator(SpeckBlockCipher(number_of_rounds=3))
            sage: dataset_generator.generate_random_dataset(input_index=0, number_of_samples=2, number_of_blocks_in_one_sample=10) # random
            [array([163,  27,  29, 156, ...,  72,  33,  37,  90], dtype=uint8),
             ...
             array([ 80, 178,  59,  25, ..., 124,  47, 118, 221], dtype=uint8)]
        """
        if len(self.cipher.inputs) == 1 and number_of_samples != 1:
            number_of_blocks_in_one_sample, number_of_samples = \
                set_testing_data_amount(number_of_blocks_in_one_sample, number_of_samples)

        # outputs of cipher
        outputs_list = [[] for _ in range(self.cipher.number_of_rounds)]
        # generate inputs
        for _ in range(number_of_samples):
            inputs = []
            for j in range(len(self.cipher.inputs)):
                bit_size = self.cipher.inputs_bit_size[j]
                if j == input_index:
                    rand_input = np.random.randint(256, size=(bit_size // 8, number_of_blocks_in_one_sample),
                                                   dtype=np.uint8)
                    inputs.append(rand_input)
                else:
                    rand_input = np.full((number_of_blocks_in_one_sample, bit_size // 8),
                                         np.random.randint(256, size=(1, bit_size // 8)), dtype=np.uint8)
                    inputs.append(rand_input.transpose())

            # output of cipher
            outputs = self.cipher.evaluate_vectorized(inputs, intermediate_outputs=True)
            for round_number in range(self.cipher.number_of_rounds - 1):
                outputs_list[round_number].append(outputs["round_output"][round_number])
            outputs_list[-1].append(outputs["cipher_output"][0])

        dataset = []
        for round_number in range(self.cipher.number_of_rounds):
            samples_r = np.unpackbits(outputs_list[round_number])
            samples_r = np.packbits(samples_r, axis=0)
            dataset.append(samples_r)

        if save_file:
            if filename == "":
                filename = self._cipher_primitive + "_random_index_" + str(input_index)
            np.savez_compressed(filename, dataset=dataset)

        return dataset

