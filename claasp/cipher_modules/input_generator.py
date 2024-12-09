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


import numpy as np
from types import ModuleType
from subprocess import Popen, PIPE

from claasp.cipher_modules import code_generator
from claasp.cipher_modules.generic_functions_vectorized_byte import cipher_inputs_to_evaluate_vectorized_inputs, \
    evaluate_vectorized_format_to_integers

def generate_zeros(amount_of_samples):
    return

def generate_ones(amount_of_samples):
    return

def generate_binary(amount_of_samples):
    return

def generate_byte(amount_of_samples):
    return

def generate_int_with_range(size_of_bit, range, amount_of_samples):
    return

def generate_avalanche(input):
    return


class InputGenerator:

    def __init__(self, cipher):
        self.cipher = cipher

    def generate_input(self, type_list, number_of_samples):
        return