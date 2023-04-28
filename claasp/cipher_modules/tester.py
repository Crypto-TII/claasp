
# ****************************************************************************
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


import secrets
from types import ModuleType

from claasp.cipher_modules import evaluator
# Imports below need to be imported one by one following best practises.
# These methods are used in generated code that needs to be reviewed
from claasp.utils.integer_functions import int_to_bytearray, bytearray_to_int


def test_against_reference_code(cipher, number_of_tests=5):
    if cipher.reference_code is not None:
        # Import the reference implementation
        reference_function_scope = {}

        f_module = ModuleType("tester")
        exec(cipher.reference_code,
             f_module.__dict__, reference_function_scope)

        reference_function = list(reference_function_scope.values())[0]
        for i in range(number_of_tests):
            # Generate random inputs
            cipher_inputs = [(secrets.randbelow(2 ** input_bit_size), input_bit_size) for input_bit_size in
                             cipher.inputs_bit_size]

            reference_implementation_inputs = [
                int_to_bytearray(
                    input_value,
                    input_size) for input_value,
                input_size in cipher_inputs]
            graph_representation_inputs = [input_value for input_value, _ in cipher_inputs]

            # Compute expected output from reference implementation
            expected_output = bytearray_to_int(reference_function(*reference_implementation_inputs))

            # Test Python library
            python_graph_output = evaluator.evaluate(cipher, graph_representation_inputs)

            # Check the results
            if expected_output != python_graph_output:
                print(f"Test n.{i + 1} for {cipher.id} failed:")

                k = 0
                for parameter in cipher.inputs:
                    print(f"    {parameter} -> {hex(graph_representation_inputs[k])}")
                    k += 1

                return False

        return True
    else:
        raise AttributeError("No reference code found.")


def test_vector_check(cipher, list_of_test_vectors_input, list_of_test_vectors_output):
    test_result = True
    for i in range(len(list_of_test_vectors_input)):
        if evaluator.evaluate(cipher, list_of_test_vectors_input[i]) != list_of_test_vectors_output[i]:
            print("Testing Failed")
            print("index:", i)
            print("input: ", list_of_test_vectors_input[i])
            print("output: ", list_of_test_vectors_output[i])
            test_result = False
    return test_result
