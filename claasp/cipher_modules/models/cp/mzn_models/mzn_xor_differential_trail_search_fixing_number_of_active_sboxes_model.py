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
import subprocess
import time as tm

from copy import deepcopy

from claasp.cipher_modules.models.cp.mzn_model import SOLVE_SATISFY
from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_model import MznXorDifferentialModel
from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_number_of_active_sboxes_model import (
    MznXorDifferentialNumberOfActiveSboxesModel,
)
from claasp.cipher_modules.models.cp.solvers import (
    CP_SOLVERS_EXTERNAL,
    SOLVER_DEFAULT,
)
from claasp.cipher_modules.models.utils import convert_solver_solution_to_dictionary
from claasp.name_mappings import UNSATISFIABLE, XOR_DIFFERENTIAL


class MznXorDifferentialFixingNumberOfActiveSboxesModel(
    MznXorDifferentialModel, MznXorDifferentialNumberOfActiveSboxesModel
):
    def __init__(self, cipher):
        self._table_items = []
        super().__init__(cipher)

    def initialise_model(self):
        self._table_items = []
        self._first_step = []
        self._first_step_find_all_solutions = []
        super().initialise_model()

    def build_xor_differential_trail_second_step_model(self, weight=-1, fixed_variables=[]):
        """
        Build the CP Model for the second step of the search of XOR differential trail of an SPN cipher.

        INPUT:

        - ``weight`` -- **integer** (default: `1`); a specific weight. If set to non-negative integer, fixes the XOR
          trail weight
        - ``fixed_variables`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in
          standard format

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_trail_search_fixing_number_of_active_sboxes_model import (
            ....: MznXorDifferentialFixingNumberOfActiveSboxesModel)
            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: cp = MznXorDifferentialFixingNumberOfActiveSboxesModel(aes)
            sage: fixed_variables = [set_fixed_variables('key', 'not_equal', range(128),
            ....: integer_to_bit_list(0, 128, 'little'))]
            sage: cp.build_xor_differential_trail_second_step_model(-1, fixed_variables)
        """
        self.c = 0
        self.sbox_mant = []
        self.component_and_probability = {}
        self.build_xor_differential_trail_model_template(weight, fixed_variables)
        variables, constraints = self.input_xor_differential_constraints()
        self._model_prefix.extend(variables)
        self._variables_list.append(constraints)
        self._model_constraints.extend(self.final_xor_differential_constraints(weight))
        self._model_constraints = self._model_prefix + self._variables_list + self._model_constraints

    def find_all_xor_differential_trails_with_fixed_weight(
        self,
        fixed_weight,
        fixed_values=[],
        first_step_solver_name=SOLVER_DEFAULT,
        second_step_solver_name=SOLVER_DEFAULT,
        nmax=2,
        repetition=1,
        num_of_processors=None,
        timelimit=None,
    ):
        """
        Return a list of solutions containing all the differential trails having the ``fixed_weight`` weight of correlation.

        INPUT:

        - ``fixed_weight`` -- **integer** (default: `-1`); a specific weight. If set to non-negative integer, fixes the XOR
          trail weight.
        - ``fixed_values`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in standard
          format
        - ``first_step_solver_name`` -- **string** (default: `None`); the solver to call for the first step
        - ``second_step_solver_name`` -- **string** (default: `None`); the solver to call for the second step
        - ``nmax`` -- **integer** (default: `2`); the minimum number of addends for which new xor components are NOT
          added when considering additional xor constraints
        - ``repetition`` -- **integer** (default: `1`); the number of times the procedure for creating new xor
          components will be repeated.
        - ``num_of_processors`` -- **integer** (default: None); the number of cores to use
        - ``timelimit`` -- **integer** (default: None); the time limit for the solver in seconds
          See also :meth:`MznModel.solver_names`.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_trail_search_fixing_number_of_active_sboxes_model import (
            ....: MznXorDifferentialFixingNumberOfActiveSboxesModel)
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: cp = MznXorDifferentialFixingNumberOfActiveSboxesModel(aes)
            sage: fixed_variables = [set_fixed_variables('key', 'equal', range(128),
            ....: integer_to_bit_list(0, 128, 'little'))]
            sage: fixed_variables.append(set_fixed_variables('plaintext', 'not_equal', range(128),
            ....: integer_to_bit_list(0, 128, 'little')))
            sage: trails = cp.find_all_xor_differential_trails_with_fixed_weight(224, fixed_variables, 'chuffed', 'chuffed') # long # doctest: +SKIP
            ...
            sage: len(trails) # long # doctest: +SKIP
            8
        """
        return self.solve_full_two_steps_xor_differential_model(
            "xor_differential_all_solutions",
            fixed_weight,
            fixed_values,
            first_step_solver_name,
            second_step_solver_name,
            nmax,
            repetition,
            num_of_processors,
            timelimit,
        )

    def find_lowest_weight_xor_differential_trail(
        self,
        fixed_values=[],
        first_step_solver_name=SOLVER_DEFAULT,
        second_step_solver_name=SOLVER_DEFAULT,
        nmax=2,
        repetition=1,
        num_of_processors=None,
        timelimit=None,
    ):
        """
        Return the solution representing a differential trail with the lowest weight.

        .. NOTE::

            There could be more than one trail with the lowest weight. In order to find all the lowest weight
            trail, run :py:meth:`~SmtModel.find_all_xor_differential_trails_with_fixed_weight`.

        INPUT:

        - ``fixed_weight`` -- **integer** (default: `-1`); a specific weight. If set to non-negative integer, fixes the XOR
          trail weight.
        - ``fixed_values`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in standard
          format
        - ``first_step_solver_name`` -- **string** (default: `None`); the solver to call for the first step
        - ``second_step_solver_name`` -- **string** (default: `None`); the solver to call for the second step
        - ``nmax`` -- **integer** (default: `2`); the minimum number of addends for which new xor components are NOT
          added when considering additional xor constraints
        - ``repetition`` -- **integer** (default: `1`); the number of times the procedure for creating new xor
          components will be repeated.
        - ``num_of_processors`` -- **integer** (default: None); the number of cores to use
        - ``timelimit`` -- **integer** (default: None); the time limit for the solver in seconds
          See also :meth:`MznModel.solver_names`.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_trail_search_fixing_number_of_active_sboxes_model import (
            ....: MznXorDifferentialFixingNumberOfActiveSboxesModel)
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: cp = MznXorDifferentialFixingNumberOfActiveSboxesModel(aes)
            sage: fixed_variables = [set_fixed_variables('key', 'equal', range(128),
            ....: integer_to_bit_list(0, 128, 'little'))]
            sage: fixed_variables.append(set_fixed_variables('plaintext', 'not_equal', range(128),
            ....: integer_to_bit_list(0, 128, 'little')))
            sage: cp.find_lowest_weight_xor_differential_trail(fixed_variables, 'chuffed', 'chuffed') # random
            5
            {'cipher': 'aes_block_cipher_k128_p128_o128_r2',
             'model_type': 'xor_differential',
             'solver_name': 'chuffed',
             'components_values': {'key': {'value': '00000000000000000000000000000000', 'weight': 0},
              ...
             'total_weight': '30.0'}
        """
        return self.solve_full_two_steps_xor_differential_model(
            "xor_differential_one_solution",
            -1,
            fixed_values,
            first_step_solver_name,
            second_step_solver_name,
            nmax,
            repetition,
            num_of_processors,
            timelimit,
        )

    def find_one_xor_differential_trail(
        self,
        fixed_values=[],
        first_step_solver_name=SOLVER_DEFAULT,
        second_step_solver_name=SOLVER_DEFAULT,
        nmax=2,
        repetition=1,
        num_of_processors=None,
        timelimit=None,
    ):
        """
        Return the solution representing a differential trail with any weight.

        INPUT:

        - ``fixed_values`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in standard
          format
        - ``first_step_solver_name`` -- **string** (default: `None`); the solver to call for the first step
        - ``second_step_solver_name`` -- **string** (default: `None`); the solver to call for the second step
        - ``nmax`` -- **integer** (default: `2`); the minimum number of addends for which new xor components are NOT
          added when considering additional xor constraints
        - ``repetition`` -- **integer** (default: `1`); the number of times the procedure for creating new xor
          components will be repeated.
        - ``num_of_processors`` -- **integer** (default: None); the number of cores to use
        - ``timelimit`` -- **integer** (default: None); the time limit for the solver in seconds
          See also :meth:`MznModel.solver_names`.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_trail_search_fixing_number_of_active_sboxes_model import (
            ....: MznXorDifferentialFixingNumberOfActiveSboxesModel)
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: cp = MznXorDifferentialFixingNumberOfActiveSboxesModel(aes)
            sage: fixed_variables = [set_fixed_variables('key', 'equal', range(128),
            ....: integer_to_bit_list(0, 128, 'little'))]
            sage: fixed_variables.append(set_fixed_variables('plaintext', 'not_equal', range(128),
            ....: integer_to_bit_list(0, 128, 'little')))
            sage: cp.find_one_xor_differential_trail(fixed_variables, 'chuffed', 'chuffed') # random
            {'cipher': 'aes_block_cipher_k128_p128_o128_r2',
             'model_type': 'xor_differential',
              ...
             'cipher_output_1_32':{'value': 'ffffffffffffffffffffffffffffffff', 'weight': 0.0}},
             'total_weight': '224.0'}
        """
        return self.solve_full_two_steps_xor_differential_model(
            "xor_differential_one_solution",
            0,
            fixed_values,
            first_step_solver_name,
            second_step_solver_name,
            nmax,
            repetition,
            num_of_processors,
            timelimit,
        )

    def find_one_xor_differential_trail_with_fixed_weight(
        self,
        fixed_weight=-1,
        fixed_values=[],
        first_step_solver_name=SOLVER_DEFAULT,
        second_step_solver_name=SOLVER_DEFAULT,
        nmax=2,
        repetition=1,
        num_of_processors=None,
        timelimit=None,
    ):
        """
        Return the solution representing a differential trail with any weight.

        INPUT:

        - ``fixed_weight`` -- **integer** (default: `-1`); a specific weight. If set to non-negative integer, fixes the XOR
          trail weight.
        - ``fixed_values`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in standard
          format
        - ``first_step_solver_name`` -- **string** (default: `None`); the solver to call for the first step
        - ``second_step_solver_name`` -- **string** (default: `None`); the solver to call for the second step
        - ``nmax`` -- **integer** (default: `2`); the minimum number of addends for which new xor components are NOT
          added when considering additional xor constraints
        - ``repetition`` -- **integer** (default: `1`); the number of times the procedure for creating new xor
          components will be repeated.
        - ``num_of_processors`` -- **integer** (default: None); the number of cores to use
        - ``timelimit`` -- **integer** (default: None); the time limit for the solver in seconds
          See also :meth:`MznModel.solver_names`.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_trail_search_fixing_number_of_active_sboxes_model import (
            ....: MznXorDifferentialFixingNumberOfActiveSboxesModel)
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: cp = MznXorDifferentialFixingNumberOfActiveSboxesModel(aes)
            sage: fixed_variables = [set_fixed_variables('key', 'equal', range(128),
            ....: integer_to_bit_list(0, 128, 'little'))]
            sage: fixed_variables.append(set_fixed_variables('plaintext', 'not_equal', range(128),
            ....: integer_to_bit_list(0, 128, 'little')))
            sage: cp.find_one_xor_differential_trail_with_fixed_weight(224, fixed_variables, 'chuffed', 'chuffed') # random
            {'cipher': 'aes_block_cipher_k128_p128_o128_r2',
             'model_type': 'xor_differential',
             'solver_name': 'chuffed',
             ...
             'total_weight': '224.0',
             'building_time_seconds':  19.993147134780884}
        """
        return self.solve_full_two_steps_xor_differential_model(
            "xor_differential_one_solution",
            fixed_weight,
            fixed_values,
            first_step_solver_name,
            second_step_solver_name,
            nmax,
            repetition,
            num_of_processors,
            timelimit,
        )

    def generate_table_of_solutions(self, solution):
        """
        Return a table with the solutions from the first step in the two steps model for xor differential trail search.

        INPUT:

        - ``solution`` -- **list**; the solution from the first step in Minizinc format

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_trail_search_fixing_number_of_active_sboxes_model import (
            ....:     MznXorDifferentialFixingNumberOfActiveSboxesModel,
            ....: )
            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: cp = MznXorDifferentialFixingNumberOfActiveSboxesModel(aes)
            sage: fixed_variables = [set_fixed_variables('key', 'not_equal', list(range(128)), (0,)*128)]
            sage: cp.build_xor_differential_trail_first_step_model(-1, fixed_variables)
            sage: first_step_solution, solve_time = cp.solve_model('xor_differential_first_step', 'chuffed')
            sage: table_of_solutions = cp.generate_table_of_solutions(first_step_solution)
            sage: table_of_solutions[:26]
            'array [0..0, 1..40] of int'
        """
        cipher_name = self.cipher_id
        separator = "----------"
        count_separator = solution.count(separator)
        table_of_solutions_length = ""
        for line in solution:
            if "table_of_solution_length" in line:
                line = line.replace(" table_of_solution_length = ", "")
                table_of_solutions_length = line.rstrip("\n")
        table_of_solutions = (
            f"array [0..{count_separator - 1}, 1..{table_of_solutions_length}] of int: "
            f"{cipher_name}_table_of_solutions = "
            f"array2d(0..{count_separator - 1}, 1..{table_of_solutions_length}, ["
        )
        for line in solution:
            for item in self.input_sbox:
                if item[0] in line:
                    value = line.replace(item[0], "")
                    value = value.replace(" = ", "")
                    table_of_solutions = table_of_solutions + value.replace("\n", "") + ","
        table_of_solutions = table_of_solutions[:-1] + "]);"
        
        return table_of_solutions

    def get_solutions_dictionaries_with_build_time(
        self, build_time, components_values, memory, solver_name, time, total_weight
    ):
        solutions = [
            convert_solver_solution_to_dictionary(
                self.cipher_id,
                XOR_DIFFERENTIAL,
                solver_name,
                time,
                memory,
                components_values[f"solution{i + 1}"],
                total_weight[i],
            )
            for i in range(len(total_weight))
        ]
        for solution in solutions:
            solution["building_time_seconds"] = build_time
        if len(solutions) == 1:
            solutions = solutions[0]
        return solutions

    def input_xor_differential_constraints(self):
        """
        Return a list of CP declarations and a list of Cp constraints for the first part of the xor differential model.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_trail_search_fixing_number_of_active_sboxes_model import (
            ....:     MznXorDifferentialFixingNumberOfActiveSboxesModel)
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: cp = MznXorDifferentialFixingNumberOfActiveSboxesModel(aes)
            sage: cp.input_xor_differential_constraints()
            (['array[0..127] of var 0..1: key;',
              'array[0..127] of var 0..1: plaintext;',
               ...
             'constraint table([word_sbox_0_1[s] | s in 0..0]++[word_sbox_0_2[s] | s in 0..0]++[word_sbox_0_3[s] | s in 0..0]++[word_sbox_0_4[s] | s in 0..0]++[word_sbox_0_5[s] | s in 0..0]++[word_sbox_0_6[s] | s in 0..0]++[word_sbox_0_7[s] | s in 0..0]++[word_sbox_0_8[s] | s in 0..0]++[word_sbox_0_9[s] | s in 0..0]++[word_sbox_0_10[s] | s in 0..0]++[word_sbox_0_11[s] | s in 0..0]++[word_sbox_0_12[s] | s in 0..0]++[word_sbox_0_13[s] | s in 0..0]++[word_sbox_0_14[s] | s in 0..0]++[word_sbox_0_15[s] | s in 0..0]++[word_sbox_0_16[s] | s in 0..0]++[word_sbox_0_26[s] | s in 0..0]++[word_sbox_0_27[s] | s in 0..0]++[word_sbox_0_28[s] | s in 0..0]++[word_sbox_0_29[s] | s in 0..0]++[word_sbox_1_0[s] | s in 0..0]++[word_sbox_1_1[s] | s in 0..0]++[word_sbox_1_2[s] | s in 0..0]++[word_sbox_1_3[s] | s in 0..0]++[word_sbox_1_4[s] | s in 0..0]++[word_sbox_1_5[s] | s in 0..0]++[word_sbox_1_6[s] | s in 0..0]++[word_sbox_1_7[s] | s in 0..0]++[word_sbox_1_8[s] | s in 0..0]++[word_sbox_1_9[s] | s in 0..0]++[word_sbox_1_10[s] | s in 0..0]++[word_sbox_1_11[s] | s in 0..0]++[word_sbox_1_12[s] | s in 0..0]++[word_sbox_1_13[s] | s in 0..0]++[word_sbox_1_14[s] | s in 0..0]++[word_sbox_1_15[s] | s in 0..0]++[word_sbox_1_21[s] | s in 0..0]++[word_sbox_1_22[s] | s in 0..0]++[word_sbox_1_23[s] | s in 0..0]++[word_sbox_1_24[s] | s in 0..0], aes_block_cipher_k128_p128_o128_r2_table_of_solutions);')
        """
        cp_declarations, cp_constraints = super().input_xor_differential_constraints()

        table = "++".join(self._table_items)
        cp_constraints = f"constraint table({table}, {self.cipher_id}_table_of_solutions);"

        return cp_declarations, cp_constraints

    def solve_full_two_steps_xor_differential_model(
        self,
        model_type="xor_differential_one_solution",
        weight=-1,
        fixed_variables=[],
        first_step_solver_name=SOLVER_DEFAULT,
        second_step_solver_name=SOLVER_DEFAULT,
        nmax=2,
        repetition=1,
        num_of_processors=None,
        timelimit=None,
    ):
        """
        Return the solution of the model for an SPN cipher.

        INPUT:

        - ``weight`` -- **integer** (default: `-1`); a specific weight. If set to non-negative integer, fixes the XOR
          trail weight.
        - ``fixed_variables`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in standard
          format
        - ``first_step_solver_name`` -- **string** (default: `None`); the solver to call for the first step
        - ``second_step_solver_name`` -- **string** (default: `None`); the solver to call for the second step
        - ``nmax`` -- **integer** (default: `2`); the minimum number of addends for which new xor components are NOT
          added when considering additional xor constraints
        - ``repetition`` -- **integer** (default: `1`); the number of times the procedure for creating new xor
          components will be repeated.
        - ``num_of_processors`` -- **integer** (default: None); the number of cores to use
        - ``timelimit`` -- **integer** (default: None); the time limit for the solver in seconds

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_trail_search_fixing_number_of_active_sboxes_model import (
            ....: MznXorDifferentialFixingNumberOfActiveSboxesModel)
            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: cp = MznXorDifferentialFixingNumberOfActiveSboxesModel(aes)
            sage: fixed_variables = [set_fixed_variables('key', 'not_equal', list(range(128)),
            ....: integer_to_bit_list(0, 128, 'little'))]
            sage: cp.solve_full_two_steps_xor_differential_model('xor_differential_one_solution', -1, fixed_variables, 'chuffed', 'chuffed') # random
            1
            {'cipher': 'aes_block_cipher_k128_p128_o128_r2',
              ...
             'total_weight': '6.0',
             'building_time': 3.7489726543426514}
        """
        self.initialise_model()
        possible_sboxes = 0
        if weight > 0:
            possible_sboxes = self.find_possible_number_of_active_sboxes(weight)
            if not possible_sboxes:
                raise ValueError("There are no trails with the fixed weight!")

        start = tm.time()
        self.build_xor_differential_trail_first_step_model(weight, fixed_variables, nmax, repetition, possible_sboxes)
        end = tm.time()
        build_time = end - start
        first_step_solution, solve_time = self.solve_model(
            "xor_differential_first_step", first_step_solver_name, num_of_processors, timelimit
        )
        start = tm.time()
        self.build_xor_differential_trail_second_step_model(weight, fixed_variables)
        end = tm.time()
        build_time += end - start

        for i in range(len(CP_SOLVERS_EXTERNAL)):
            if second_step_solver_name == CP_SOLVERS_EXTERNAL[i]["solver_name"]:
                command_options = deepcopy(CP_SOLVERS_EXTERNAL[i]["keywords"]["command"])

        for attempt in range(10000):
            if weight == -1:
                start = tm.time()
                self.transform_first_step_model(attempt, first_step_solution[0])
                end = tm.time()
                build_time += end - start
                first_step_all_solutions, solve_first_step_time = self.solve_model(
                    "xor_differential_first_step_find_all_solutions", first_step_solver_name
                )
                solve_time += solve_first_step_time
                table_of_solutions = self.generate_table_of_solutions(first_step_all_solutions)
                command_options["options"].insert(0, "-a")
            elif model_type == "xor_differential_all_solutions":
                table_of_solutions = self.generate_table_of_solutions(first_step_solution)
                command_options["options"].insert(0, "-a")
            else:
                table_of_solutions = self.generate_table_of_solutions(first_step_solution)
            if num_of_processors is not None:
                command_options["options"].insert(0, f"-p {num_of_processors}")
            if timelimit is not None:
                command_options["options"].append(["--time-limit", str(timelimit)])
            command = []
            for key in command_options["format"]:
                command.extend(command_options[key])

            model = table_of_solutions + "\n" + "\n".join(self._model_constraints) + "\n"
            solver_process = subprocess.run(command, input=model, capture_output=True, text=True)
            if solver_process.returncode < 0:
                raise ValueError("something went wrong with solver subprocess... sorry!")

            solver_output = solver_process.stdout.splitlines()

            if any(UNSATISFIABLE in line for line in solver_output) and weight not in (-1, 0):
                return UNSATISFIABLE

            time, memory, components_values, total_weight = self._parse_solver_output(
                solver_output, model_type, False, True, second_step_solver_name
            )

            solutions = self.get_solutions_dictionaries_with_build_time(
                build_time, components_values, memory, second_step_solver_name, time, total_weight
            )

            return solutions

    def solve_model(self, model_type, solver_name=SOLVER_DEFAULT, num_of_processors=None, timelimit=None):
        """
        Return the solution of the model.

        INPUT:

        - ``model_type`` -- **string**; the model to solve:

            * 'xor_differential_first_step'
            * 'xor_differential_first_step_find_all_solutions'
        - ``solver_name`` -- **string** (default: `None`); the name of the solver.
          See also :meth:`MznModel.solver_names`.

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_trail_search_fixing_number_of_active_sboxes_model import (
            ....: MznXorDifferentialFixingNumberOfActiveSboxesModel)
            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: cp = MznXorDifferentialFixingNumberOfActiveSboxesModel(aes)
            sage: fixed_variables = [set_fixed_variables('key', 'not_equal', list(range(128)),
            ....: integer_to_bit_list(0, 128, 'little'))]
            sage: cp.build_xor_differential_trail_first_step_model(-1, fixed_variables)
            sage: cp.solve_model('xor_differential_first_step', 'chuffed') # random
            ['1',
             ' table_of_solution_length = 40',
             ' xor_0_0[0] = 0',
             ...
             '0',
             '----------',
             '==========',
             0.19837307929992676)]
        """
        start = tm.time()
        for i in range(len(CP_SOLVERS_EXTERNAL)):
            if solver_name == CP_SOLVERS_EXTERNAL[i]["solver_name"]:
                command_options = deepcopy(CP_SOLVERS_EXTERNAL[i]["keywords"]["command"])

        if model_type == "xor_differential_first_step_find_all_solutions":
            model = "\n".join(self._first_step_find_all_solutions) + "\n"
            command_options["options"].insert(0, "-a")
        else:
            if model_type == "xor_differential_first_step":
                model = "\n".join(self._first_step) + "\n"
            else:
                model = "\n".join(self._model_constraints) + "\n"
        if num_of_processors is not None:
            command_options["options"].insert(0, f"-p {num_of_processors}")
        if timelimit is not None:
            command_options["options"].append(["--time-limit", str(timelimit)])

        command = []
        for key in command_options["format"]:
            command.extend(command_options[key])
        command.remove("--solver-statistics")
        solver_process = subprocess.run(command, input=model, capture_output=True, text=True)
        solution = []
        temp = []
        for c in solver_process.stdout:
            if c == "\n":
                solution.append("".join(temp))
                temp = []
            else:
                temp.append(c)
        if temp:
            solution.append("".join(temp))
        end = tm.time()

        return solution, end - start

    def transform_first_step_model(self, attempt, active_sboxes, weight=-1):
        """
        Return the first step CP model (set of constraints).

        The first step CP model for an SPN cipher for finding all solutions fixing the number of active S-boxes and
        outputs it in a file.

        INPUT:

        - ``attempt`` -- **integer**; the ordinal number of the attempt while looping for two steps search of
          differential trails
        - ``active_sboxes`` -- **integer**; the number of active S-boxes in the trail
        - ``weight`` -- **integer** (default: `-1`); the total weight. If negative, no constraints on the weight is
          added

        EXAMPLES::

            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_trail_search_fixing_number_of_active_sboxes_model import (
            ....:     MznXorDifferentialFixingNumberOfActiveSboxesModel,
            ....: )
            sage: from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: aes = AESBlockCipher(number_of_rounds=2)
            sage: cp = MznXorDifferentialFixingNumberOfActiveSboxesModel(aes)
            sage: fixed_variables = [set_fixed_variables('key', 'not_equal', range(128), integer_to_bit_list(0, 128, 'little'))]
            sage: cp.build_xor_differential_trail_first_step_model(-1, fixed_variables)
            sage: first_step_solution, solve_time = cp.solve_model('xor_differential_first_step','chuffed')
            sage: cp.transform_first_step_model(0, first_step_solution[0])
            sage: first_step_solution[0]
            '1'
        """
        self._first_step_find_all_solutions = []
        for line in self._first_step:
            if ": number_of_active_sBoxes;" in line:
                if weight != -1:
                    possible_sboxes = self.find_possible_number_of_active_sboxes(weight)
                    self._first_step_find_all_solutions += [f"var {str(possible_sboxes)}:number_of_active_sBoxes;"]
                else:
                    self._first_step_find_all_solutions += [
                        f"var int:number_of_active_sBoxes = {int(active_sboxes) + attempt};"
                    ]
            elif "solve minimize" in line:
                self._first_step_find_all_solutions += [SOLVE_SATISFY]
                new_constraint = (
                    'output[show(number_of_active_sBoxes) ++ "\\n" ++ " table_of_solution_length = '
                    '"++ show(table_of_solutions_length) ++ "\\n" ++'
                )
                for i in range(len(self.input_sbox)):
                    new_constraint = (
                        f'{new_constraint}" {self.input_sbox[i][0]} = "++ show({self.input_sbox[i][0]})++ "\\n" ++'
                    )
                self._first_step_find_all_solutions += [new_constraint[:-2] + "];\n"]
                break
            else:
                self._first_step_find_all_solutions += [line]

    def update_sbox_ddt_valid_probabilities(self, component, valid_probabilities):
        input_size = int(component.input_bit_size)
        output_id_link = component.id
        super().update_sbox_ddt_valid_probabilities(component, valid_probabilities)
        input_id_link = component.input_id_links[0]
        input_bit_positions = component.input_bit_positions[0]
        all_inputs = [f"{input_id_link}[{position}]" for position in input_bit_positions]
        for i in range(input_size // self.word_size):
            ineq_left_side = "+".join([f"{all_inputs[i * self.word_size + j]}" for j in range(self.word_size)])
            new_declaration = f"constraint ({ineq_left_side} > 0) = word_{output_id_link}[{i}];"
            self._cp_xor_differential_constraints.append(new_declaration)
        self._cp_xor_differential_constraints.append(
            f"array[0..{input_size // self.word_size - 1}] of var 0..1: word_{output_id_link};"
        )
        self._table_items.append(f"[word_{output_id_link}[s] | s in 0..{input_size // self.word_size - 1}]")
