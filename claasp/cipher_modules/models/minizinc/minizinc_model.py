
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


from datetime import timedelta

from minizinc import Instance, Model, Solver


class MinizincModel:
    """
    Build and solve MiniZinc models.

    With this class, you can build MiniZinc models using the methods build_*.
    And to solve them, you can use the MiniZinc command line, the MiniZinc IDE, or the class method `solve`.
    """

    def __init__(self, cipher, window_size_list=None, probability_weight_per_round=None, sat_or_milp='sat'):
        """
        Initialise.

        INPUT:

        - ``cipher`` -- **Cipher object**; instance of cipher
        - ``window_size_list`` -- **list** (default: `None`)
        - ``probability_weight_per_round`` -- **list** (default: `None`)
        - ``sat_or_milp`` -- **string** (default: `sat`)
        """
        if sat_or_milp not in ['sat', 'milp']:
            raise ValueError("Allowed value for sat_or_milp parameter is either sat or milp")

        self.sat_or_milp = sat_or_milp
        if self.sat_or_milp == "sat":
            self.data_type = "bool"
            self.true_value = "true"
            self.false_value = "false"
        else:
            self.data_type = "0..1"
            self.true_value = "1"
            self.false_value = "0"

        self.probability_vars = []
        self.carries_vars = []
        self.mzn_comments = []
        self.intermediate_constraints_array = []
        self.mzn_output_directives = []
        self.mzn_carries_output_directives = []
        self.input_postfix = "x"
        self.output_postfix = "y"
        self.window_size_list = window_size_list
        self.probability_weight_per_round = probability_weight_per_round
        self._cipher = cipher
        self._variables_list = []
        self._model_constraints = []
        self.carries_vars = []
        if probability_weight_per_round and len(probability_weight_per_round) != self._cipher.number_of_rounds:
            raise ValueError("probability_weight_per_round size must be equal to cipher_number_of_rounds")

        self.probability_modadd_vars_per_round = [[] for _ in range(self._cipher.number_of_rounds)]

        if window_size_list and len(window_size_list) != self._cipher.number_of_rounds:
            raise ValueError("window_size_list size must be equal to cipher_number_of_rounds")

    def add_comment(self, comment):
        """
        Write a 'comment' at the beginning of the model.

        INPUT:

        - ``comment`` -- **string**; string with the comment to be added
        """
        self.mzn_comments.append("% " + comment)

    def add_constraint_from_str(self, str_constraint):
        self._model_constraints.append(str_constraint)

    def add_output_comment(self, comment):
        self.mzn_output_directives.append(f'output [\"Comment: {comment}\", \"\\n\"];')

    def fix_variables_value_constraints(self, fixed_variables=[]):
        """
        Return a list of constraints that fix the input variables to a specific value.

        INPUT:

        - ``fixed_variables`` -- **list** (default: `[]`); the variables to be fixed in standard format

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.cipher_modules.models.minizinc.minizinc_models.minizinc_xor_differential_model import MinizincXorDifferentialModel
            sage: from claasp.ciphers.block_ciphers.raiden_block_cipher import RaidenBlockCipher
            sage: raiden = RaidenBlockCipher(number_of_rounds=1)
            sage: minizinc = MinizincXorDifferentialModel(raiden)
            sage: minizinc.build_xor_differential_trail_model()
            sage: fixed_variables = [{
            ....:     'component_id': 'key',
            ....:     'constraint_type': 'equal',
            ....:     'bit_positions': [0, 1, 2, 3],
            ....:     'bit_values': [0, 1, 0, 1]
            ....: }]
            sage: minizinc.fix_variables_value_constraints(fixed_variables)[0]
            'constraint key_y0 = 0;'

            sage: fixed_variables = [{ 'component_id': 'plaintext',
            ....:     'constraint_type': 'sum',
            ....:     'bit_positions': [0, 1, 2, 3],
            ....:     'operator': '>',
            ....:     'value': '0' }]
            sage: minizinc.fix_variables_value_constraints(fixed_variables)[0]
            'constraint plaintext_y0+plaintext_y1+plaintext_y2+plaintext_y3>0;'
        """
        def equal_operator(constraints_, fixed_variables_object_):
            component_name = fixed_variables_object_["component_id"]
            for i in range(len(fixed_variables_object_["bit_positions"])):
                bit_position = fixed_variables_object_["bit_positions"][i]
                bit_value = fixed_variables_object_["bit_values"][i]
                constraints_.append(f'constraint {component_name}_y{bit_position} = {bit_value};')
                if 'intermediate_output' in component_name or 'cipher_output' in component_name:
                    constraints_.append(f'constraint {component_name}_x{bit_position}'
                                        f'='
                                        f'{bit_value};')

        def sum_operator(constraints_, fixed_variables_object_):
            component_name = fixed_variables_object_["component_id"]
            bit_positions = []
            for i in range(len(fixed_variables_object_["bit_positions"])):
                bit_position = fixed_variables_object_["bit_positions"][i]
                bit_var_name_position = f'{component_name}_y{bit_position}'
                bit_positions.append(bit_var_name_position)
            constraints_.append(f'constraint {"+".join(bit_positions)}'
                                f'{fixed_variables_object_["operator"]}'
                                f'{fixed_variables_object_["value"]};')

        constraints = []

        for fixed_variables_object in fixed_variables:
            if fixed_variables_object["constraint_type"] == "equal":
                equal_operator(constraints, fixed_variables_object)
            elif fixed_variables_object["constraint_type"] == "sum":
                sum_operator(constraints, fixed_variables_object)

        return constraints

    def output_probability_per_round(self):
        for mzn_probability_modadd_vars in self.probability_modadd_vars_per_round:
            mzn_probability_vars_per_round = "++".join(mzn_probability_modadd_vars)
            self.mzn_output_directives.append(f'output ["\\n"++"Probability {mzn_probability_vars_per_round}:'
                                              f' "++show(sum({mzn_probability_vars_per_round}))++"\\n"];')

    def solve(self, solver_name=None, timeout_in_seconds_=30,
              processes_=4, nr_solutions_=None, random_seed_=None,
              all_solutions_=False, intermediate_solutions_=False,
              free_search_=False, optimisation_level_=None):
        """
        Solve the model passed in `str_model_path` by using `MiniZinc` and `str_solver``.

        INPUT:

            - ``model_type`` -- **string**; the type of the model that has been solved
            - ``solver_name`` -- **string** (default: `None`); name of the solver to be used together with MiniZinc
            - ``timeout_in_seconds_`` -- **integer** (default: `30`); time in seconds to interrupt the solving process
            - ``processes_`` -- **integer** (default: `4`); set the number of processes the solver can use. (Only
              available when the ``-p`` flag is supported by the solver)
            - ``nr_solutions_`` -- **integer** (default: `None`); the requested number of solution. (Only available on
              satisfaction problems and when the ``-n`` flag is supported by the solver)
            - ``random_seed_`` -- **integer** (default: `None`); set the random seed for solver. (Only available when
              the ``-r`` flag is supported by the solver)
            - ``intermediate_solutions_`` -- **boolean** (default: `False`); request the solver to output any
              intermediate solutions that are found during the solving process. (Only available on optimisation
              problems and when the ``-a`` flag is supported by the solver)
            - ``all_solutions_`` -- **boolean** (default: `False`); request to solver to find all solutions. (Only
              available on satisfaction problems and when the ``-a`` flag is supported by the solver)
            - ``free_search`` -- **boolean** (default: `False`); allow the solver to ignore the search definition within
              the instance (Only available when the ``-f`` flag is supported by the solver)
            - ``optimisation_level_`` -- **integer** (default: `None`); set the MiniZinc compiler optimisation level

              - 0: Disable optimisation
              - 1: Single pass optimisation (default)
              - 2: Flatten twice to improve flattening decisions
              - 3: Perform root-node-propagation
              - 4: Probe bounds of all variables at the root node
              - 5: Probe values of all variables at the root node

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.minizinc.minizinc_models.minizinc_xor_differential_model import MinizincXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=5, block_bit_size=32, key_bit_size=64)
            sage: minizinc = MinizincXorDifferentialModel(speck)
            sage: bit_positions = [i for i in range(speck.output_bit_size)]
            sage: bit_positions_key = list(range(64))
            sage: fixed_variables = [{ 'component_id': 'plaintext',
            ....:     'constraint_type': 'sum',
            ....:     'bit_positions': bit_positions,
            ....:     'operator': '>',
            ....:     'value': '0' }]
            sage: fixed_variables.append({ 'component_id': 'key',
            ....:     'constraint_type': 'sum',
            ....:     'bit_positions': bit_positions_key,
            ....:     'operator': '=',
            ....:     'value': '0' })
            sage: minizinc.build_xor_differential_trail_model(-1, fixed_variables)
            sage: result = minizinc.solve('Xor')
            sage: result.statistics['nSolutions']
            1
        """
        constraints = self._model_constraints
        variables = self._variables_list
        mzn_model_string = "\n".join(constraints) + "\n".join(variables)
        solver_name_mzn = Solver.lookup(solver_name)
        bit_mzn_model = Model()
        bit_mzn_model.add_string(mzn_model_string)
        instance = Instance(solver_name_mzn, bit_mzn_model)
        result = instance.solve(processes=processes_, timeout=timedelta(seconds=int(timeout_in_seconds_)),
                                nr_solutions=nr_solutions_, random_seed=random_seed_, all_solutions=all_solutions_,
                                intermediate_solutions=intermediate_solutions_, free_search=free_search_,
                                optimisation_level=optimisation_level_)

        return result

    def write_minizinc_model_to_file(self, file_path, prefix=""):
        """
        Write the MiniZinc model into a file inside file_path.

        INPUT:

        - ``file_path`` -- **string**; the path of the file that will contain the model
        - ``prefix`` -- **str** (default: ``)
        """
        model_string = "\n".join(self.mzn_comments) + "\n".join(self._variables_list) +  \
                       "\n".join(self._model_constraints) + "\n".join(self.mzn_output_directives) + \
                       "\n".join(self.mzn_carries_output_directives)
        if prefix == "":
            filename = f'{file_path}/{self.cipher_id}_mzn_{self.sat_or_milp}.mzn'
        else:
            filename = f'{file_path}/{prefix}_{self.cipher_id}_mzn_{self.sat_or_milp}.mzn'

        f = open(filename, "w")
        f.write(model_string)
        f.close()

    @property
    def cipher(self):
        return self._cipher

    @property
    def cipher_id(self):
        return self._cipher.id

    @property
    def model_constraints(self):
        """
        Return the model specified by ``model_type``.

        If the key refers to one of the available solver, Otherwise will raise a KeyError exception.

        INPUT:

        - ``model_type`` -- **string**; the model to retrieve

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.minizinc.minizinc_model import MinizincModel
            sage: speck = SpeckBlockCipher(number_of_rounds=4)
            sage: minizinc = MinizincModel(speck)
            sage: minizinc.model_constraints('xor_differential')
            Traceback (most recent call last):
            ...
            ValueError: No model generated
        """
        if not self._model_constraints:
            raise ValueError(f'No model generated')
        return self._model_constraints
