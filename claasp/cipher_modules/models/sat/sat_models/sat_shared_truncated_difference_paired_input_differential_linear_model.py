import time
from copy import deepcopy

from claasp.cipher_modules.models.sat import solvers
from claasp.cipher_modules.models.sat.sat_model import SatModel
from claasp.cipher_modules.models.sat.sat_models.sat_bitwise_deterministic_truncated_xor_differential_model import \
    SatBitwiseDeterministicTruncatedXorDifferentialModel
from claasp.cipher_modules.models.sat.sat_models.sat_xor_linear_model import SatXorLinearModel
from claasp.cipher_modules.models.sat.utils import utils as sat_utils, constants
from claasp.cipher_modules.models.sat.utils.utils import _generate_component_model_types, \
    _update_component_model_types_for_linear_components
from claasp.cipher_modules.models.utils import set_component_solution, get_bit_bindings
from claasp.name_mappings import INPUT_KEY, INPUT_PLAINTEXT, INPUT_TWEAK


class SharedTruncatedDifferencePairedInputDifferentialLinearModel(SatModel):
    """
    Model for finding high-order differential-linear distinguishers based on SAT encoding.

    This model combines three propagation techniques:
    - SharedDifferencePairedInputDifferentialModel,
    - and XOR linear mask propagation.

    It is specifically designed to search for trails satisfying the following condition:

    .. MATH::

        \lambda(f(x) \oplus f(x + a) \oplus f(y) \oplus f(y + a)) = 0

    where :math:`\lambda(.)` represents the application of a linear mask and the computation of the parity (i.e., inner product).

    """

    def __init__(self, cipher, dict_of_components):
        """
        Initializes the model with cipher and components.

        INPUT:
        - ``cipher`` -- **object**; The cipher model used in the SAT-based differential trail search.
        - ``dict_of_components`` -- **dict**; Dictionary mapping component IDs to their respective models and types.

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_shared_difference_paired_input_differential_linear_model import SharedDifferencePairedInputDifferentialLinearModel
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: component_dict = {'middle_part_components': [], 'bottom_part_components': speck.get_components_in_round(4)}
            sage: model = SharedDifferencePairedInputDifferentialLinearModel(speck, component_dict)
        """
        bottom_part_components = dict_of_components["bottom_part_components"]
        component_model_types = _generate_component_model_types(
            cipher, model_type="sat_bitwise_deterministic_truncated_xor_differential_constraints"
        )
        _update_component_model_types_for_linear_components(component_model_types, bottom_part_components)

        self.dict_of_components = component_model_types
        self.truncated_components = self._get_components_by_type(
            'sat_bitwise_deterministic_truncated_xor_differential_constraints'
        )
        new_truncated_components = []
        truncated_components = deepcopy(self.truncated_components)
        for truncated_component_dict in truncated_components:
            truncated_component_id = truncated_component_dict["component_id"]

            truncated_component = truncated_component_dict["component_object"]
            round_number = cipher.get_round_from_component_id(truncated_component_id)
            truncated_component_copy = deepcopy(truncated_component)
            truncated_component_copy._id = 'cipher1_' + truncated_component._id

            new_input_id_links = [
                f'cipher1_{input_id_link}' if input_id_link not in cipher.inputs else input_id_link
                for input_id_link in truncated_component_copy.input_id_links
            ]

            truncated_component_copy.set_input_id_links(new_input_id_links)

            cipher._rounds.rounds[round_number]._components.extend([truncated_component_copy])
            new_truncated_components.append({
                'component_id': truncated_component_copy.id,
                'component_object': truncated_component_copy,
                "model_type": "sat_bitwise_deterministic_truncated_xor_differential_constraints"
            })
        self.truncated_components.extend(new_truncated_components)
        self.new_truncated_components = new_truncated_components
        self.linear_components = self._get_components_by_type('sat_xor_linear_mask_propagation_constraints')
        self.bit_bindings, self.bit_bindings_for_intermediate_output = get_bit_bindings(cipher, '_'.join)
        super().__init__(cipher, "sequential", False)

    def _get_components_by_type(self, model_type):
        """
        Retrieves components based on their model type.

        INPUT:
        - ``model_type`` -- **str**; The model type to filter components.

        RETURN:
        - **list**; A list of components of the specified type.
        """
        return [component for component in self.dict_of_components if component['model_type'] == model_type]

    def _get_regular_xor_differential_components_in_border(self):
        """
        Retrieves differential components that are connected to linear components (border components).

        RETURN:
        - **list**; A list of regular components at the border.
        """
        regular_component_ids = {item['component_id'] for item in self.regular_components}
        border_components = []

        for linear_component in self.linear_components:
            component_obj = self.cipher.get_component_from_id(linear_component['component_id'])
            for input_id in component_obj.input_id_links:
                if input_id in regular_component_ids:
                    border_components.append(input_id)

        return list(set(border_components))

    def _get_connecting_constraints1(self):
        """
        Adds constraints for connecting regular and linear components.
        """

        def is_any_string_in_list_substring_of_string(string, string_list):
            return any(s in string for s in string_list)

        border_components = self._get_regular_xor_differential_components_in_border()
        linear_component_ids = [item['component_id'] for item in self.linear_components]

        for component_id in border_components:
            component = self.cipher.get_component_from_id(component_id)
            for idx in range(component.output_bit_size):
                linear_component = f'{component_id}_{idx}_o'
                component_successors = self.bit_bindings[linear_component]

                for component_successor in component_successors:
                    length_component_successor = len(component_successor)
                    component_successor_id = component_successor[:length_component_successor - 2]

                    if is_any_string_in_list_substring_of_string(component_successor_id, linear_component_ids):
                        # TODO: update method name get_cnf_truncated_linear_constraints for something more general
                        constraints = sat_utils.get_cnf_truncated_linear_constraints(
                            component_successor, f'{component_id}_{idx}'
                        )
                        self._model_constraints.extend(constraints)
                        constraints = sat_utils.get_cnf_truncated_linear_constraints(
                            component_successor, f'cipher1_{component_id}_{idx}'
                        )
                        self._model_constraints.extend(constraints)
                        self._variables_list.extend([component_successor, f'{component_id}_{idx}'])

    def _get_truncated_xor_differential_components_in_border(self):
        """
        Retrieves truncated components that are connected to linear components (border components).

        RETURN:
        - **list**; A list of truncated components at the border.
        """
        truncated_component_ids = {item['component_id'] for item in self.truncated_components}
        border_components = []
        for linear_component in self.linear_components:
            component_obj = self.cipher.get_component_from_id(linear_component['component_id'])
            for input_id in component_obj.input_id_links:
                if input_id in truncated_component_ids:
                    border_components.append(input_id)

        return list(set(border_components))

    def _get_connecting_constraints(self):
        """
        Adds constraints for connecting regular, truncated, and linear components.
        """

        def get_component_output_bit_size(component_identifier):
            component_output_bit_size = 0
            if component_identifier not in [INPUT_KEY, INPUT_PLAINTEXT, INPUT_TWEAK]:
                component = self.cipher.get_component_from_id(component_identifier)
                component_output_bit_size = component.output_bit_size
            else:
                for cipher_index, cipher_input in enumerate(self._cipher.inputs):
                    if component_identifier == cipher_input:
                        component_output_bit_size = self._cipher.inputs_bit_size[cipher_index]
                        break
            return component_output_bit_size

        def is_any_string_in_list_substring_of_string(string, string_list):
            # Check if any string in the list is a substring of the given string
            return any(s in string for s in string_list)

        border_components = self._get_truncated_xor_differential_components_in_border()

        linear_component_ids = [item['component_id'] for item in self.linear_components]

        for component_id in border_components:
            component = self.cipher.get_component_from_id(component_id)
            for idx in range(component.output_bit_size):
                truncated_component = f'{component_id}_{idx}_o'
                component_successors = self.bit_bindings[truncated_component]
                for component_successor in component_successors:
                    length_component_successor = len(component_successor)
                    component_successor_id = component_successor[:length_component_successor - 2]

                    if is_any_string_in_list_substring_of_string(component_successor_id, linear_component_ids):
                        constraints = sat_utils.get_cnf_truncated_linear_constraints(
                            component_successor, f'{component_id}_{idx}_0'
                        )
                        self._model_constraints.extend(constraints)
                        constraints = sat_utils.get_cnf_truncated_linear_constraints(
                            component_successor, f'cipher1_{component_id}_{idx}_0'
                        )
                        self._model_constraints.extend(constraints)
                        self._variables_list.extend([component_successor, f'{component_id}_{idx}_0'])

    def _build_weight_constraints(self, weight):
        """
        Builds weight constraints for the model based on the specified weight.

        INPUT:
        - ``weight`` -- **int**; The weight to constrain the search. If set to 0, the hardware variables are negated.

        RETURN:
        - **tuple**; A tuple containing a list of variables and a list of constraints.
        """

        hw_variables = [var_id for var_id in self._variables_list if var_id.startswith('hw_')]

        linear_component_ids = [linear_component["component_id"] for linear_component in self.linear_components]
        hw_linear_variables = []
        for linear_component_id in linear_component_ids:
            for hw_variable in hw_variables:
                if linear_component_id in hw_variable:
                    hw_linear_variables.append(hw_variable)
        hw_variables.extend(hw_linear_variables)
        if weight == 0:
            return [], [f'-{var}' for var in hw_variables]

        return self._sequential_counter(hw_variables, weight, dummy_id='dummy_hw_000')

    def build_shared_truncated_difference_paired_input_differential_model(
            self, weight=-1, fixed_values=None, key_recovery=None
    ):
        """
        Constructs a model to search for differential-linear trails.
        This model is a combination of the SharedDifferencePairedInputDifferentialModel,
        and the linear XOR differential model.

        INPUT:
        - ``weight`` -- **integer** (default: `-1`); specifies the maximum probability weight. If set to a non-negative
        integer, it constrains the search to trails with the fixed probability weight.
        - ``number_of_unknown_variables`` -- **int** (default: None); specifies the upper limit on the number of unknown
        variables allowed in the differential trail.

        EXAMPLES::

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_shared_difference_paired_input_differential_linear_model import SharedDifferencePairedInputDifferentialLinearModel
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: component_dict = {'middle_part_components': [], 'bottom_part_components': speck.get_components_in_round(4)}
            sage: model = SharedDifferencePairedInputDifferentialLinearModel(speck, component_dict)
            sage: model.build_shared_difference_paired_input_differential_model()
            ...
        """
        self.build_generic_sat_model_from_dictionary(self.dict_of_components + self.new_truncated_components)
        constraints = SatXorLinearModel.branch_xor_linear_constraints(self.bit_bindings)
        self._model_constraints.extend(constraints)
        high_order_differential_constraints = []
        for component in self._cipher.get_all_components():
            if (component.id.startswith('cipher1_') and "modadd" in component.id) or (
                    component.id.startswith('cipher1_') and "modsub" in component.id):
                component_copy_id = component.id.split("cipher1_")[1]
                for i in range(component.output_bit_size):
                    # new_constraint_cnf = [
                    #    f'-cipher1_{component_copy_id}_{i})_0 -{component_copy_id}_{i}_0',
                    #    f'-cipher1_{component_copy_id}_{i}_0 {component_copy_id}_{i}_0 -{component_copy_id}_{i}_1',
                    #    f'cipher1_{component_copy_id}_{i}_0 -cipher1_{component_copy_id}_{i}_1 {component_copy_id}_{i}_0 -{component_copy_id}_{i}_1',
                    # ]
                    new_constraint_cnf = [
                        # f'{component_copy_id}_{i}_0 -{component_copy_id}_{i}_1',
                        # f'cipher1_{component_copy_id}_{i}_0 -cipher1_{component_copy_id}_{i}_1',
                        # f'-cipher1_{component_copy_id}_{i}_0 -{component_copy_id}_{i}',
                        f'{component_copy_id}_{i})_0 -{component_copy_id}_{i})_1 cipher1_{component_copy_id}_{i}_0 -cipher1_{component_copy_id}_{i}_0',
                    ]
                    high_order_differential_constraints.extend(new_constraint_cnf)
        self._model_constraints.extend(high_order_differential_constraints)

        if weight != -1:
            variables, constraints = self._build_weight_constraints(weight)
            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

        if fixed_values is not None:
            constraints = self.fix_variables_value_constraints(
                fixed_values,
                self.truncated_components,
                self.linear_components
            )
            self.model_constraints.extend(constraints)
            self._model_constraints.extend(constraints)

        if key_recovery == True:
            # pnbs = []
            # for i in range(512):
            #    # import pdb; pdb.set_trace()
            #    pnbs.append(f'bottom_fake_plaintext_{i}_0')
            #
            # variables, constraints = self._sequential_counter_algorithm(
            #    pnbs, 1, "dummy_id_for_pnbs", greater_or_equal=True
            # )
            #
            # self._variables_list.extend(variables)
            # self._model_constraints.extend(constraints)

            pnbs = []
            for i in range(128, 384):
                # import pdb; pdb.set_trace()
                pnbs.append(f'bottom_fake_plaintext_{i}_0')

            variables, constraints = self._sequential_counter_algorithm(
                pnbs, 1, "dummy_id_for_pnbs11", greater_or_equal=True
            )

            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

            pnbs = []
            for i in range(512):
                # import pdb; pdb.set_trace()
                pnbs.append(f'bottom_plaintext_{i}_i')

            variables, constraints = self._sequential_counter_algorithm(
                pnbs, 1, "dummy_id_for_output_mask", greater_or_equal=True
            )
            # [xxxx for xxxx in self._variables_list if xxxx.startswith('bottom_plaintext_')]
            # import ipdb; ipdb.set_trace()
            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

            pnbs = []
            for i in range(512):
                # import pdb; pdb.set_trace()
                pnbs.append(f'bottom_intermediate_output_3_24_{i}_0')
            #
            variables, constraints = self._sequential_counter_algorithm(
                pnbs, 32, "dummy_id_jaslkjksasaklj3", greater_or_equal=False
            )
            # [xxxx for xxxx in self._variables_list if xxxx.startswith('bottom_plaintext_')]
            # import ipdb; ipdb.set_trace()
            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)
            #
            pnbs = []
            for i in range(512):
                # import pdb; pdb.set_trace()
                pnbs.append(f'cipher1_bottom_intermediate_output_3_24_{i}_0')
            #
            variables, constraints = self._sequential_counter_algorithm(
                pnbs, 32, "dummy_id_jaslkjksasaklj4", greater_or_equal=False
            )
            # [xxxx for xxxx in self._variables_list if xxxx.startswith('bottom_plaintext_')]
            # import ipdb; ipdb.set_trace()
            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

        self._get_connecting_constraints()

    @staticmethod
    def fix_variables_value_constraints(
            fixed_variables, truncated_components=None, linear_components=None):
        """
        Imposes fixed value constraints on variables within differential, truncated, and linear components.

        INPUT:
        - ``fixed_variables`` -- **list** (default: `[]`); specifies a list of variables that should be fixed to specific values. Each entry in the list should be a dictionary representing constraints for specific components, written in the CLAASP constraining syntax.
        - ``regular_components`` -- **list** (default: None); list of regular components.
        - ``truncated_components`` -- **list** (default: None); list of truncated components.
        - ``linear_components`` -- **list** (default: None); list of linear components.

        RETURN:
        - **list**; A list of constraints for the model.
        """
        truncated_vars = []
        linear_vars = []

        for var in fixed_variables:
            component_id = var["component_id"]

            if component_id in [comp["component_id"] for comp in linear_components] and 2 in var['bit_values']:
                raise ValueError("The fixed value in a linear component cannot be 2")

            if component_id in [comp["component_id"] for comp in truncated_components]:
                truncated_vars.append(var)
            elif component_id in [comp["component_id"] for comp in linear_components]:
                linear_vars.append(var)
            else:
                truncated_vars.append(var)

        truncated_constraints = SatBitwiseDeterministicTruncatedXorDifferentialModel.fix_variables_value_constraints(
            truncated_vars)
        linear_constraints = SatXorLinearModel.fix_variables_value_xor_linear_constraints(linear_vars)

        return truncated_constraints + linear_constraints

    def _parse_solver_output(self, variable2value):
        """
        Parses the solver's output and returns component solutions and total weight. The total weight is the sum of the
        probability weight of the top part (differential part) and the correlation weight of the bottom part (linear part).
        Note that the weight of the middle part is deterministic.

        INPUT:
        - ``variable2value`` -- **dict**; mapping of solver's variables to their values.

        RETURN:
        - **tuple**; a tuple containing the dictionary of component solutions and the total weight.
        """
        components_solutions = self._get_cipher_inputs_components_solutions_double_ids(variable2value)
        total_weight_diff = 0
        total_weight_lin = 0

        for component in self._cipher.get_all_components():
            # import ipdb; ipdb.set_trace()
            if component.id in [d['component_id'] for d in self.truncated_components]:
                value = self._get_component_value_double_ids(component, variable2value)
                components_solutions[component.id] = set_component_solution(value, weight=0)

            elif component.id in [d['component_id'] for d in self.linear_components]:
                hex_value = self._get_component_hex_value(component, constants.OUTPUT_BIT_ID_SUFFIX, variable2value)
                weight = self.calculate_component_weight(component, constants.OUTPUT_BIT_ID_SUFFIX, variable2value)
                total_weight_lin += weight
                components_solutions[component.id] = set_component_solution(hex_value, weight)

        return components_solutions, total_weight_diff + 2 * total_weight_lin

    def find_one_shared_truncated_difference_paired_input_differential_linear_trail_with_fixed_weight(
            self, weight, fixed_values=[], solver_name=solvers.SOLVER_DEFAULT
    ):
        """
        Finds a high-order differential-linear trail with fixed weight using paired inputs and a shared difference.

        This method searches for trails satisfying:

        .. MATH::

            \lambda(f(x) \oplus f(x + a) \oplus f(y) \oplus f(y + a)) = 0

        where :math:`\lambda(.)` applies a linear mask and computes the parity.

        INPUT:
        - ``weight`` -- **int**; total fixed weight of the trail.
        - ``fixed_values`` -- **list**; constraints for fixing inputs, keys, or outputs.
        - ``solver_name`` -- **str** (default: `solvers.SOLVER_DEFAULT`); SAT solver to use.

        RETURN:
        - **dict**; a solution dictionary returned by the SAT solver.

        EXAMPLES::

            sage: import itertools
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_shared_difference_paired_input_differential_linear_model import SharedDifferencePairedInputDifferentialLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
            sage: speck = SpeckBlockCipher(number_of_rounds=5)
            sage: top_part_components = []
            sage: bottom_part_components = []
            sage: for round_number in range(2):
            ....:     top_part_components.append(speck.get_components_in_round(round_number))
            sage: for round_number in range(2, 5):
            ....:     bottom_part_components.append(speck.get_components_in_round(round_number))
            sage: bottom_part_components = list(itertools.chain(*bottom_part_components))
            sage: bottom_part_components = [component.id for component in bottom_part_components]
            sage: component_model_list = {
            ....:     'bottom_part_components': bottom_part_components
            ....: }
            sage: plaintext = set_fixed_variables(
            ....:     component_id='plaintext',
            ....:     constraint_type='equal',
            ....:     bit_positions=range(32),
            ....:     bit_values=integer_to_bit_list(
            ....:         0x00302000,
            ....:         32,
            ....:         'big'
            ....:     )
            ....: )
            sage: key = set_fixed_variables(
            ....:     component_id='key',
            ....:     constraint_type='equal',
            ....:     bit_positions=range(64),
            ....:     bit_values=integer_to_bit_list(
            ....:         0x0,
            ....:         64,
            ....:         'big'
            ....:     )
            ....: )
            sage: cipher_output_4_12 = set_fixed_variables(
            ....:     component_id='cipher_output_4_12',
            ....:     constraint_type='equal',
            ....:     bit_positions=range(32),
            ....:     bit_values=integer_to_bit_list(
            ....:         0x00040004,
            ....:         32,
            ....:         'big'
            ....:     )
            ....: )
            sage: sat_heterogeneous_model = SharedDifferencePairedInputDifferentialLinearModel(speck, component_model_list)
            sage: trail = sat_heterogeneous_model.find_one_shared_difference_paired_input_differential_linear_trail_with_fixed_weight(
            ....:     weight=11,
            ....:     fixed_values=[
            ....:         key, plaintext, cipher_output_4_12
            ....:     ],
            ....:     solver_name="PARKISSAT_EXT"
            ....: )
            sage: trail["status"]
            'SATISFIABLE'
        """
        start_time = time.time()

        self.build_shared_truncated_difference_paired_input_differential_model(weight)
        constraints = self.fix_variables_value_constraints(
            fixed_values,
            self.truncated_components,
            self.linear_components
        )
        self.model_constraints.extend(constraints)
        pnbs = []
        for i in range(512):
            # import pdb; pdb.set_trace()
            pnbs.append(f'bottom_fake_plaintext_{i}_0')

        variables, constraints = self._sequential_counter_algorithm(
            pnbs, 3, "dummy_id_for_pnbs", greater_or_equal=True
        )

        self._variables_list.extend(variables)
        self._model_constraints.extend(constraints)

        pnbs = []
        for i in range(512):
            # import pdb; pdb.set_trace()
            pnbs.append(f'bottom_plaintext_{i}_i')

        variables, constraints = self._sequential_counter_algorithm(
            pnbs, 5, "dummy_id_for_output_mask", greater_or_equal=True
        )
        # [xxxx for xxxx in self._variables_list if xxxx.startswith('bottom_plaintext_')]
        # import ipdb; ipdb.set_trace()
        self._variables_list.extend(variables)
        self._model_constraints.extend(constraints)

        pnbs = []
        for i in range(512):
            # import pdb; pdb.set_trace()
            pnbs.append(f'bottom_intermediate_output_3_24_{i}_0')
        #
        variables, constraints = self._sequential_counter_algorithm(
            pnbs, 32, "dummy_id_jaslkjksasaklj3", greater_or_equal=False
        )
        # [xxxx for xxxx in self._variables_list if xxxx.startswith('bottom_plaintext_')]
        # import ipdb; ipdb.set_trace()
        self._variables_list.extend(variables)
        self._model_constraints.extend(constraints)
        #
        pnbs = []
        for i in range(512):
            # import pdb; pdb.set_trace()
            pnbs.append(f'cipher1_bottom_intermediate_output_3_24_{i}_0')
        #
        variables, constraints = self._sequential_counter_algorithm(
            pnbs, 32, "dummy_id_jaslkjksasaklj4", greater_or_equal=False
        )
        # [xxxx for xxxx in self._variables_list if xxxx.startswith('bottom_plaintext_')]
        # import ipdb; ipdb.set_trace()
        self._variables_list.extend(variables)
        self._model_constraints.extend(constraints)

        solution = self.solve(
            "SHARED_TRUNCATED_DIFFERENCE_PAIRED_INPUT_DIFFERENTIAL_LINEAR_MODEL", solver_name=solver_name
        )
        # import pdb;
        # pdb.set_trace()
        solution['building_time_seconds'] = time.time() - start_time
        solution['test_name'] = "find_one_shared_difference_paired_input_differential_linear_model_trail"

        return solution

    @property
    def cipher(self):
        """
        Returns the cipher instance associated with the model.

        RETURN:
        - **object**; The cipher object being used in this model.
        """
        return self._cipher
