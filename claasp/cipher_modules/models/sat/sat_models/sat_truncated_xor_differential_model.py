from claasp.cipher_modules.models.sat.sat_model import SatModel


class SatTruncatedXorDifferentialModel(SatModel):
    def __init__(self, cipher, counter='sequential', compact=False):
        super().__init__(cipher, counter, compact)

    @staticmethod
    def fix_variables_value_constraints(fixed_variables=[]):
        """
        Return constraints for fixed variables

        Return lists of variables and clauses for fixing variables in semi
        deterministic truncated XOR differential model.

        .. SEEALSO::

           :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        INPUT:

        - ``fixed_variables`` -- **list** (default: `[]`); variables in default format

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.sat.sat_models.sat_semi_deterministic_truncated_xor_differential_model import SatSemiDeterministicTruncatedXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: sat = SatSemiDeterministicTruncatedXorDifferentialModel(speck)
            sage: fixed_variables = [{
            ....:    'component_id': 'plaintext',
            ....:    'constraint_type': 'equal',
            ....:    'bit_positions': [0, 1, 2, 3],
            ....:    'bit_values': [1, 0, 1, 1]
            ....: }, {
            ....:    'component_id': 'ciphertext',
            ....:    'constraint_type': 'not_equal',
            ....:    'bit_positions': [0, 1, 2, 3],
            ....:    'bit_values': [2, 1, 1, 0]
            ....: }]
            sage: list_of_constraints = SatSemiDeterministicTruncatedXorDifferentialModel.fix_variables_value_constraints(fixed_variables)
            sage: expected_set_of_constraints = set(['-plaintext_0_0',
            ....: 'plaintext_0_1',
            ....: '-plaintext_1_0',
            ....: '-plaintext_1_1',
            ....: '-plaintext_2_0',
            ....: 'plaintext_2_1',
            ....: '-plaintext_3_0',
            ....: 'plaintext_3_1',
            ....: '-ciphertext_0_0 ciphertext_0_1',
            ....: '-ciphertext_0_0 -ciphertext_0_1',
            ....: 'ciphertext_1_0 -ciphertext_1_1 ciphertext_2_0 -ciphertext_2_1 ciphertext_3_0 ciphertext_3_1'])
            sage: set(list_of_constraints) == expected_set_of_constraints
            True
        """
        constraints = []
        for variable in fixed_variables:
            component_id = variable['component_id']
            is_equal = (variable['constraint_type'] == 'equal')
            bit_positions = variable['bit_positions']
            bit_values = variable['bit_values']
            variables_ids = []
            all_values_are_2 = all(v == 2 for v in bit_values)

            for position, value in zip(bit_positions, bit_values):
                false_sign = '-' * is_equal
                true_sign = '-' * (not is_equal)
                if value == 0:
                    variables_ids.append(f'{false_sign}{component_id}_{position}_0')
                    variables_ids.append(f'{false_sign}{component_id}_{position}_1')
                elif value == 1:
                    variables_ids.append(f'{false_sign}{component_id}_{position}_0')
                    variables_ids.append(f'{true_sign}{component_id}_{position}_1')
                elif value == 2:
                    if not is_equal:
                        # Forbid (1,0) and ensure mutual exclusion of (1,1)
                        constraints.append(f'-{component_id}_{position}_0 {component_id}_{position}_1')
                        constraints.append(f'-{component_id}_{position}_0 -{component_id}_{position}_1')
                    else:
                        variables_ids.append(f'{true_sign}{component_id}_{position}_0')

            if is_equal:
                constraints.extend(variables_ids)
            else:
                if all_values_are_2:
                    # Require at least one (0,1) tuple
                    clause = ' '.join([f'{component_id}_{position}_1' for position in bit_positions])
                    constraints.append(clause)
                else:
                    joined_clause = ' '.join(variables_ids)
                    if joined_clause:
                        constraints.append(joined_clause)

        return constraints

    def _build_unknown_variable_constraints(self, number_of_unknowns_per_component):
        variables = []
        constraints = []
        for component_id in list(number_of_unknowns_per_component.keys()):
            if component_id in self._cipher.get_all_components_ids():
                set_to_be_minimized = []
                set_to_be_minimized.extend([bit_id for bit_id in self._variables_list
                                            if bit_id.startswith(component_id) and bit_id.endswith("_0")])
                number_of_unknowns_per_component = number_of_unknowns_per_component[component_id]
                unknown_variables, unknown_constraints = self._sequential_counter_algorithm(
                    set_to_be_minimized,
                    number_of_unknowns_per_component,
                    f'unknown_vars_for_{component_id}'
                )

                variables.extend(unknown_variables)
                constraints.extend(unknown_constraints)
            else:
                raise ValueError(f'Component {component_id} not found in number_of_unknowns_per_component')

        return variables, constraints
