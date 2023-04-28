
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


from claasp.cipher_modules.models.milp.milp_model import MilpModel
from claasp.name_mappings import (INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, LINEAR_LAYER, WORD_OPERATION, MIX_COLUMN)


class MilpCipherModel(MilpModel):

    def __init__(self, cipher, n_window_heuristic=None):
        super().__init__(cipher, n_window_heuristic)

    def build_cipher_model(self, fixed_variables=[]):
        """
        Build the cipher model.

        Cannot be done with MILP, non-linear components cannot be modeled with only inequalities.

        INPUT:

        - ``fixed_variables`` -- **list** (default: `[]`); dictionaries containing the variables to be fixed in
          standard format

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.cipher_modules.models.milp.milp_models.milp_cipher_model import MilpCipherModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=22)
            sage: milp = MilpCipherModel(speck)
            sage: milp.init_model_in_sage_milp_class()
            sage: milp.build_cipher_model()
            ...
        """
        variables = []
        self._variables_list = []
        constraints = self.fix_variables_value_constraints(fixed_variables)
        component_types = [CIPHER_OUTPUT, INTERMEDIATE_OUTPUT, LINEAR_LAYER, MIX_COLUMN, WORD_OPERATION]
        operation_types = ['NOT', 'ROTATE', 'SHIFT', 'XOR']
        self._model_constraints = constraints

        for component in self._cipher.get_all_components():
            operation = component.description[0]
            if component.type not in component_types or (
                    WORD_OPERATION == component.type and operation not in operation_types):
                print(f'{component.id} not yet implemented')
            else:
                variables, constraints = component.milp_constraints(self)

            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)
