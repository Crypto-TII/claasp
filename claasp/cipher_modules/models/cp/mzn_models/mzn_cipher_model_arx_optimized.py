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


from claasp.cipher_modules.models.cp.mzn_model import MznModel
from claasp.name_mappings import CIPHER_OUTPUT, INTERMEDIATE_OUTPUT, WORD_OPERATION


class MznCipherModelARXOptimized(MznModel):

    def __init__(self, cipher, sat_or_milp='sat'):
        super().__init__(cipher, sat_or_milp)

    def build_cipher_model(self, fixed_variables=[]):
        """
        Build the cipher model.

        INPUT:

        - ``fixed_variables`` -- **list** (default: `[]`); the variables to be fixed in standard format

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_cipher_model_arx_optimized import MznCipherModelARXOptimized
            sage: speck = SpeckBlockCipher(number_of_rounds=22)
            sage: minizinc = MznCipherModelARXOptimized(speck)
            sage: minizinc.build_cipher_model()
            ...
        """
        self._variables_list = []
        variables = []
        constraints = self.fix_variables_value_constraints_for_ARX(fixed_variables)
        self._model_constraints = constraints
        component_types = [CIPHER_OUTPUT, INTERMEDIATE_OUTPUT, WORD_OPERATION]
        operation_types = ["ROTATE", "SHIFT", "XOR"]

        for component in self._cipher.get_all_components():
            operation = component.description[0]
            if component.type not in component_types or (
                WORD_OPERATION == component.type and operation not in operation_types
            ):
                print(f"{component.id} not yet implemented")
            else:
                variables, constraints = component.minizinc_constraints(self)

            self._model_constraints.extend(constraints)
            self._variables_list.extend(variables)
