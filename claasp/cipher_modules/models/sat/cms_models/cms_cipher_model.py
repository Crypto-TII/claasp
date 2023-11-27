
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


"""CryptoMiniSat model of Cipher.

.. _cms-cipher-standard:

CMS cipher model of a cipher
------------------------------------

The target of this class is to override the methods of the superclass
:py:class:`Sat Cipher Model <cipher_modules.models.sat.sat_models.sat_cipher_model>` to take the advantage given by
the handling of XOR clauses in CryptoMiniSat SAT solver. Therefore, the
internal format for SAT CNF clauses follows 4 rules (3 from the superclass +
1):

    * every variable is a string with no spaces nor dashes;
    * if a literal is a negation of a variable, a dash is prepended to the
      variable;
    * the separator for literals is a space;
    * the string ``'x '`` is prepended to a clause representing a XOR.

Note that only methods that do not need to introduce new variables to handle
XOR operations were overridden.

For any further information, visit `CryptoMiniSat - XOR clauses
<https://www.msoos.org/xor-clauses/>`_.
"""
from claasp.cipher_modules.models.sat.utils import utils
from claasp.cipher_modules.models.sat.sat_models.sat_cipher_model import SatCipherModel
from claasp.name_mappings import (CONSTANT, SBOX, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT,
                                  LINEAR_LAYER, MIX_COLUMN, WORD_OPERATION)


class CmsSatCipherModel(SatCipherModel):

    def __init__(self, cipher, window_size_weight_pr_vars=-1,
                 counter='sequential', compact=False):
        super().__init__(cipher, window_size_weight_pr_vars, counter, compact)

    def _add_clauses_to_solver(self, numerical_cnf, solver):
        """
        Add clauses to the (internal) SAT solver.

        It needs to be overwritten in this class because it must handle the XOR clauses.
        """
        utils.cms_add_clauses_to_solver(numerical_cnf, solver)

    def build_cipher_model(self, fixed_variables=[]):
        """
        Build the cipher model.

        INPUT:

        - ``fixed_variables`` -- **list**  (default: `[]`); the variables to be fixed in standard format

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.cipher_modules.models.sat.cms_models.cms_cipher_model import CmsSatCipherModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=22)
            sage: cms = CmsSatCipherModel(speck)
            sage: cms.build_cipher_model()
        """
        variables = []
        constraints = self.fix_variables_value_constraints(fixed_variables)
        component_types = [CIPHER_OUTPUT, CONSTANT, INTERMEDIATE_OUTPUT, LINEAR_LAYER, MIX_COLUMN, SBOX, WORD_OPERATION]
        operation_types = ['AND', 'MODADD', 'MODSUB', 'NOT', 'OR', 'ROTATE', 'SHIFT', 'SHIFT_BY_VARIABLE_AMOUNT', 'XOR']
        self._model_constraints = constraints
        self._variables_list = []

        for component in self._cipher.get_all_components():
            operation = component.description[0]
            if component.type not in component_types or (
                    WORD_OPERATION == component.type and operation not in operation_types):
                print(f'{component.id} not yet implemented')
            else:
                variables, constraints = component.cms_constraints()

            self._model_constraints.extend(constraints)
            self._variables_list.extend(variables)
