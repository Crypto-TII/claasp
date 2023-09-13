
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

.. _cms-deterministic-truncated-standard:

CMS Deterministic Truncated XOR Differential of a cipher
------------------------------------------------------------

The target of this class is to override the methods of the superclass
:py:class:`Sat Deterministic Truncated Xor Differential Model
<cipher_modules.models.sat.sat_models.sat_deterministic_truncated_xor_differential_model>`
to take the advantage given by the handling of XOR clauses in CryptoMiniSat SAT solver. Therefore,
the internal format for SAT CNF clauses follows 4 rules (3 from the superclass +
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
from claasp.cipher_modules.models.sat.sat_models.sat_deterministic_truncated_xor_differential_model import \
    SatDeterministicTruncatedXorDifferentialModel
from claasp.name_mappings import (CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT,
                                  WORD_OPERATION)


class CmsSatDeterministicTruncatedXorDifferentialModel(SatDeterministicTruncatedXorDifferentialModel):

    def __init__(self, cipher, window_size_weight_pr_vars=-1,
                 counter='sequential', compact=False):
        super().__init__(cipher, window_size_weight_pr_vars, counter, compact)

    def _add_clauses_to_solver(self, numerical_cnf, solver):
        """
        Add clauses to the (internal) SAT solver.

        It needs to be overwritten in this class because it must handle the XOR clauses.
        """
        utils.cms_add_clauses_to_solver(numerical_cnf, solver)

    def build_deterministic_truncated_xor_differential_trail_model(self, fixed_variables=[]):
        """
        Build the model for the search of deterministic truncated XOR DIFFERENTIAL trails.

        INPUT:

        - ``fixed_variables`` -- **list**  (default: `[]`); the variables to be fixed in standard format

        .. SEEALSO::

            :py:meth:`~cipher_modules.models.utils.set_fixed_variables`

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.sat.cms_models.cms_deterministic_truncated_xor_differential_model import CmsSatDeterministicTruncatedXorDifferentialModel
            sage: speck = SpeckBlockCipher(number_of_rounds=22)
            sage: cms = CmsSatDeterministicTruncatedXorDifferentialModel(speck)
            sage: cms.build_deterministic_truncated_xor_differential_trail_model()
            ...
        """
        variables = []
        constraints = self.fix_variables_value_constraints(fixed_variables)
        self._variables_list = []
        self._model_constraints = constraints

        for component in self._cipher.get_all_components():
            component_types = [CONSTANT, INTERMEDIATE_OUTPUT, CIPHER_OUTPUT, WORD_OPERATION]
            operation = component.description[0]
            operation_types = ["ROTATE", "SHIFT"]

            if component.type in component_types and (component.type != WORD_OPERATION or operation in operation_types):
                variables, constraints = component.cms_deterministic_truncated_xor_differential_trail_constraints()
            else:
                print(f'{component.id} not yet implemented')

            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)
