
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

.. _cms-linear-standard:

CMS XOR LINEAR model of a cipher
------------------------------------

The target of this class is to override the methods of the superclass
:py:class:`Sat Xor Linear Model <cipher_modules.models.sat.sat_models.sat_xor_linear_model>` to
take the advantage given by the handling of XOR clauses in CryptoMiniSat SAT solver. Therefore, the
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
from claasp.cipher_modules.models.utils import get_bit_bindings
from claasp.cipher_modules.models.sat.sat_models.sat_xor_linear_model import SatXorLinearModel
from claasp.name_mappings import CONSTANT, LINEAR_LAYER, SBOX, MIX_COLUMN, WORD_OPERATION


class CmsSatXorLinearModel(SatXorLinearModel):

    def __init__(self, cipher, window_size_weight_pr_vars=-1,
                 counter='sequential', compact=False):
        super().__init__(cipher, window_size_weight_pr_vars, counter, compact)
        self.bit_bindings, self.bit_bindings_for_intermediate_output = get_bit_bindings(cipher, '_'.join)

    def _add_clauses_to_solver(self, numerical_cnf, solver):
        """
        Add clauses to the (internal) SAT solver.

        It needs to be overwritten in this class because it must handle the XOR clauses.
        """
        utils.cms_add_clauses_to_solver(numerical_cnf, solver)

    def branch_xor_linear_constraints(self):
        """
        Return lists of variables and clauses for branch in XOR LINEAR model.

        .. SEEALSO::

            :ref:`CMS XOR LINEAR model  <cms-linear-standard>` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.cipher_modules.models.sat.cms_models.cms_xor_linear_model import CmsSatXorLinearModel
            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: speck = SpeckBlockCipher(number_of_rounds=3)
            sage: sat = CmsSatXorLinearModel(speck)
            sage: sat.branch_xor_linear_constraints()
            ['x -plaintext_0_o rot_0_0_0_i',
             'x -plaintext_1_o rot_0_0_1_i',
             'x -plaintext_2_o rot_0_0_2_i',
             ...
             'x -xor_2_10_13_o cipher_output_2_12_29_i',
             'x -xor_2_10_14_o cipher_output_2_12_30_i',
             'x -xor_2_10_15_o cipher_output_2_12_31_i']
        """
        constraints = []
        for output_bit, input_bits in self.bit_bindings.items():
            operands = [f'x -{output_bit}'] + input_bits
            constraints.append(' '.join(operands))

        return constraints

    def build_xor_linear_trail_model(self, weight=-1, fixed_variables=[]):
        """
        Build the linear model.

        INPUT:

        - ``weight`` -- **integer** (default: `-1`)
        - ``fixed_variables`` -- **list** (default: `[]`)

        EXAMPLES::

            sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
            sage: from claasp.cipher_modules.models.sat.cms_models.cms_xor_linear_model import CmsSatXorLinearModel
            sage: speck = SpeckBlockCipher(number_of_rounds=22)
            sage: cms = CmsSatXorLinearModel(speck)
            sage: cms.build_xor_linear_trail_model()
            ...
        """
        self._variables_list = []
        variables = []
        constraints = self.fix_variables_value_xor_linear_constraints(fixed_variables)
        self._model_constraints = constraints

        for component in self._cipher.get_all_components():
            component_types = [CONSTANT, LINEAR_LAYER, SBOX, MIX_COLUMN, WORD_OPERATION]
            operation = component.description[0]
            operation_types = ["AND", "MODADD", "NOT", "ROTATE", "SHIFT", "XOR", "OR", "MODSUB"]
            if component.type in component_types and (component.type != WORD_OPERATION or operation in operation_types):
                variables, constraints = component.cms_xor_linear_mask_propagation_constraints(self)
            else:
                print(f'{component.id} not yet implemented')

            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)

        constraints = self.branch_xor_linear_constraints()
        self._model_constraints.extend(constraints)

        if weight != -1:
            variables, constraints = self.weight_xor_linear_constraints(weight)
            self._variables_list.extend(variables)
            self._model_constraints.extend(constraints)
