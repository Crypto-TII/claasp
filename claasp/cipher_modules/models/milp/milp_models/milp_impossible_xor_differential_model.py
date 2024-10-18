
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

"""
The search methods presented in this class differ from those of the classes
:py:class:`Milp Bitwise Impossible Xor Differential Model
<cipher_modules.models.milp.milp_models.milp_bitwise_impossible_xor_differential_cipher_model>`

and :py:class:`Milp Wordwise Impossible Xor Differential Model
<cipher_modules.models.milp.milp_models.milp_wordwise_impossible_xor_differential_cipher_model>`.

Indeed, this class implements the framework proposed by `Cui et al.<https://eprint.iacr.org/2016/689.pdf>` which uses
infeasibility of a XOR DIFFERENTIAL model to detect an impossible differential trail.
"""

from claasp.cipher_modules.models.milp import solvers
from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
from claasp.cipher_modules.models.utils import enumerate_impossible_xor_differential_trails

class MilpImpossibleXorDifferentialModel(MilpXorDifferentialModel):
    def __init__(self, cipher, n_window_heuristic=None, verbose=False):
        super().__init__(cipher, n_window_heuristic, verbose)

    def find_one_impossible_xor_differential_trail(self, number_of_active_key_bits=1, number_of_active_pt_bits=1, number_of_active_ct_bits=1, solver_name=solvers.SOLVER_DEFAULT):
        """
        Returns one impossible XOR differential trail.

        INPUTS:

        - ``fixed_values`` -- *list of dict*, the variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)
        - ``solver_name`` -- *str*, the solver to call

        EXAMPLE::

            # to retrieve one of the trails of Table 2 from https://eprint.iacr.org/2016/689
            sage: from claasp.ciphers.block_ciphers.lblock_block_cipher import LBlockBlockCipher
            sage: lblock = LBlockBlockCipher(number_of_rounds=16)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_impossible_xor_differential_model import MilpImpossibleXorDifferentialModel
            sage: milp = MilpImpossibleXorDifferentialModel(lblock)
            sage: trail = milp.find_one_impossible_xor_differential_trail(1,0,0) # doctest: +SKIP
            ...

        """

        return enumerate_impossible_xor_differential_trails(self, number_of_active_key_bits, number_of_active_pt_bits,
                                                                  number_of_active_ct_bits, solver_name,
                                                                  output_only_one_solution=True)

    def find_all_impossible_xor_differential_trails(self, number_of_active_key_bits=1, number_of_active_pt_bits=1, number_of_active_ct_bits=1, solver_name=solvers.SOLVER_DEFAULT):
        """
        Returns all impossible XOR differential trails.

        INPUTS:

        - ``fixed_values`` -- *list of dict*, the variables to be fixed in
          standard format (see :py:meth:`~GenericModel.set_fixed_variables`)
        - ``solver_name`` -- *str*, the solver to call

        EXAMPLE::

            # to retrieve the trails of Table 2 from https://eprint.iacr.org/2016/689
            sage: from claasp.ciphers.block_ciphers.lblock_block_cipher import LBlockBlockCipher
            sage: lblock = LBlockBlockCipher(number_of_rounds=16)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_impossible_xor_differential_model import MilpImpossibleXorDifferentialModel
            sage: milp = MilpImpossibleXorDifferentialModel(lblock)
            sage: trails = milp.find_all_impossible_xor_differential_trails(1,0,0) # doctest: +SKIP
            ...

        """

        return enumerate_impossible_xor_differential_trails(self, number_of_active_key_bits, number_of_active_pt_bits,
                                                                  number_of_active_ct_bits, solver_name)