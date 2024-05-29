
# ****************************************************************************

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


from claasp.cipher_modules.models.sat.sat_models.sat_bitwise_deterministic_truncated_xor_differential_model import \
    SatBitwiseDeterministicTruncatedXorDifferentialModel


class CmsSatDeterministicTruncatedXorDifferentialModel(SatBitwiseDeterministicTruncatedXorDifferentialModel):

    def __init__(self, cipher, window_size_weight_pr_vars=-1,
                 counter='sequential', compact=False):
        super().__init__(cipher, window_size_weight_pr_vars, counter, compact)

        print("\n*** WARNING ***\n"
              "At the best of the authors knowldege, deterministic truncated XOR differential model "
              "cannot take any advantage of CryptoMiniSat. Therefore, the implementation is the same "
              "of the SAT one.")
