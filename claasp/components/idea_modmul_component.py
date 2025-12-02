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


from claasp.components.modular_component import Modular
from claasp.cipher_modules.models.smt.utils import utils as smt_utils
from claasp.cipher_modules.models.sat.utils import utils as sat_utils


class IDEA_MODMUL(Modular):
    """
    Component for modular multiplication (a * b) mod M.
    
    This component implements modular multiplication with automatic
    0 <-> 2^n mapping for moduli of the form 2^n + 1:
    - Input: 0 is treated as 2^n before multiplication
    - Output: 2^n is mapped back to 0 after reduction
    - Implements multiplicative group structure where 0 represents 2^n
    """
    
    def __init__(
        self,
        current_round_number,
        current_round_number_of_components,
        input_id_links,
        input_bit_positions,
        output_bit_size,
        modulus,
    ):
        super().__init__(
            current_round_number,
            current_round_number_of_components,
            input_id_links,
            input_bit_positions,
            output_bit_size,
            "idea_modmul",
            modulus,
        )

    def algebraic_polynomials(self, model):
        """
        Return a list of polynomials for Modular Multiplication.

        .. NOTE::

            Not implemented.
        """
        raise NotImplementedError(
            "Algebraic polynomials for IDEA_MODMUL are not yet implemented."
        )

    def cms_constraints(self):
        """
        Return a list of variables and a list of clauses for Modular Multiplication in CMS CIPHER model.

        .. NOTE::

            Not implemented.
        """
        raise NotImplementedError(
            "CMS constraints for IDEA_MODMUL are not yet implemented."
        )

    def cp_constraints(self):
        """
        Return lists of declarations and constraints for Modular Multiplication component for CP CIPHER model.

        .. NOTE::

            Not implemented.
        """
        raise NotImplementedError(
            "CP constraints for IDEA_MODMUL are not yet implemented."
        )

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        """
        Generate Python code for bit-based vectorized modular multiplication.
        
        INPUT:

        - ``params`` -- **list**; the parameters for the function
        - ``convert_output_to_bytes`` -- **boolean**; whether to convert output to bytes

        EXAMPLES::

            sage: from claasp.components.idea_modmul_component import IDEA_MODMUL
            sage: modmul = IDEA_MODMUL(0, 0, ['input1', 'input2'], [[0,1,2,3], [0,1,2,3]], 4, 17)
            sage: modmul.get_bit_based_vectorized_python_code(['a', 'b'], False)
            ['  idea_modmul_0_0 = bit_vector_IDEA_MODMUL([a,b], 2, 4, 17)']
        """
        # Retrieve stored parameters
        num_inputs = self.description[1]
        modulus = self.description[2]
        
        return [
            f"  {self.id} = bit_vector_IDEA_MODMUL([{','.join(params)}], "
            f"{num_inputs}, {self.output_bit_size}, {modulus})"
        ]

    def get_byte_based_vectorized_python_code(self, params):
        """
        Generate byte-based vectorized Python code for MODMUL evaluation.
        
        INPUT:

        - ``params`` -- **string**; the parameters for the function
        """
        # Retrieve stored modulus and word_size
        modulus = self.description[2]
        word_size = self.output_bit_size
        
        return [f"  {self.id} = byte_vector_IDEA_MODMUL({params}, {modulus}, {word_size})"]

    def sat_constraints(self):
        """
        Return a list of variables and a list of clauses representing MODULAR MULTIPLICATION for SAT CIPHER model.

        .. NOTE::

            Not implemented.
        """
        raise NotImplementedError(
            "SAT constraints for IDEA_MODMUL are not yet implemented."
        )

    def smt_constraints(self):
        """
        Return a variable list and SMT-LIB list asserts representing MODULAR MULTIPLICATION for SMT CIPHER model.

        .. NOTE::

            Not implemented.
        """
        raise NotImplementedError(
            "SMT constraints for IDEA_MODMUL are not yet implemented."
        )
