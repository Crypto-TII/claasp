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


class IdeaModmul(Modular):
    """
    Component for modular multiplication (a * b) mod M.

    This component implements modular multiplication with automatic
    0 <-> 2^n mapping for moduli of the form 2^n + 1:
    - Input: 0 is treated as 2^n before multiplication
    - Output: 2^n is mapped back to 0 after reduction
    - Implements multiplicative group structure where 0 represents 2^n


    INPUT:

    - ``current_round_number`` -- **integer**; round index where the component is created. ``0`` is valid.
    - ``current_round_number_of_components`` -- **integer**; index of the component inside the round. ``0`` is valid.
    - ``input_id_links`` -- **list**; input component identifiers (usually strings). Must align with ``input_bit_positions``.
    - ``input_bit_positions`` -- **list**; bit positions for each input identifier (list of lists). Must align with ``input_id_links``.
    - ``output_bit_size`` -- **integer**; output size in bits. ``0`` is valid only when supported by the component semantics.
    - ``modulus`` -- **integer**; modulus used by modular arithmetic operations. Must be greater than ``0``.

    EXAMPLES::

        sage: from claasp.components.idea_modmul_component import IdeaModmul
        sage: component = IdeaModmul(0, 0, ['input1', 'input2'], [[0, 1], [0, 1]], 2, 5)
        sage: print(component.id)
        idea_modmul_0_0
        sage: print(component.type)
        word_operation
        sage: print(component.description)
        ['IDEA_MODMUL', 2, 5]
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
            "Algebraic polynomials for idea_modmul are not yet implemented."
        )

    def cms_constraints(self):
        """
        Return a list of variables and a list of clauses for Modular Multiplication in CMS CIPHER model.

        .. NOTE::

            Not implemented.
        """
        raise NotImplementedError(
            "CMS constraints for idea_modmul are not yet implemented."
        )

    def cp_constraints(self):
        """
        Return lists of declarations and constraints for Modular Multiplication component for CP CIPHER model.

        .. NOTE::

            Not implemented.
        """
        raise NotImplementedError(
            "CP constraints for idea_modmul are not yet implemented."
        )

    def get_bit_based_vectorized_python_code(self, params):
        """
        Generate Python code for bit-based vectorized modular multiplication.
        
        INPUT:

        - ``params`` -- **list**; the parameters for the function

        EXAMPLES::

            sage: from claasp.components.idea_modmul_component import IdeaModmul
            sage: modmul = IdeaModmul(0, 0, ['input1', 'input2'], [[0,1,2,3], [0,1,2,3]], 4, 17)
            sage: modmul.get_bit_based_vectorized_python_code(['a', 'b'])
            ['  idea_modmul_0_0 = bit_vector_idea_modmul([a,b], 2, 4, 17)']
        """
        # Retrieve stored parameters
        num_inputs = self.description[1]
        modulus = self.description[2]
        
        return [
            f"  {self.id} = bit_vector_idea_modmul([{','.join(params)}], "
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
        
        return [f"  {self.id} = byte_vector_idea_modmul({params}, {modulus}, {word_size})"]

    def sat_constraints(self):
        """
        Return a list of variables and a list of clauses representing MODULAR MULTIPLICATION for SAT CIPHER model.

        .. NOTE::

            Not implemented.
        """
        raise NotImplementedError(
            "SAT constraints for idea_modmul are not yet implemented."
        )

    def smt_constraints(self):
        """
        Return a variable list and SMT-LIB list asserts representing MODULAR MULTIPLICATION for SMT CIPHER model.

        .. NOTE::

            Not implemented.
        """
        raise NotImplementedError(
            "SMT constraints for idea_modmul are not yet implemented."
        )
