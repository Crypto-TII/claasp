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

import numpy as np
from claasp.cipher import Cipher
from claasp.name_mappings import BLOCK_CIPHER


def test_modmul_component_creation():
    """Test that idea_modmul component can be created and has correct properties."""
    cipher = Cipher("test_modmul", BLOCK_CIPHER, ["input"], [32], 16)
    cipher.add_round()
    
    # Add idea_modmul component with example modulus (2^16 + 1)
    modmul_component = cipher.add_idea_modmul_component(
        ["input", "input"],
        [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
         [16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]],
        16,
        65537  # Example: 2^16 + 1
    )
    
    assert modmul_component.id == "idea_modmul_0_0"
    assert modmul_component.type == "word_operation"
    assert modmul_component.description[0] == "IDEA_MODMUL"
    assert modmul_component.description[1] == 2  # number of inputs
    assert modmul_component.description[2] == 65537  # modulus
    assert modmul_component.output_bit_size == 16


def test_modmul_component_vectorized_code():
    """Test that idea_modmul component generates correct vectorized code."""
    cipher = Cipher("test_modmul", BLOCK_CIPHER, ["input"], [32], 16)
    cipher.add_round()
    
    modmul_component = cipher.add_idea_modmul_component(
        ["input", "input"],
        [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
         [16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]],
        16,
        65537
    )
    
    # Test bit-based vectorized code generation
    code = modmul_component.get_bit_based_vectorized_python_code(["a", "b"])
    assert len(code) == 1
    assert "bit_vector_idea_modmul" in code[0]
    assert "idea_modmul_0_0" in code[0]
    assert "65537" in code[0]

