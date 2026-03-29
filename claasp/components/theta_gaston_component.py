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

import os
import pickle
from typing import Any

from claasp.input import Input
from claasp.cipher_modules.generic_functions import THETA_GASTON
from claasp.component import linear_layer_to_binary_matrix
from claasp.components.linear_layer_component import LinearLayer

# Global matrix cache
_cached_matrices: dict[str, Any] = {}

# File to persist the matrix cache
THIS_DIR = os.path.dirname(__file__)
ROOT_DIR = os.path.abspath(os.path.join(THIS_DIR, ".."))
CACHE_DIR = os.path.join(ROOT_DIR, "ciphers", "permutations")
os.makedirs(CACHE_DIR, exist_ok=True)


def _matrix_cache_path(cipher_id):
    return os.path.join(CACHE_DIR, f"gaston_theta_{cipher_id}.pkl")


class ThetaGaston(LinearLayer):
    """
    Construct a Theta-Gaston component.


    INPUT:

    - Parameters follow this class constructor (``__init__``) signature.
    - Required parameters should not be ``None``.
    - ``0`` is valid for round/component indices and numeric parameters when semantically meaningful.
    - For list parameters, pass Python lists; ``[]`` is valid only when explicitly supported by the component semantics.
    EXAMPLES::

        sage: from claasp.components.theta_gaston_component import ThetaGaston
        sage: component = ThetaGaston(0, 0, ['input'], [[i for i in range(320)]], 320, [1, 18, 23, 25, 32, 52, 60, 63])
        sage: print(component.id)
        theta_gaston_0_0
        sage: print(component.type)
        linear_layer
        sage: print(component.input_bit_size)
        320
    """
    def __init__(
        self,
        current_round_number,
        current_round_number_of_components,
        input_id_links,
        input_bit_positions,
        output_bit_size,
        rotation_amounts_parameter,
    ):
        matrix_id = "_".join(str(p) for p in rotation_amounts_parameter)
        if matrix_id in _cached_matrices:
            binary_matrix = _cached_matrices[matrix_id]
        else:
            path = _matrix_cache_path(matrix_id)
            if os.path.exists(path):
                with open(path, "rb") as f:
                    binary_matrix = pickle.load(f)
            else:
                binary_matrix = linear_layer_to_binary_matrix(
                    THETA_GASTON, output_bit_size, output_bit_size, [rotation_amounts_parameter]
                )
                with open(path, "wb") as f:
                    pickle.dump(binary_matrix, f)

            _cached_matrices[matrix_id] = binary_matrix
        description = list(binary_matrix.transpose())
        super().__init__(
            current_round_number,
            current_round_number_of_components,
            input_id_links,
            input_bit_positions,
            output_bit_size,
            description,
        )
        self._id = f"theta_gaston_{current_round_number}_{current_round_number_of_components}"
        self._input = Input(output_bit_size, input_id_links, input_bit_positions)
