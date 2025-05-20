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
import time
from copy import deepcopy

from minizinc import Status

from claasp.cipher_modules.models.cp import solvers
from claasp.cipher_modules.models.cp.minizinc_utils.mzn_bct_predicates import get_bct_operations
from claasp.cipher_modules.models.cp.minizinc_utils.utils import group_strings_by_pattern
from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_model import MznXorDifferentialModel
from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_model_arx_optimized import \
    MznXorDifferentialModelARXOptimized


class MznHadipourBoomerangModel(MznXorDifferentialModel):
    def __init__(self, cipher, boomerang_structure):
        self.boomerang_structure = boomerang_structure
        top_part_number_of_rounds = boomerang_structure["top_part_number_of_rounds"]
        middle_part_number_of_rounds = boomerang_structure["middle_part_number_of_rounds"]
        bottom_part_number_of_rounds = boomerang_structure["bottom_part_number_of_rounds"]

        total_number_of_rounds = top_part_number_of_rounds + middle_part_number_of_rounds + bottom_part_number_of_rounds
        assert total_number_of_rounds == cipher.number_of_rounds

        e0_cipher = cipher.get_partial_cipher(
            start_round=0,
            end_round=top_part_number_of_rounds + middle_part_number_of_rounds - 1,
            keep_key_schedule=False
        )
        e1_cipher = cipher.cipher_partial_inverse(
            start_round=top_part_number_of_rounds,
            end_round=top_part_number_of_rounds + middle_part_number_of_rounds + bottom_part_number_of_rounds - 1,
            keep_key_schedule=False
        )
        # TODO:: Create a unified cipher from e0_cipher and e1_cipher
        unified_cipher = None
        super().__init__(unified_cipher)

        import ipdb;
        ipdb.set_trace()

