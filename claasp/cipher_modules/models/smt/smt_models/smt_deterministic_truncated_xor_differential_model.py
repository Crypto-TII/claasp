
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


from claasp.cipher_modules.models.smt.smt_model import SmtModel


class SmtDeterministicTruncatedXorDifferentialModel(SmtModel):
    def __init__(self, cipher, counter='sequential'):
        raise NotImplementedError("The model is not implemented since, at the best of the authors knowledge, "
                                  "deterministic truncated XOR differential model cannot take any advantage "
                                  "of an SMT solver. Therefore, there is no SMT implementation for deterministic "
                                  "truncated XOR differential model.")
