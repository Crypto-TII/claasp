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

import pytest
from claasp.ciphers.block_ciphers.msx_block_cipher import MSXBlockCipher

"""
MSX block cipher unit tests.

Test vectors are verified against the official MSX reference implementation:
- Reference code: https://github.com/mrahman454/Block-Cipher-MSX/
- Paper: https://cic.iacr.org/p/2/4/32
"""

def test_msx64_128_vector():
    # pt: 0x0011223344556677
    # ct: 0xFA396532AFBEE794
    # key: 0xFE5A9E88BE34EAA338D5CF8A071FF6A3
    pt = 0x0011223344556677
    key = 0xFE5A9E88BE34EAA338D5CF8A071FF6A3
    ct = 0xFA396532AFBEE794
    msx = MSXBlockCipher(block_bit_size=64, key_bit_size=128)
    assert msx.test_vector_check([[pt, key]], [ct]) is True


def test_msx128_128_vector():
    # pt: 0x00112233445566778899AABBCCDDEEFF
    # ct: 0xDE999656047F271479804265DB9969BE
    pt = 0x00112233445566778899AABBCCDDEEFF
    key = 0xFE5A9E88BE34EAA338D5CF8A071FF6A3
    ct = 0xDE999656047F271479804265DB9969BE
    msx = MSXBlockCipher(block_bit_size=128, key_bit_size=128)
    assert msx.test_vector_check([[pt, key]], [ct]) is True


def test_msx128_256_vector():
    pt = 0x00112233445566778899AABBCCDDEEFF
    key = 0x5F14593A16BCEF6116499CDBEC51F8EE1074EF525BB35F233BE58334DDDCDCA2
    ct = 0xB2A6056E8B6A4CBE7B71A6991146E9BD
    msx = MSXBlockCipher(block_bit_size=128, key_bit_size=256)
    assert msx.test_vector_check([[pt, key]], [ct]) is True
