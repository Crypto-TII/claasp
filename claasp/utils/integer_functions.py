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


def bytearray_to_int(data, endianess="big"):
    return int.from_bytes(data, endianess, signed=False)


def int_to_bytearray(data, size, endianess="big"):
    return bytearray(data.to_bytes(size // 8, endianess))


def bytearray_to_wordlist(data, word_size, size=None):
    if size is None:
        size = len(data) * 8
    data_int = bytearray_to_int(data)

    return int_to_wordlist(data_int, word_size, size)


def wordlist_to_bytearray(data, word_size, size=None):
    if size is None:
        size = len(data) * word_size
    data_int = wordlist_to_int(data, word_size)

    return int_to_bytearray(data_int, size)


def int_to_wordlist(value, word_size, size, endianess="big"):
    wordlist = []
    for _ in range(size // word_size):
        wordlist.append(value % 2**word_size)
        value = value >> word_size

    if endianess == "big":
        wordlist.reverse()

    return wordlist


def wordlist_to_int(wordlist, word_size, endianess="big"):
    value = 0
    if endianess == "little":
        ordered_list = wordlist
    elif endianess == "big":
        ordered_list = reversed(wordlist)
    for i, word in enumerate(ordered_list):
        value += word * 2 ** (word_size * i)

    return value


def ror(value, rotation, size):
    r = rotation % size
    n = value % 2**size

    return (2**size - 1) & (n >> r | n << (size - r))


def lor(value, rotation, size):
    return ror(value, size - (rotation % size), size)
