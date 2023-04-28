
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


"""

Generator for LowMC constants.

Adapted from the generate_matrices.py file the LowMC repo:
https://github.com/LowMC/lowmc/blob/master/generate_matrices.py

"""
import os

blocksize = None
keysize = None
rounds = None


def main(args):
    """
    Generate matrices for LowMC instance.

    Use the global parameters `blocksize`, `keysize` and `rounds`
    to create the set of matrices and constants for the corresponding
    LowMC instance. Save those in a file named
    `lowmc_constants_p{blocksize}_k{keysize}_r{rounds}.dat`.
    """
    assert len(args) == 3, "Wrong number of arguments!"

    blocksize = int(args[0])
    keysize = int(args[1])
    rounds = int(args[2])

    filename = os.path.dirname(os.path.realpath(__file__)) + '/lowmc_constants_p' + \
        str(blocksize) + '_k' + str(keysize) + '_r' + str(rounds) + '.dat'

    gen = grain_ssg()
    linlayers = []
    for _ in range(rounds):
        linlayers.append(instantiate_matrix(blocksize, blocksize, gen))

    round_constants = []
    for _ in range(rounds):
        constant = [next(gen) for _ in range(blocksize)]
        round_constants.append(constant)

    roundkey_matrices = []
    for _ in range(rounds + 1):
        mat = instantiate_matrix(blocksize, keysize, gen)
        roundkey_matrices.append(mat)

    with open(filename, 'w') as matfile:
        s = str(blocksize) + '\n' + str(keysize) + '\n' + str(rounds) + '\n'

        matfile.write(s)
        for r in range(rounds):
            s = ''
            for row in linlayers[r]:
                s += ''.join(str(e) for e in row) + '\n'
            matfile.write(s)

        for r in range(rounds):
            s = ''
            s += ''.join(str(e) for e in round_constants[r]) + '\n'
            matfile.write(s)

        for r in range(rounds + 1):
            s = ''
            for row in roundkey_matrices[r]:
                s += ''.join(str(e) for e in row) + '\n'
            matfile.write(s)


def instantiate_matrix(n, m, gen):
    """Instantiate a matrix of maximal rank using bits from the generatator `gen`."""
    while True:
        mat = []
        for _ in range(n):
            row = []
            for _ in range(m):
                row.append(next(gen))
            mat.append(row)
        if rank(mat) >= min(n, m):
            return mat


def grain_ssg():
    """Generate a Grain LSFR in a self-shrinking generator."""
    state = [1 for _ in range(80)]
    index = 0
    # Discard first 160 bits
    for _ in range(160):
        state[index] ^= state[(index + 13) % 80] ^ state[(index + 23) % 80]\
            ^ state[(index + 38) % 80] ^ state[(index + 51) % 80]\
            ^ state[(index + 62) % 80]
        index += 1
        index %= 80
    choice = False
    while True:
        state[index] ^= state[(index + 13) % 80] ^ state[(index + 23) % 80]\
            ^ state[(index + 38) % 80] ^ state[(index + 51) % 80]\
            ^ state[(index + 62) % 80]
        choice = state[index]
        index += 1
        index %= 80
        state[index] ^= state[(index + 13) % 80] ^ state[(index + 23) % 80]\
            ^ state[(index + 38) % 80] ^ state[(index + 51) % 80]\
            ^ state[(index + 62) % 80]
        if choice == 1:
            yield state[index]
        index += 1
        index %= 80


def rank(matrix):
    """Determine the rank of a binary matrix."""
    # Copy matrix
    mat = [[x for x in row] for row in matrix]

    rows_n = len(matrix)
    columns_m = len(matrix[0])
    if columns_m > rows_n:
        return rows_n
    for column in range(columns_m):
        row = column
        while mat[row][column] != 1:
            row += 1
            if row >= rows_n:
                return column
        mat[column], mat[row] = mat[row], mat[column]
        xor_matrix_values(column, columns_m, mat, rows_n)

    return columns_m


def xor_matrix_values(column, columns_m, mat, rows_n):
    for row in range(column + 1, rows_n):
        if mat[row][column] == 1:
            for j in range(columns_m):
                mat[row][j] ^= mat[column][j]


if __name__ == '__main__':
    import sys
    main(sys.argv[1:])
