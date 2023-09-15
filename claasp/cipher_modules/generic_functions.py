
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


# using bitstring module to manage bits
from math import log
from copy import copy
from bitstring import BitArray  # pip3 install bitstring

from sage.crypto.sbox import SBox
from sage.rings.quotient_ring import QuotientRing
from sage.matrix.constructor import matrix, Matrix
from sage.modules.free_module_element import vector
from sage.rings.polynomial.polynomial_ring_constructor import PolynomialRing
from sage.rings.finite_rings.finite_field_constructor import FiniteField as GF

from claasp.utils.utils import int_to_poly, poly_to_int
from claasp.cipher_modules.models.algebraic.boolean_polynomial_ring import BooleanPolynomialRing


number_of_inputs_expression = "  #in = {}"
input_expression = "  in  = {}"
output_expression = "  out = {}"


def int_to_byte_array(integer_value, bit_length):
    byte_array_len = (bit_length + 7) // 8
    byte_array = bytearray(byte_array_len)
    tmp_int = integer_value
    for i in range(byte_array_len):
        byte_array[i] = (tmp_int >> 8 * i) & 0xFF

    return byte_array


def set_from_hex_string(hex_str):
    return BitArray(hex_str)


def sbox(input, lookup_table, output_len, verbosity=False):
    """
    INPUT:

    - ``input`` -- **BitArray object**; BitArray
    - ``lookup_table`` -- **list**; list of integers
    - ``output_len`` -- **integer**; output bit size of sbox
    - ``verbosity`` -- **boolean** (default: `False`); set this flag to True to print the input/output
    """
    output = BitArray(bin(lookup_table[input.uint]))
    # fill with zero on the left
    for _ in range(output.len, output_len):
        output.prepend("0b0")

    if verbosity:
        print("SBOX:")
        print("  LT  = {}".format(lookup_table))
        print(input_expression.format(input.bin))
        print(output_expression.format(output.bin))

    return output


def sbox_bool_func(component, BoolPolyRing):
    """
    INPUT:

    - ``component`` -- **Component object**; component of a cipher
    - ``BoolPolyRing`` -- **Boolean Polynomial Ring object**; Boolean Polynomial Ring
    """
    lookup_table = component.description
    output_bit_size = component.output_bit_size
    variables_names = [component.input_id_links[0] + "_" + str(i) for i in component.input_bit_positions[0]]

    X = BooleanPolynomialRing(output_bit_size, 'x')
    substitution = {}
    for i in range(output_bit_size):
        substitution[X.gens()[i]] = BoolPolyRing(variables_names[output_bit_size - i - 1])

    component_as_BF = []
    dim = int(log(len(lookup_table), 2))
    S = SBox(lookup_table)
    for i in range(dim):
        f = S.component_function(1 << i)
        b = f.algebraic_normal_form()
        component_as_BF.append(b.substitute(substitution))

    component_as_BF.reverse()
    variables_names_positions = {component.input_id_links[0]: [variables_names, component.input_bit_positions[0]]}

    return variables_names_positions, component_as_BF


def linear_layer(input, matrix, verbosity=False):
    """
    INPUT:

    - ``input`` -- **BitArray object**; a BitArray
    - ``matrix`` -- **list**; a list of lists of 0s and 1s. len(matrix) should be equal to input.len
    - ``verbosity`` -- **boolean** (default: `False`); set this flag to True to print the input/output
    """
    output = BitArray()
    for c in range(input.len):
        tmp = 0
        for r in range(len(matrix)):
            tmp = tmp ^ (input[r] & matrix[r][c])
        output.append(bin(tmp))

    if verbosity:
        print("LINEAR LAYER:")
        print("  M   = {}".format(matrix))
        print(input_expression.format(input.bin))
        print(output_expression.format(output.bin))

    return output


def mix_column_generalized(input_vector, input_matrix, polynomial, word_size, verbosity=False):
    """
    INPUT:

    - ``input_vector`` -- **BitArray object**; BitArray
    - ``input_matrix`` -- **list**; 2 dimensional list
    - ``polynomial`` -- **integer**; irreducible polynomial that defines the quotient ring
    - ``word_size`` -- **integer**; size of each element of the input_matrix and the input_vector
    - ``verbosity`` -- **boolean** (default: `False`); set this flag to True to print the input/output
    """

    nb_rows = len(input_matrix)
    nb_cols = len(input_matrix[0])

    if polynomial == 0:
        input_vector_split = [(input_vector.uint >> (i * word_size)) % (2 ** word_size) for i in range(nb_cols)]
        input_vector_split.reverse()
        output_vector_split = Matrix(input_matrix) * vector(input_vector_split)
        output_vector_bit_array = BitArray()
        for i in range(nb_cols):
            output_vector_bit_array.append(f'0b{output_vector_split[i]:0{word_size}b}')
        return output_vector_bit_array

    R = PolynomialRing(GF(2 ** word_size), 'x')
    x = R.gen()
    irred_polynomial = int_to_poly(polynomial, word_size + 1, x)
    S = QuotientRing(R, R.ideal(irred_polynomial), 'a')
    a = S.gen()

    M_tmp = [[0 for _ in range(nb_cols)] for _ in range(nb_rows)]
    for i in range(nb_rows):
        for j in range(nb_cols):
            M_tmp[i][j] = int_to_poly(input_matrix[i][j], word_size, a)
    M_poly = Matrix(S, M_tmp)

    c_tmp = [0 for _ in range(nb_cols)]
    block_len = input_vector.len // nb_cols
    for i in range(0, nb_cols):
        c_tmp[i] = int_to_poly(input_vector[i * block_len:(i + 1) * block_len].uint, word_size, a)
    c_poly = vector(S, c_tmp)

    res_vector = M_poly * c_poly
    output_vector = add_padding(a, nb_rows, res_vector, word_size)

    if verbosity:
        print("MIX COLUMN:")
        print("  Ring = {}".format(S))
        print("  M   =\n{}".format(input_matrix))
        print("  M (polynomial form)  =\n{}".format(M_poly))
        print(input_expression.format(input_vector.bin))
        print("  in (polynomial form)   =\n{}".format(c_poly))
        print(output_expression.format(output_vector.bin))

    return output_vector


def add_padding(a, number_of_rows, res_vector, word_size):
    output_vector = BitArray()
    # Padding when needed
    for row in range(number_of_rows):
        tmp = poly_to_int(res_vector[row], word_size, a)
        if word_size == 8 and tmp < 16:
            output_vector.append(4)
        if word_size in [4, 8]:
            output_vector.append(hex(tmp))
        if word_size == 3 and tmp < 2:
            output_vector.append(2)
            output_vector.append(bin(tmp))
        elif word_size == 3 and tmp < 4:
            output_vector.append(1)
            output_vector.append(bin(tmp))
        elif word_size not in [4, 8]:
            if tmp < 2:
                output_vector.append(1)
            output_vector.append(bin(tmp))

    return output_vector


def convert_x_to_binary_matrix_given_polynomial_modulus(word_size, polynomial):
    """
    Calculate binary matrix from word_size and polynomial.

    Multiplication by 2 in the QuotientRing defined by word_size and the irreducible polynomial.

    INPUT:

    - ``word_size`` -- **integer**; size of each element of the input_matrix and the input_vector
    - ``polynomial`` -- **integer**; irreducible polynomial that defines the quotient ring

    OUTPUT:

    - Binary matrix.
    """
    def rot1_right(input_list):
        tmp = input_list[len(input_list) - 1]
        return [tmp] + input_list[:len(input_list) - 1]

    F2 = PolynomialRing(GF(2), 'x')
    rot = [0] * word_size
    rot[1] = 1
    l = [rot]
    for _ in range(word_size - 1):
        l.append(rot1_right(l[-1]))

    for row in range(word_size):
        l[word_size - row - 1][0] = (polynomial & (1 << row)) >> row

    M = matrix(F2, l)

    return M


def convert_polynomial_to_binary_matrix_given_polynomial_modulus(word_size, polynomial, N):
    """
    Calculate binary matrix from word_size, polynomial and N.

    Multiplication by N in the QuotientRing defined by word_size and the irreducible polynomial.

    INPUT:

    - ``word_size`` -- **integer**; size of each element of the input_matrix and the input_vector
    - ``polynomial`` -- **integer**; irreducible polynomial that defines the quotient ring
    - ``N`` -- **integer**; a polynomial

    OUTPUT:

    - Binary matrix.
    """
    M2 = convert_x_to_binary_matrix_given_polynomial_modulus(word_size, polynomial)
    Nbinary = bin(N)[2:].zfill(word_size)

    F2 = PolynomialRing(GF(2), 'x')
    Tmp = matrix.identity(F2, word_size)
    M_N = matrix(F2, word_size)

    for i in range(word_size):
        if Nbinary[word_size - i - 1] == "1":
            M_N = M_N + Tmp
        Tmp = M2 * Tmp

    return M_N


def transform_GF2NMatrix_to_BinMatrix(GF2NMatrix, polynomial, word_size):
    """
    Transform the binary matrix into the equivalent GF2NMatrix.

    INPUT:

    - ``GF2NMatrix`` -- **matrix**; matrix
    - ``polynomial`` -- **integer**; irreducible polynomial that defines the quotient ring
    - ``word_size`` -- **integer**; size of each element of the input_matrix and the input_vector

    OUTPUT:

    - Binary matrix.
    """
    state_size = len(GF2NMatrix)
    index = [i for i in range(0, word_size * state_size - 1, word_size)]

    F2 = PolynomialRing(GF(2), 'x')
    BinMatrix = matrix(F2, word_size * state_size)
    for i in range(state_size):
        for j in range(state_size):
            BinMatrix.set_block(
                index[i],
                index[j],
                convert_polynomial_to_binary_matrix_given_polynomial_modulus(
                    word_size,
                    polynomial,
                    GF2NMatrix[i][j]))

    return BinMatrix


def mix_column_generalized_bool_func(component, BoolPolyRing):
    """
    INPUT:

    - ``component`` -- **object**; component of a cipher
    - ``BoolPolyRing`` -- **Boolean Polynomial Ring object**; Boolean Polynomial Ring
    """
    GF2NMatrix = component.description[0]
    polynomial = component.description[1]
    word_size = component.description[2]
    BinMatrix = transform_GF2NMatrix_to_BinMatrix(GF2NMatrix, polynomial, word_size)
    state_size = BinMatrix.nrows()

    number_of_inputs = len(component.input_id_links)
    variables_names = []
    variables_names_positions = {}
    for i in range(number_of_inputs):
        tmp = [component.input_id_links[i] + "_" + str(j) for j in component.input_bit_positions[i]]
        variables_names += tmp
        variables_names_positions[component.input_id_links[i]] = [tmp, component.input_bit_positions[i]]

    component_as_BF = []
    row_sum = 0
    for i in range(state_size):
        for j in range(state_size):
            if BinMatrix[i][j]:
                row_sum += BoolPolyRing(variables_names[j])
        component_as_BF.append(row_sum)
        row_sum = 0

    return variables_names_positions, component_as_BF


def padding(input, verbosity=False):
    """
    INPUT:

    - ``input`` -- **BitArray object**; BitArray
    - ``verbosity`` -- **boolean** (default: `False`); set this flag to True to print the input/output
    """
    if input.len % 4 != 0:
        input.prepend(4 - input.len % 4)
    output = BitArray(input)
    output.append('0b1')
    distance_from_m512 = 512 - (input.len % 512) - 1
    if distance_from_m512 > 64:
        output.append(distance_from_m512 - 64)
    else:
        output.append(distance_from_m512 + 512 - 64)

    tmp = BitArray(length=64)
    tmp.overwrite(bin(input.len), 64 - len(bin(input.len)) + 2)
    output.append(tmp)

    if verbosity:
        print("Padding:")
        print(input_expression.format(input.bin))
        print(output_expression.format(output.bin))

    return output


def XOR(input, number_of_inputs, verbosity=False):
    """
    INPUT:

    - ``input`` -- **BitArray object**; BitArray
    - ``number_of_inputs`` -- **integer**; specify in how many parts must the input be split
    - ``verbosity`` -- **boolean** (default: `False`); set this flag to True to print the input/output
    """
    block_len = input.len // number_of_inputs
    output = input[0:block_len]
    for i in range(1, number_of_inputs):
        output = output ^ input[i * block_len:(i + 1) * block_len]

    if verbosity:
        print("XOR:")
        print(number_of_inputs_expression.format(number_of_inputs))
        print(input_expression.format(input.bin))
        print(output_expression.format(output.bin))

    return output


def XOR_boolean_function(component, BoolPolyRing):
    """
    INPUT:

    - ``component`` -- **object**; component of a cipher
    - ``BoolPolyRing`` -- **Boolean Polynomial Ring object**; Boolean Polynomial Ring
    """
    number_of_inputs = len(component.input_id_links)
    number_of_blocks = component.description[1]
    output_bit_size = component.output_bit_size
    variables_names = []
    variables_names_positions = {}
    for i in range(number_of_inputs):
        tmp = [component.input_id_links[i] + "_" + str(j) for j in component.input_bit_positions[i]]
        variables_names += tmp
        if component.input_id_links[i] not in variables_names_positions:
            variables_names_positions[component.input_id_links[i]] = [tmp, component.input_bit_positions[i]]
        else:  # Keys are unique in a python dico, so need to handle 2 same entries in input_id_links !
            variables_names_positions[component.input_id_links[i]] = [variables_names_positions[component.input_id_links[i]]
                                                                      [0] + tmp, variables_names_positions[component.input_id_links[i]][1] + component.input_bit_positions[i]]

    component_as_BF = []
    tmp = 0
    for i in range(output_bit_size):
        for j in range(number_of_blocks):
            tmp += BoolPolyRing(variables_names[i + output_bit_size * j])
        component_as_BF.append(tmp)
        tmp = 0

    return variables_names_positions, component_as_BF


def constant_bool_func(component):
    """
    INPUT:

    - ``component`` -- **Component object**; component of a cipher
    """
    output_bit_size = component.output_bit_size
    if component.description[0][:2] == "0b":
        return [''], [int(component.description[0][i + 2]) for i in range(output_bit_size)]
    elif component.description[0][:2] == "0x":
        tmp = bin(int(component.description[0], 16))
        while len(tmp) - 2 < output_bit_size:
            tmp = tmp[:2] + "0" + tmp[2:]
        return [''], [int(tmp[i + 2]) for i in range(output_bit_size)]
    else:
        print("TODO")  # what to do when the constant is not given as bin string or hexa string


def concatenate_bool_func(component, BoolPolyRing):
    """
    INPUT:

    - ``component`` -- **Component object**; component of a cipher
    - ``BoolPolyRing`` -- **Boolean Polynomial Ring object**; Boolean Polynomial Ring
    """
    number_of_inputs = len(component.input_id_links)
    variables_names = []
    variables_names_positions = {}
    for i in range(number_of_inputs):
        tmp = [component.input_id_links[i] + "_" + str(j) for j in component.input_bit_positions[i]]
        variables_names += tmp
        variables_names_positions[component.input_id_links[i]] = [tmp, component.input_bit_positions[i]]

    output_bit_size = component.output_bit_size

    return variables_names_positions, [BoolPolyRing(variables_names[i]) for i in range(output_bit_size)]


def AND(input, number_of_inputs, verbosity=False):
    """
    INPUT:

    - ``input`` -- **BitArray object**; BitArray
    - ``number_of_inputs`` -- **integer**; specify in how many parts must the input be split
    - ``verbosity`` -- **boolean** (default: `False`); set this flag to True to print the input/output
    """
    block_len = input.len // number_of_inputs
    output = input[0:block_len]
    for i in range(1, number_of_inputs):
        output = output & input[i * block_len:(i + 1) * block_len]

    if verbosity:
        print("AND:")
        print(number_of_inputs_expression.format(number_of_inputs))
        print(input_expression.format(input.bin))
        print(output_expression.format(output.bin))

    return output


def OR(input, number_of_inputs, verbosity=False):
    """
    INPUT:

    - ``input`` -- **BitArray object**; BitArray
    - ``number_of_inputs`` -- **integer**; specify in how many parts must the input be split
    - ``verbosity`` -- **boolean** (default: `False`); set this flag to True to print the input/output
    """
    block_len = input.len // number_of_inputs
    output = input[0:block_len]
    for i in range(1, number_of_inputs):
        output = output | input[i * block_len:(i + 1) * block_len]

    if verbosity:
        print("OR:")
        print(number_of_inputs_expression.format(number_of_inputs))
        print(input_expression.format(input.bin))
        print(output_expression.format(output.bin))

    return output


def NOT(input, verbosity=False):
    """
    INPUT:

    - ``input`` -- **BitArray object**; BitArray
    - ``verbosity`` -- **boolean** (default: `False`); set this flag to True to print the input/output
    """
    output = BitArray(bin((1 << input.len) - 1))
    output.__ixor__(input)

    if verbosity:
        print("NOT:")
        print(input_expression.format(input.bin))
        print(output_expression.format(output.bin))

    return output


def MODADD(input, number_of_inputs, modulus, verbosity=False):
    """
    The modulus is 2^w, where w=Floor(input_length/number_of_inputs).

    INPUT:

    - ``input`` -- **BitArray object**; BitArray
    - ``number_of_inputs`` -- **integer**; specify in how many parts must the input be split
    - ``verbosity`` -- **boolean** (default: `False`); set this flag to True to print the input/output
    """
    block_len = input.len // number_of_inputs
    output = input[0:block_len].uint
    if modulus is None:
        modulus = 2 ** block_len
    for i in range(1, number_of_inputs):
        output = (output + input[i * block_len:(i + 1) * block_len].uint) % modulus

    output = BitArray(uint=output, length=block_len)
    if verbosity:
        print("MODADD:")
        print(number_of_inputs_expression.format(number_of_inputs))
        print(input_expression.format(input.bin))
        print(output_expression.format(output.bin))

    return output


def MODSUB(input, number_of_inputs, verbosity=False):
    """
    The modulus is 2^w, where w=Floor(input_length/number_of_inputs).

    INPUT:

    - ``input`` -- **BitArray object**; BitArray
    - ``number_of_inputs`` -- **integer**; specify in how many parts must the input be split
    - ``verbosity`` -- **boolean** (default: `False`); set this flag to True to print the input/output
    """
    block_len = input.len // number_of_inputs
    output = input[0:block_len].uint
    modulus = 2 ** block_len
    for i in range(1, number_of_inputs):
        output = (output - input[i * block_len:(i + 1) * block_len].uint) % modulus

    output = BitArray(uint=output, length=block_len)
    if verbosity:
        print("MODSUB:")
        print(number_of_inputs_expression.format(number_of_inputs))
        print(input_expression.format(input.bin))
        print(output_expression.format(output.bin))

    return output


def ROTATE(input, rotation_amount, verbosity=False):
    """
    If rotation_amount is negative rotation happens to the left, to the right otherwise.

    INPUT:

    - ``input`` -- **BitArray object**; a BitArray representing a binary string
    - ``rotation_amount`` -- **integer**; an integer indicating the amount of the rotation, positive for right rotation,
      negative for left rotation
    - ``verbosity`` -- **boolean** (default: `False`); set this flag to True to print the input/output

    EXAMPLES::

        sage: from claasp.cipher_modules.generic_functions import ROTATE
        sage: from bitstring import BitArray
        sage: b = BitArray("0x8")
        sage: b.bin
        '1000'
        sage: ROTATE(b,1).bin
        '0100'
        sage: ROTATE(b,-2).bin
        '0010'
    """
    r = rotation_amount % input.len
    output = copy(input)
    for i in range(input.len - r):
        output[i + r] = input[i]
    for i in range(r):
        output[i] = input[input.len - r + i]

    if verbosity:
        print("ROTATE:")
        print("  r   = {}".format(rotation_amount))
        print(input_expression.format(input.bin))
        print(output_expression.format(output.bin))

    return output


def SIGMA(input, rotation_amounts, verbosity=False):
    """
    If rotation_amount is negative rotation happens to the left, to the right otherwise.

    INPUT:

    - ``input`` -- **BitArray object**; a BitArray representing a binary string
    - ``rotation_amounts`` -- **list**; list indicating the amount of the rotations
    - ``verbosity`` -- **boolean** (default: `False`); set this flag to True to print the input/output

    EXAMPLES::

        sage: from claasp.cipher_modules.generic_functions import SIGMA
        sage: from bitstring import BitArray
        sage: b = BitArray("0x8")
        sage: SIGMA(b,[1,3]).bin
        '1101'
    """
    inputs_rotated = []
    for rotation_amount in rotation_amounts:
        new_rotation_amount = rotation_amount % input.len
        tmp = copy(input)
        for i in range(input.len - new_rotation_amount):
            tmp[i + new_rotation_amount] = input[i]
        for i in range(new_rotation_amount):
            tmp[i] = input[input.len - new_rotation_amount + i]
        inputs_rotated.append(tmp)

    number_of_inputs = len(rotation_amounts) + 1
    block_len = input.len
    xor_input = copy(input)
    for input_rotated in inputs_rotated:
        xor_input += input_rotated
    output = xor_input[0:block_len]
    for i in range(1, number_of_inputs):
        output = output ^ xor_input[i * block_len:(i + 1) * block_len]

    if verbosity:
        print("SIGMA:")
        print("  r   = {}".format(rotation_amounts))
        print(input_expression.format(input.bin))
        print(output_expression.format(output.bin))

    return output


def THETA_KECCAK(input):
    """
    Perform the mixing layer of Keccak.

    INPUT:

    - ``input`` -- **BitArray object**; a BitArray representing a binary string

    EXAMPLES::

        sage: from claasp.cipher_modules.generic_functions import THETA_KECCAK
        sage: from bitstring import BitArray
        sage: b = BitArray("0xf1258f7940e1dde784d5ccf933c0478ad598261ea65aa9eebd1547306f80494d8b284e056253d057ff97a42d7f8e6fd490fee5a0a44647c48c5bda0cd6192e76ad30a6f71b19059c30935ab7d08ffc64eb5aa93f2317d635a9a6e6260d71210381a57c16dbcf555f43b831cd0347c82601f22f1a11a5569f05e5635a21d9ae6164befef28cc970f2613670957bc46611b87c5a554fd00ecb8c3ee88a1ccf32c8940c7922ae3a26141841f924a2c509e416f53526e70465c275f644e97f30a13beaf1ff7b5ceca249")
        sage: THETA_KECCAK(b).hex == '09b84e4804496b9b7c480dc87768f1f62d05e72fe2f21f92458886012b28ff3173b58f3426fb662b6be4933769b0bcec048dd2bab27894fc1828ed16c027fd4e394391ed0d27d6a4a4e06dadc6b12f5cfd95713beec720a9bf693e22c0a1d79f976aa412161fa3c35577e9c9ce973eba173df71edc75a0038f8853e756dc0031eed3ce4ffbccdea2eb5b40280cc1c84132116ae838d5a09b0653d8376bca9c988c89ff979aa0f7a600c47f91965fd8560e70b393d39eb4706d73c25c4baa7089f27479ce687673fb'
        True
    """
    # Xoring the 5 lanes of each rows
    lane_len = 64
    plane_len = 320
    lanes_xored = []
    for i in range(5):
        tmp = input[i * plane_len: i * plane_len + lane_len]
        for j in range(1, 5):
            tmp = tmp ^ input[i * plane_len + j * lane_len: i * plane_len + (j + 1) * lane_len]
        lanes_xored.append(tmp)

    # Rotation of the lanes_rotated by -1
    rotated_xored_lanes = []
    for i in range(5):
        base = lanes_xored[i]
        tmp = copy(base)
        for j in range(lane_len - 1):
            tmp[j] = base[j + 1]
        for j in range(lane_len - (lane_len - 1)):
            tmp[lane_len - 1 + j] = base[j]
        rotated_xored_lanes.append(tmp)

    # Rows parity
    parity_rows = []
    for i in range(5):
        parity_rows.append(lanes_xored[(4 + i) % 5] ^ rotated_xored_lanes[(1 + i) % 5])

    # Xor rows parity to the corresponding lane
    output = 0
    for i in range(5):
        for j in range(5):
            output += input[i * plane_len + j * lane_len: i * plane_len + (j + 1) * lane_len] ^ parity_rows[i]

    return output


def THETA_XOODOO(input):
    """
    Perform the mixing layer of Xoodoo.

    INPUT:

    - ``input`` -- **BitArray object**; a BitArray representing a binary string

    EXAMPLES::

        sage: from claasp.cipher_modules.generic_functions import THETA_XOODOO
        sage: from bitstring import BitArray
        sage: b = BitArray("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
        sage: THETA_XOODOO(b).bin[:10] == '0101100100'
        True
    """
    # Xoring the 3 planes
    block_len = 128
    plane = input[0:block_len]
    for i in range(1, 3):
        plane = plane ^ input[i * block_len:(i + 1) * block_len]

    # Get the 4 lanes of plane
    plane_4_chunks = []
    for i in range(4):
        tmp = plane[i * 32:(i + 1) * 32]
        plane_4_chunks.append(tmp)

    # Rotation by 5 to the right on the z axis
    chunks_rotated_by_5 = []
    for i in range(4):
        base = plane_4_chunks[i]
        tmp = copy(base)
        for j in range(base.len - 5):
            tmp[j + 5] = base[j]
        for j in range(5):
            tmp[j] = base[base.len - 5 + j]
        chunks_rotated_by_5.append(tmp)

    # Rotation by 14 to the right on the z axis
    chunks_rotated_by_14 = []
    for i in range(4):
        base = plane_4_chunks[i]
        tmp = copy(base)
        for j in range(base.len - 14):
            tmp[j + 14] = base[j]
        for j in range(14):
            tmp[j] = base[base.len - 14 + j]
        chunks_rotated_by_14.append(tmp)

    # Rotation by 1 to the right on the x axis
    last_elt = chunks_rotated_by_5[-1]
    chunks_rotated_by_5.insert(0, last_elt)
    chunks_rotated_by_5 = chunks_rotated_by_5[:-1]
    last_elt = chunks_rotated_by_14[-1]
    chunks_rotated_by_14.insert(0, last_elt)
    chunks_rotated_by_14 = chunks_rotated_by_14[:-1]
    chunks_rotated = chunks_rotated_by_5 + chunks_rotated_by_14

    # Concatenation of the 8 chunks rotated
    chunks_concatenated = copy(chunks_rotated[0])
    for chunk in chunks_rotated[1:]:
        chunks_concatenated += chunk

    plane_updated = chunks_concatenated[0:128] ^ chunks_concatenated[128:256]
    plane_updated_concat_3_times = plane_updated + plane_updated + plane_updated
    output = copy(input)
    output ^= plane_updated_concat_3_times

    return output


def ROTATE_BY_VARIABLE_AMOUNT(input, input_size, rotation_direction, verbosity=False):
    """

    INPUT:

    - ``input`` -- **BitArray object**; a BitArray representing a binary string
    - ``input_size`` -- **integer**; size in bits of the binary string to be rotated
    - ``rotation_direction`` -- **integer**; an integer indicating the direction of the rotation, positive for right
        and negative for left
    - ``verbosity`` -- **boolean** (default: `False`); set this flag to True to print the input/output
    """

    output = input[:input_size]
    rotation_amount = input[input_size:].uint * rotation_direction
    r = rotation_amount % input_size
    for i in range(input_size - r):
        output[i + r] = input[i]
    for i in range(r):
        output[i] = input[input_size - r + i]

    if verbosity:
        print("VARIABLE_ROTATE:")
        print("  r   = {}".format(rotation_amount))
        print(input_expression.format(input[:input_size].bin))
        print(output_expression.format(output.bin))

    return output


def ROTATE_boolean_function(component, BoolPolyRing):
    """

    INPUT:

    - ``component`` -- **Component object**; is a component of a cipher
    - ``BoolPolyRing`` -- **Boolean Polynomial Ring object**; is a Boolean Polynomial Ring
    """
    number_of_inputs = len(component.input_id_links)
    step = abs(component.description[1])
    output_bit_size = component.output_bit_size
    variables_names = []
    variables_names_positions = {}
    for i in range(number_of_inputs):
        tmp = [component.input_id_links[i] + "_" + str(j) for j in component.input_bit_positions[i]]
        variables_names += tmp
        variables_names_positions[component.input_id_links[i]] = [tmp, component.input_bit_positions[i]]

    tmp = variables_names[:step]
    variables_names = variables_names[step:] + tmp

    component_as_BF = []
    for i in range(output_bit_size):
        component_as_BF.append(BoolPolyRing(variables_names[i]))

    return variables_names_positions, component_as_BF


def SHIFT(input, shift_amount, verbosity=False):
    """
    If shift_amount is negative shift happens to the left, to the right otherwise.

    INPUT:

    - ``input`` -- **BitArray object**; a BitArray representing a binary string
    - ``shift_amount`` -- **integer**; an integer indicating the amount of the shift, positive for right shift,
        negative for left shift
    - ``verbosity`` -- **boolean** (default: `False`); set this flag to True to print the input/output

    EXAMPLES::

        sage: from claasp.cipher_modules.generic_functions import SHIFT
        sage: from bitstring import BitArray
        sage: b = BitArray("0xF")
        sage: b.bin
        '1111'
        sage: SHIFT(b,1).bin
        '0111'
        sage: SHIFT(b,-2).bin
        '1100'
    """
    output = BitArray(input.len)
    if shift_amount >= input.len:
        return output
    elif shift_amount > 0:
        for i in range(input.len - shift_amount):
            output[i + shift_amount] = input[i]
    else:
        s = - shift_amount
        for i in range(input.len - s):
            output[i] = input[i + s]

    if verbosity:
        print("SHIFT:")
        print("  s   = {}".format(shift_amount))
        print(input_expression.format(input.bin))
        print(output_expression.format(output.bin))

    return output


def SHIFT_BY_VARIABLE_AMOUNT(input, input_size, shift_direction, verbosity=False):
    """

    INPUT:

    - ``input`` -- **BitArray object**; a BitArray representing a binary string
    - ``input_size`` -- **integer**; size in bits of the binary string to be shifted
    - ``shift_direction`` -- **integer**; an integer indicating the direction of the shift, positive for right and
        negative for left
    - ``verbosity`` -- **boolean** (default: `False`); set this flag to True to print the input/output
    """

    output = BitArray(input_size)
    shift_amount = input[input_size:].uint % input_size

    if shift_amount >= input_size:
        return output

    shift_amount *= shift_direction

    if shift_amount > 0:
        for i in range(input_size - shift_amount):
            output[i + shift_amount] = input[i]
    else:
        for i in range(input_size + shift_amount):
            output[i] = input[i - shift_amount]

    if verbosity:
        print("VARIABLE_SHIFT:")
        print("  s   = {}".format(shift_amount))
        print(input_expression.format(input[:input_size].bin))
        print(output_expression.format(output.bin))

    return output


def select_bits(input, bit_positions, verbosity=False):
    """
    INPUT:

    - ``input`` -- **BitArray object**; a BitArray representing a binary string
    - ``bit_positions`` -- **list**; the positions of the bits
    - ``verbosity`` -- **boolean** (default: `False`); set this flag to True to print the input/output
    """
    output = BitArray()
    if bit_positions == [-1]:
        return input

    if not bit_positions:
        return output

    for i in range(len(bit_positions)):
        output = output + input[bit_positions[i]:bit_positions[i] + 1]

    if output == BitArray():
        print("ERROR: returning empty bitstring!\n  input = {}\n  bit_positions = {}".format(input.bin, bit_positions))

    if verbosity:
        print("SELECT BITS:")
        print("  pos = {}".format(bit_positions))
        print(input_expression.format(input.bin))
        print(output_expression.format(output.bin))

    return output


def merge_bits():
    return 0
