#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "generic_bit_based_cuda_functions.cuh"

#define pow2(i) (1lu << i)
#define byte_size(bit_size) (bit_size / 8 + (bit_size % 8 == 0 ? 0 : 1))

CUDA_HOSTDEV BitString* copy(BitString *b) {
    BitString *b_copy = zero_bitstring(b -> bit_size);
    memcpy(b_copy -> list, b -> list, byte_size(b -> bit_size));

    return b_copy;
}

CUDA_HOSTDEV BitString* copy_most_significant_bytes(BitString *b, uint16_t bits_to_copy) {
    BitString *b_copy = zero_bitstring(bits_to_copy);
    memcpy(b_copy -> list, b -> list, byte_size(bits_to_copy));

    return b_copy;
}

CUDA_HOSTDEV BitString* copy_least_significant_bytes(BitString *b, uint16_t bits_to_copy) {
    BitString *b_copy = zero_bitstring(bits_to_copy);
    memcpy(b_copy -> list, (b -> list) + (byte_size(b -> bit_size) - byte_size(bits_to_copy)), byte_size(bits_to_copy));

    return b_copy;
}

CUDA_HOSTDEV uint8_t get(BitString *b, uint16_t i) {
    uint16_t bit_index = (b -> bit_size % 8 == 0 ? 0 : 8 - (b -> bit_size % 8)) + i;
    return (b -> list[bit_index / 8] >> (7 - (bit_index % 8))) & 1;
}

CUDA_HOSTDEV void set(BitString *b, uint16_t i, uint8_t new_bit) {
    uint16_t bit_index = (b -> bit_size % 8 == 0 ? 0 : 8 - (b -> bit_size % 8)) + i;

    if (new_bit)
        b -> list[bit_index / 8] |= 1 << (7 - (bit_index % 8));
    else
        b -> list[bit_index / 8] &= ~(1 << (7 - (bit_index % 8)));
}

CUDA_HOSTDEV uint64_t bitstring_to_uint(BitString *input) {
    uint64_t output_value = 0;
    uint16_t input_byte_size = byte_size(input -> bit_size);

    for (int i = 0; i < input_byte_size; i++)
        output_value |= input -> list[input_byte_size - 1 - i] << (i * 8);

    return output_value;
}

CUDA_HOSTDEV BitString* select_bits(uint8_t n, BitString** b, uint16_t** bit_positions, uint16_t component_output_size) {
    uint16_t selected_bits = 0, bit_index = 0, operand_byte_size, number_of_operands, bit_offset;

    for (int i = 0; i < n; i++)
        selected_bits += bit_positions[i][0];

    if (component_output_size > selected_bits)
        number_of_operands = 1;
    else
        number_of_operands = selected_bits / component_output_size;

    //Maybe...
    operand_byte_size = byte_size(component_output_size);
    bit_offset = component_output_size % 8 == 0 ? 0 : 8 - (component_output_size % 8);
    bit_index = bit_offset;

    BitString *component_input = zero_bitstring(byte_size(selected_bits / number_of_operands) * number_of_operands * 8);

    //beginning bits are the most significant (index 0)
    for (int i = 0; i < n; i++) {
        for (int j = 1; j <= bit_positions[i][0]; j++) {
            if (get(b[i], bit_positions[i][j]))
                set(component_input, bit_index, 1);

            bit_index++;

            if (bit_index % (operand_byte_size * 8) == 0)
                bit_index += bit_offset;
        }
    }

    return component_input;
}

/*BitString** select_bits_and_split(uint8_t n, BitString* b[n], uint16_t* bit_positions[n], uint8_t number_of_operands) {
    uint16_t total_bit_size = 0, operand_bit_size, total_bit_index = 0, operand_index, operand_bit_index;

    for (int i = 0; i < n; i++)
        total_bit_size += bit_positions[i][0];

    operand_bit_size = total_bit_size / number_of_operands;

    BitString **r = malloc(sizeof(BitString*) * number_of_operands);

    for (int i = 0; i < number_of_operands; i++)
        r[i] = zero_bitstring(operand_bit_size);

    for (int i = 0; i < n; i++) {        
        for (int j = 1; j <= bit_positions[i][0]; j++) {
            operand_index = total_bit_index / operand_bit_size;
            operand_bit_index = total_bit_index % operand_bit_size;

            if (get(b[i], bit_positions[i][j]))
                (r[operand_index] -> list)[byte_size(operand_bit_size) - operand_bit_index/8 - 1] += pow2(operand_bit_index % 8);

            total_bit_index++;
        }
    }

    return r;
}*/

CUDA_HOSTDEV void delete_multiple_bitstrings(int n, ...) {
    va_list args;
    va_start(args, n);

    for (int i = 0; i < n; i++)
        delete_bitstring(va_arg(args, BitString*));

    va_end(args);

}

CUDA_HOSTDEV void delete_bitstring(BitString *b) {
    free(b -> list);
    free(b);
}

CUDA_HOSTDEV char* bitstring_to_binary_string(BitString* b) {
    char *str = (char *)malloc(b -> bit_size + 1);

    for (int i = 0; i < b -> bit_size; i++)
        str[i] = get(b, i) ? '1': '0';
        
    return str;
}

CUDA_HOSTDEV char* bitstring_to_decimal_string(BitString* b) {

    char *str = (char *)malloc((b -> bit_size / 10) + 1);


    return str;
}

CUDA_HOSTDEV char* bitstring_to_hex_string(BitString* b) {

    uint16_t index, hex_size = (b -> bit_size / 4) + (b -> bit_size % 4 > 0);
    char *str = (char *)malloc(hex_size + 3);

    if (str == NULL) {
        printf("malloc() failed");
        return NULL;
    }

    str = strcpy(str, "0x");

    if (b -> bit_size % 8 > 4 || b -> bit_size % 8 == 0) {
        sprintf(str + 2, "%02x", (b -> list)[0]);
        index = 4;
    } else {
        sprintf(str + 2, "%x", (b -> list)[0] % pow2(4));
        index = 3;
    }

    for (int i = 1; i < byte_size(b -> bit_size); i++)
        sprintf(str + index + ((i-1) * 2), "%02x", (b -> list)[i]);

    return str;
}

CUDA_HOSTDEV void print_bitstring(BitString* b, uint8_t base) {
    char *str;

    switch (base) {
        case 2:
            str = bitstring_to_binary_string(b);
        case 10:
            str = bitstring_to_decimal_string(b);
        case 16:
            str = bitstring_to_hex_string(b);
            break;
        
        default:
            printf("Invalid base.\n");
            exit(-1);
    }

    printf("%s\n", str);
    free(str);
}

CUDA_HOSTDEV bool equals(BitString *b1, BitString *b2) {
    if (b1 -> bit_size != b2 -> bit_size)
        return false;

    if ((b1 -> list)[0] % pow2(b1 -> bit_size % 8) != (b2 -> list)[0] % pow2(b2 -> bit_size % 8))
        return false;

    for (int i = 1; i < byte_size(b1 -> bit_size); i++)
        if ((b1 -> list)[i] != (b2 -> list)[i])
            return false;

    return true;
}

//Constructors
CUDA_HOSTDEV BitString* zero_bitstring(uint16_t bit_size) {
    BitString *b = (BitString*)malloc(sizeof(BitString));

    if (b == NULL) {
        printf("malloc() failed.");
        return NULL;
    }

    b -> list = (uint8_t *)calloc(byte_size(bit_size), sizeof(uint8_t));

    if (b -> list == NULL) {
        printf("malloc() failed.");
        free(b);
        return NULL;
    }

    b -> bit_size = bit_size;

    return b;
}

CUDA_HOSTDEV BitString* bitstring_from_binary_string(char *bits, uint16_t bit_size) {
    BitString *result = zero_bitstring(bit_size);
    uint16_t bit_index = bit_size % 8 == 0 ? 0 : 8 - (bit_size % 8);

    for (int i = 0; i < bit_size; i++) {
        if (bits[i] == '1')
            result -> list[bit_index / 8] |= pow2(7 - (bit_index % 8));

        bit_index++;
    }

    return result;
}

CUDA_HOSTDEV BitString* bitstring_from_hex_string(char *hex_digits, uint16_t bit_size) {
    BitString *result = zero_bitstring(bit_size);
    uint16_t hex_length = strlen(hex_digits), j = byte_size(bit_size) - 1;;
    char app[2];

    for (int i = hex_length - 1; i >= 3; i -= 2) {
        app[0] = hex_digits[i - 1];
        app[1] = hex_digits[i];

        result -> list[j--] = strtoul(app, NULL, 16);
    }

    if ((hex_length - 2) % 2) {
        app[0] = '0';
        app[1] = hex_digits[2];
        result -> list[j] = strtoul(app, NULL, 16);
    }

    return result;
}

/*
BitString* bitstring_from_hex_string(char *hex_digits, uint16_t bit_size) {
    BitString *result = zero_bitstring(bit_size);

    char app[2];
    uint16_t start_index = 0;

    if (bit_size % 8 <= 4 && bit_size % 8 != 0) {
        app[0] = '0';
        app[1] = hex_digits[2];

        result -> list[0] = strtoul(app, NULL, 16);

        start_index = 1;
    }

    for (int i = start_index; i < byte_size(bit_size); i++) {
        app[0] = hex_digits[(i * 2) + 2];
        app[1] = hex_digits[(i * 2) + 3];

        result -> list[i] = strtoul(app, NULL, 16);
    }

    return result;
}*/

CUDA_HOSTDEV BitString* bitstring_from_int(uint64_t value, uint16_t bit_size) {
    BitString *b = zero_bitstring(bit_size);

    for (int i = byte_size(bit_size) - 1; i >= 0; i--) {
        (b -> list)[i] = value % pow2(8);
        value = value >> 8;
    }

    if (bit_size % 8 != 0)
        (b -> list)[0] = (b -> list)[0] % pow2(bit_size % 8);

    return b;

}

//////////////
//OPERATIONS//
//////////////

//NOT
CUDA_HOSTDEV BitString* NOT(BitString* input, uint16_t operand_bit_size) {
    uint16_t input_byte_size = byte_size(operand_bit_size);

    BitString *result = zero_bitstring(operand_bit_size);

    for (int i = 0; i < input_byte_size; i++)
        (result -> list)[i] = ~(input -> list[i]);

    return result;
}

//XOR
/*BitString* var_xor(uint8_t n, ...) {

    va_list args;
    va_start(args, n);

    BitString* operands[n];

    //TODO: remember to check the sizes (if necessary...)
    for (int i = 0; i < n; i++) {
        operands[i] = va_arg(args, BitString*);
    }

    BitString *result = copy(operands[0]);

    for (int i = 0; i < byte_size(result -> bit_size); i++)
        for (int j = 1; j < n; j++)
            (result -> list)[i] ^= (operands[j] -> list)[i];

    va_end(args);

    return result;
}

BitString* array_xor(uint8_t n, BitString* inputs[n]) {

    BitString *result = copy(inputs[0]);

    for (int i = 0; i < byte_size(result -> bit_size); i++)
        for (int j = 1; j < n; j++)
            (result -> list)[i] ^= (inputs[j] -> list)[i];

    return result;
}*/

CUDA_HOSTDEV BitString* XOR(BitString* input, uint16_t operand_bit_size) {
    uint16_t operand_byte_size = byte_size(operand_bit_size);
    uint16_t number_of_operands = byte_size(input -> bit_size) / operand_byte_size;

    BitString *result = copy_most_significant_bytes(input, operand_bit_size);

    for (int i = 0; i < operand_byte_size; i++)
        for (int j = 1; j < number_of_operands; j++)
            (result -> list)[i] ^= (input -> list)[j*operand_byte_size + i];

    return result;
}

//OR
/*BitString* var_or(uint8_t n, ...) {

    va_list args;
    va_start(args, n);

    BitString* operands[n];

    //TODO: remember to check the sizes (if necessary...)
    for (int i = 0; i < n; i++) {
        operands[i] = va_arg(args, BitString*);
    }

    BitString *result = copy(operands[0]);

    for (int i = 0; i < byte_size(result -> bit_size); i++)
        for (int j = 1; j < n; j++)
            (result -> list)[i] |= (operands[j] -> list)[i];

    va_end(args);

    return result;
}

BitString* array_or(uint8_t n, BitString* inputs[n]) {

    BitString *result = copy(inputs[0]);

    for (int i = 0; i < byte_size(result -> bit_size); i++)
        for (int j = 1; j < n; j++)
            (result -> list)[i] |= (inputs[j] -> list)[i];

    return result;
}*/

CUDA_HOSTDEV BitString* OR(BitString* input, uint16_t operand_bit_size) {
    uint16_t operand_byte_size = byte_size(operand_bit_size);
    uint16_t number_of_operands = byte_size(input -> bit_size) / operand_byte_size;

    BitString *result = copy_most_significant_bytes(input, operand_bit_size);
    
    for (int i = 0; i < operand_byte_size; i++)
        for (int j = 1; j < number_of_operands; j++)
            (result -> list)[i] |= (input -> list)[j*operand_byte_size + i];

    return result;
}

//AND
/*BitString* var_and(uint8_t n, ...) {

    va_list args;
    va_start(args, n);

    BitString* operands[n];

    //TODO: remember to check the sizes (if necessary...)
    for (int i = 0; i < n; i++) {
        operands[i] = va_arg(args, BitString*);
    }

    BitString *result = copy(operands[0]);

    for (int i = 0; i < byte_size(result -> bit_size); i++)
        for (int j = 1; j < n; j++)
            (result -> list)[i] &= (operands[j] -> list)[i];

    va_end(args);

    return result;
}

BitString* array_and(uint8_t n, BitString* inputs[n]) {

    BitString *result = copy(inputs[0]);

    for (int i = 0; i < byte_size(result -> bit_size); i++)
        for (int j = 1; j < n; j++)
            (result -> list)[i] &= (inputs[j] -> list)[i];

    return result;
}*/

CUDA_HOSTDEV BitString* AND(BitString* input, uint16_t operand_bit_size) {
    uint16_t operand_byte_size = byte_size(operand_bit_size);
    uint16_t number_of_operands = byte_size(input -> bit_size) / operand_byte_size;

    BitString *result = copy_most_significant_bytes(input, operand_bit_size);

    for (int i = 0; i < operand_byte_size; i++)
        for (int j = 1; j < number_of_operands; j++)
            (result -> list)[i] &= (input -> list)[j*operand_byte_size + i];

    return result;
}

//MODADD
/*BitString* var_modadd(uint8_t n, ...) {

    va_list args;
    va_start(args, n);

    BitString* operands[n];

    //TODO: remember to check the sizes (if necessary...)
    for (int i = 0; i < n; i++) {
        operands[i] = va_arg(args, BitString*);
    }

    BitString *result = zero_bitstring(operands[0] -> bit_size);
    uint16_t sum = 0; //16 bits should be more than enough

    for (int i = byte_size(result -> bit_size) - 1; i >= 0; i--) {
        for (int j = 0; j < n; j++)
            sum += (operands[j] -> list)[i];

        //least byte of sum gets assigned
        (result -> list)[i] = sum;
        sum = sum >> 8;
    }

    //truncate the excessive bits
    //if (result -> bit_size % 8 != 0)
    //    (result -> list)[0] = (result -> list)[0] % pow2(result -> bit_size % 8);

    va_end(args);

    return result;
}

BitString* array_modadd(uint8_t n, BitString* inputs[n]) {

    BitString *result = zero_bitstring(inputs[0] -> bit_size);
    uint16_t sum = 0; //16 bits should be more than enough

    for (int i = byte_size(result -> bit_size) - 1; i >= 0; i--) {
        for (int j = 0; j < n; j++)
            sum += (inputs[j] -> list)[i];

        //least byte of sum gets assigned
        (result -> list)[i] = sum;
        sum = sum >> 8;
    }

    //truncate the excessive bits
    //if (result -> bit_size % 8 != 0)
    //    (result -> list)[0] = (result -> list)[0] % pow2(result -> bit_size % 8);

    return result;
}*/

CUDA_HOSTDEV BitString* MODADD(BitString* input, uint16_t operand_bit_size) {
    uint16_t sum = 0, operand_byte_size = byte_size(operand_bit_size); //16 bits should be more than enough
    uint16_t number_of_operands = byte_size(input -> bit_size) / operand_byte_size;

    BitString *result = zero_bitstring(operand_bit_size);

    for (int i = operand_byte_size - 1; i >= 0; i--) {
        for (int j = 0; j < number_of_operands; j++)
            sum += (input -> list)[j*operand_byte_size + i];

        //least byte of sum gets assigned
        (result -> list)[i] = sum;
        sum = sum >> 8;
    }

    return result;
}

//MODSUB
/*BitString* var_modsub(uint8_t n, ...) {

    va_list args;
    va_start(args, n);

    BitString* operands[n];

    //TODO: remember to check the sizes (if necessary...)
    for (int i = 0; i < n; i++) {
        operands[i] = va_arg(args, BitString*);
    }

    BitString *result = zero_bitstring(operands[0] -> bit_size);
    uint8_t sub; //16 bits should be more than enough
    uint16_t borrow = 0;

    for (int i = byte_size(result -> bit_size) - 1; i >= 0; i--) {

        sub = (operands[0] -> list)[i] - borrow;

        if ((operands[0] -> list)[i] < borrow)
            borrow = 1;
        else
            borrow = 0;

        for (int j = 1; j < n; j++) {
            if ((operands[j] -> list)[i] > sub)
                borrow++;
            
            sub -= (operands[j] -> list)[i];
        }
            
        //least byte of sum gets assigned
        (result -> list)[i] = sub;
    }

    //truncate the excessive bits
    //if (result -> bit_size % 8 != 0)
    //    (result -> list)[0] = (result -> list)[0] % pow2(result -> bit_size % 8);

    va_end(args);

    return result;
}

BitString* array_modsub(uint8_t n, BitString* inputs[n]) {
    BitString *result = zero_bitstring(inputs[0] -> bit_size);
    uint8_t sub; //16 bits should be more than enough
    uint16_t borrow = 0; //i can lower it to 8 bits probably

    for (int i = byte_size(result -> bit_size) - 1; i >= 0; i--) {

        sub = (inputs[0] -> list)[i] - borrow;

        if ((inputs[0] -> list)[i] < borrow)
            borrow = 1;
        else
            borrow = 0;

        for (int j = 1; j < n; j++) {
            if ((inputs[j] -> list)[i] > sub)
                borrow++;
            
            sub -= (inputs[j] -> list)[i];
        }
            
        //least byte of sum gets assigned
        (result -> list)[i] = sub;
    }

    //truncate the excessive bits
    if (result -> bit_size % 8 != 0)
        (result -> list)[0] = (result -> list)[0] % pow2(result -> bit_size % 8);

    return result;
}

BitString* MODSUB(uint8_t n, BitString* inputs[n]) {
    BitString *result = zero_bitstring(inputs[0] -> bit_size);
    uint8_t sub;
    uint16_t borrow = 0; //can i lower it to 8 bits?

    for (int i = byte_size(result -> bit_size) - 1; i >= 0; i--) {

        sub = (inputs[0] -> list)[i] - borrow;

        if ((inputs[0] -> list)[i] < borrow)
            borrow = 1;
        else
            borrow = 0;

        for (int j = 1; j < n; j++) {
            if ((inputs[j] -> list)[i] > sub)
                borrow++;
            
            sub -= (inputs[j] -> list)[i];
        }
            
        //least byte of sub gets assigned
        (result -> list)[i] = sub;
    }

    return result;
}*/

CUDA_HOSTDEV BitString* MODSUB(BitString* input, uint16_t operand_bit_size) {
    uint16_t borrow = 0, operand_byte_size = byte_size(operand_bit_size); //16 bits should be more than enough
    uint16_t number_of_operands = byte_size(input -> bit_size) / operand_byte_size;
    uint8_t sub;

    BitString *result = zero_bitstring(operand_bit_size);

    for (int i = operand_byte_size - 1; i >= 0; i--) {

        sub = (input -> list)[i] - borrow;
        borrow = (input -> list)[i] < borrow ? 1 : 0;

        for (int j = 1; j < number_of_operands; j++) {
            if (input -> list[j*operand_byte_size + i] > sub)
                borrow++;
            
            sub -= (input -> list)[j*operand_byte_size + i];
        }

        //least byte of sub gets assigned
        (result -> list)[i] = sub;
    }

    return result;
}

//RIGHT SHIFT
CUDA_HOSTDEV BitString* right_shift(BitString *b, uint16_t shift_amount) {
    BitString *result = zero_bitstring(b -> bit_size);
    uint16_t last_shift = shift_amount % 8, bytes_to_shift = shift_amount / 8;
    uint8_t bits_to_shift, shifted_bits = 0;

    for (int i = bytes_to_shift; i < byte_size(b -> bit_size); i++) {
        bits_to_shift = b -> list[i - bytes_to_shift] % pow2(last_shift);
        result -> list[i] = (shifted_bits << (8 - last_shift)) + (b -> list[i - bytes_to_shift] >> last_shift);
        shifted_bits = bits_to_shift;
    }

    return result;

}

//LEFT SHIFT
CUDA_HOSTDEV BitString* left_shift(BitString *b, uint16_t shift_amount) {
    BitString *result = zero_bitstring(b -> bit_size);
    uint16_t last_shift = shift_amount % 8, bytes_to_shift = shift_amount / 8;
    uint8_t bits_to_shift, shifted_bits = 0;

    for (int i = byte_size(b -> bit_size) - bytes_to_shift; i >= 0; i--) {
        bits_to_shift = b -> list[i + bytes_to_shift] >> (8 - last_shift);
        result -> list[i] = (b -> list[i + bytes_to_shift] << last_shift) + shifted_bits;
        shifted_bits = bits_to_shift;
    }

    return result;

}

CUDA_HOSTDEV BitString* SHIFT(BitString *input, uint16_t output_bit_size, int shift_amount) {
    input -> bit_size = output_bit_size;

    if (shift_amount >= 0)
        return right_shift(input, shift_amount % output_bit_size);
    else
        return left_shift(input, -shift_amount % output_bit_size);

}

//RIGHT ROTATE
CUDA_HOSTDEV BitString* right_rotate(BitString *b, uint16_t rotation_amount) {
    BitString *result = zero_bitstring(b -> bit_size);

    //left shift
    uint16_t last_shift = (b -> bit_size - rotation_amount) % 8, bytes_to_shift = (b -> bit_size - rotation_amount) / 8;
    uint8_t bits_to_shift, shifted_bits = 0;

    for (int i = byte_size(b -> bit_size) - bytes_to_shift; i >= 0; i--) {
        bits_to_shift = b -> list[i + bytes_to_shift] >> (8 - last_shift);
        result -> list[i] = (b -> list[i + bytes_to_shift] << last_shift) + shifted_bits;
        shifted_bits = bits_to_shift;
    }

    //right_shift
    bytes_to_shift = rotation_amount / 8;
    last_shift = rotation_amount % 8;
    shifted_bits = 0;

    for (int i = bytes_to_shift; i < byte_size(b -> bit_size); i++) {
        bits_to_shift = b -> list[i - bytes_to_shift] % pow2(last_shift);
        result -> list[i] |= (shifted_bits << (8 - last_shift)) + (b -> list[i - bytes_to_shift] >> last_shift);
        shifted_bits = bits_to_shift;
    }

    return result;
}

//LEFT ROTATE
CUDA_HOSTDEV BitString* left_rotate(BitString *b, uint16_t rotation_amount) {

    BitString *result = zero_bitstring(b -> bit_size);

    //left shift
    uint16_t last_shift = rotation_amount % 8, bytes_to_shift = rotation_amount / 8;
    uint8_t bits_to_shift, shifted_bits = 0;

    for (int i = byte_size(b -> bit_size) - bytes_to_shift; i >= 0; i--) {
        bits_to_shift = b -> list[i + bytes_to_shift] >> (8 - last_shift);
        result -> list[i] = (b -> list[i + bytes_to_shift] << last_shift) + shifted_bits;
        shifted_bits = bits_to_shift;
    }

    //right_shift
    bytes_to_shift = (b -> bit_size - rotation_amount) / 8;
    last_shift = (b -> bit_size - rotation_amount) % 8;
    shifted_bits = 0;

    for (int i = bytes_to_shift; i < byte_size(b -> bit_size); i++) {
        bits_to_shift = b -> list[i - bytes_to_shift] % pow2(last_shift);
        result -> list[i] |= (shifted_bits << (8 - last_shift)) + (b -> list[i - bytes_to_shift] >> last_shift);
        shifted_bits = bits_to_shift;
    }

    return result;

}

CUDA_HOSTDEV BitString* ROTATE(BitString *input, uint16_t output_bit_size, int rotation_amount) {
    input -> bit_size = output_bit_size;

    if (rotation_amount >= 0)
        return right_rotate(input, rotation_amount % output_bit_size);
    else
        return left_rotate(input, -rotation_amount % output_bit_size);

}

//VARIABLE_AMOUNT
CUDA_HOSTDEV BitString* SHIFT_BY_VARIABLE_AMOUNT(BitString *input, uint16_t output_bit_size, int shift_direction) {
    uint16_t shift_amount = 0, output_byte_size = byte_size(output_bit_size);
    uint8_t i = byte_size(input -> bit_size) - 1;

    if (byte_size(input -> bit_size) - output_byte_size >= 2)
        shift_amount = (input -> list[i] | input -> list[i-1] << 8) % output_bit_size;
    else
        shift_amount = input -> list[i] % output_bit_size;

    BitString *b = copy_most_significant_bytes(input, output_bit_size);

    if (shift_direction >= 0)
        return right_shift(b, shift_amount);
    else
        return left_shift(b, shift_amount);

}

CUDA_HOSTDEV BitString* ROTATE_BY_VARIABLE_AMOUNT(BitString *input, uint16_t output_bit_size, int rotation_direction) {
    uint16_t rotation_amount = 0, output_byte_size = byte_size(output_bit_size);
    uint8_t i = byte_size(input -> bit_size) - 1;

    if (byte_size(input -> bit_size) - output_byte_size >= 2)
        rotation_amount = (input -> list[i] | input -> list[i-1] << 8) % output_bit_size;
    else
        rotation_amount = input -> list[i] % output_bit_size;

    BitString *b = copy_most_significant_bytes(input, output_bit_size);

    if (rotation_direction >= 0)
        return right_rotate(b, rotation_amount);
    else
        return left_rotate(b, rotation_amount);
}

//SBOX
//For now it only supports bitstrings up to 64 bits, but this limitation can be easily (?) removed
CUDA_HOSTDEV BitString* SBOX(BitString* input, uint16_t output_bit_size, uint64_t* sbox) {
    uint64_t input_value = bitstring_to_uint(input);
    uint64_t output_value = sbox[input_value];

    return bitstring_from_int(output_value, output_bit_size);
}

CUDA_HOSTDEV uint64_t carryless_product(uint64_t a, uint64_t b, uint16_t bit_size) {
    uint64_t result = 0;

    for (int i = 0; i < bit_size; i++)
        if ((a >> i) & 1)
            result ^= (b << i);

    return result;
}

CUDA_HOSTDEV BitString* MIX_COLUMNS(BitString *input, uint64_t **matrix, uint64_t polynomial, uint16_t word_bit_size) {
    BitString *result = zero_bitstring(input -> bit_size);

    uint16_t column_size = input -> bit_size / word_bit_size, word_byte_size = byte_size(word_bit_size), bit_index;
    uint16_t bit_offset;
    uint64_t result_value, input_value;

    if (input -> bit_size % 8 != 0)
        bit_offset = 8 - input -> bit_size % 8;
    else
        bit_offset = 0;

    for (int i = 0; i < column_size; i++)
        for (int j = 0; j < column_size; j++) {

            input_value = 0;

            //extract the value from the input
            for (int b = 0; b < word_bit_size; b++) {
                bit_index = b + i * word_bit_size;
                
                if (get(input, b + j * word_bit_size))
                    input_value |= pow2(word_bit_size - b - 1);
            }

            result_value = carryless_product(input_value, matrix[i][j], word_bit_size);

            if (polynomial != 0)
                result_value = result_value % polynomial;

            for (int b = 0; b < word_bit_size; b++) {
                bit_index = b + i * word_bit_size;

                if ((result_value >> word_bit_size - b - 1) & 1)
                    result -> list[(bit_index + bit_offset) / 8] ^= pow2(7 - ((bit_index + bit_offset) % 8));

            }
        }

    return result;

}

CUDA_HOSTDEV BitString* LINEAR_LAYER(BitString *input, uint8_t **linear_transformation) {
    BitString *result = zero_bitstring(input -> bit_size);

    for (int i = 0; i < input -> bit_size; i++)
        for (int j = 0; j < input -> bit_size; j++)
            if (linear_transformation[j][i] & get(input, j))
                set(result, i, !get(result, i));

    return result;
}

CUDA_HOSTDEV BitString* PADDING(BitString *input, uint16_t output_bit_size) {
    BitString *result = zero_bitstring(output_bit_size);
    uint16_t offset = byte_size(output_bit_size) - byte_size(input -> bit_size);
    memcpy(result -> list + offset, input -> list, byte_size(input -> bit_size));

    return result;
}