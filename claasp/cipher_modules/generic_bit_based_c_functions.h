#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

#define uint128_t __uint128_t
#define delete(...) delete_multiple_bitstrings(sizeof((BitString* []) {__VA_ARGS__}) / sizeof(BitString*), __VA_ARGS__)

//msb are at the beginning (index 0)
typedef struct {
    uint8_t *list;
    uint16_t bit_size;
} BitString;

//Util functions
BitString* copy(BitString *b);
uint8_t get(BitString *b, uint16_t i);

char* bitstring_to_binary_string(BitString* b);
char* bitstring_to_decimal_string(BitString* b);
char* bitstring_to_hex_string(BitString* b);
void print_bitstring(BitString* b, uint8_t base);

bool equals(BitString *b1, BitString *b2);
void delete_bitstring(BitString *b);
void delete_multiple_bitstrings(int n, ...);
BitString* select_bits(uint8_t n, BitString* b[n], uint16_t* bit_positions[n], uint16_t component_output_size);
BitString** select_bits_and_split(uint8_t n, BitString* b[n], uint16_t* bit_positions[n], uint8_t number_of_operands);

//Constructors
BitString* zero_bitstring(uint16_t bit_size);
BitString* bitstring_from_binary_string(char *bits, uint16_t bit_size);
BitString* bitstring_from_hex_string(char *hex_digits, uint16_t bit_size);
BitString* bitstring_from_int(uint128_t value, uint16_t bit_size);

//Operations
BitString* NOT(BitString* input, uint16_t operand_bit_size);

//BitString* var_and(uint8_t n, ...);
//BitString* array_and(uint8_t n, BitString* inputs[n]);
BitString* AND(BitString* input, uint16_t operand_bit_size);

//BitString* var_or(uint8_t n, ...);
//BitString* array_or(uint8_t n, BitString* inputs[n]);
BitString* OR(BitString* input, uint16_t operand_bit_size);

//BitString* var_xor(uint8_t n, ...);
//BitString* array_xor(uint8_t n, BitString* inputs[n]);
BitString* XOR(BitString* input, uint16_t operand_bit_size);

//BitString* var_modadd(uint8_t n, ...);
//BitString* array_modadd(uint8_t n, BitString* inputs[n]);
BitString* MODADD(BitString* input, uint16_t operand_bit_size);

//BitString* var_modsub(uint8_t n, ...);
//BitString* array_modsub(uint8_t n, BitString* inputs[n]);
BitString* MODSUB(BitString* input, uint16_t operand_bit_size);

BitString* right_shift(BitString *b, uint16_t shift_amount);
BitString* left_shift(BitString *b, uint16_t shift_amount);
BitString* SHIFT(BitString *input, uint16_t output_bit_size, int shift_amount);

BitString* SHIFT_BY_VARIABLE_AMOUNT(BitString *input, uint16_t output_bit_size, int shift_direction);

BitString* right_rotate(BitString *b, uint16_t rotation_amount);
BitString* left_rotate(BitString *b, uint16_t rotation_amount);
BitString* ROTATE(BitString *input, uint16_t output_bit_size, int rotation_amount);

BitString* ROTATE_BY_VARIABLE_AMOUNT(BitString *input, uint16_t output_bit_size, int rotation_direction);

BitString* SBOX(BitString* input, uint16_t output_bit_size, uint64_t* sbox);

BitString* MIX_COLUMNS(BitString *input, uint64_t **matrix, uint64_t polynomial, uint16_t word_bit_size);

BitString* LINEAR_LAYER(BitString *input, uint8_t **matrix);

BitString* PADDING(BitString *input, uint16_t output_bit_size);