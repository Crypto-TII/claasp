#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

#ifdef __CUDACC__
#define CUDA_HOSTDEV __host__ __device__
#else
#define CUDA_HOSTDEV
#endif

#define uint128_t __uint128_t
#define delete(...) delete_multiple_bitstrings(sizeof((BitString* []) {__VA_ARGS__}) / sizeof(BitString*), __VA_ARGS__)

//msb are at the beginning (index 0)
typedef struct {
    uint8_t *list;
    uint16_t bit_size;
} BitString;

//Util functions
CUDA_HOSTDEV BitString* copy(BitString *b);
CUDA_HOSTDEV uint8_t get(BitString *b, uint16_t i);

CUDA_HOSTDEV char* bitstring_to_binary_string(BitString* b);
CUDA_HOSTDEV char* bitstring_to_decimal_string(BitString* b);
CUDA_HOSTDEV char* bitstring_to_hex_string(BitString* b);
CUDA_HOSTDEV void print_bitstring(BitString* b, uint8_t base);

CUDA_HOSTDEV bool equals(BitString *b1, BitString *b2);
CUDA_HOSTDEV void delete_bitstring(BitString *b);
CUDA_HOSTDEV void delete_multiple_bitstrings(int n, ...);
CUDA_HOSTDEV BitString* select_bits(uint8_t n, BitString** b, uint16_t** bit_positions, uint16_t component_output_size);
CUDA_HOSTDEV BitString** select_bits_and_split(uint8_t n, BitString** b, uint16_t** bit_positions, uint8_t number_of_operands);

//Constructors
CUDA_HOSTDEV BitString* zero_bitstring(uint16_t bit_size);
CUDA_HOSTDEV BitString* bitstring_from_binary_string(char *bits, uint16_t bit_size);
CUDA_HOSTDEV BitString* bitstring_from_hex_string(char *hex_digits, uint16_t bit_size);
CUDA_HOSTDEV BitString* bitstring_from_int(uint64_t value, uint16_t bit_size);

//Operations
CUDA_HOSTDEV BitString* NOT(BitString* input, uint16_t operand_bit_size);

//BitString* var_and(uint8_t n, ...);
//BitString* array_and(uint8_t n, BitString* inputs[n]);
CUDA_HOSTDEV BitString* AND(BitString* input, uint16_t operand_bit_size);

//BitString* var_or(uint8_t n, ...);
//BitString* array_or(uint8_t n, BitString* inputs[n]);
CUDA_HOSTDEV BitString* OR(BitString* input, uint16_t operand_bit_size);

//BitString* var_xor(uint8_t n, ...);
//BitString* array_xor(uint8_t n, BitString* inputs[n]);
CUDA_HOSTDEV BitString* XOR(BitString* input, uint16_t operand_bit_size);

//BitString* var_modadd(uint8_t n, ...);
//BitString* array_modadd(uint8_t n, BitString* inputs[n]);
CUDA_HOSTDEV BitString* MODADD(BitString* input, uint16_t operand_bit_size);

//BitString* var_modsub(uint8_t n, ...);
//BitString* array_modsub(uint8_t n, BitString* inputs[n]);
CUDA_HOSTDEV BitString* MODSUB(BitString* input, uint16_t operand_bit_size);

CUDA_HOSTDEV BitString* right_shift(BitString *b, uint16_t shift_amount);
CUDA_HOSTDEV BitString* left_shift(BitString *b, uint16_t shift_amount);
CUDA_HOSTDEV BitString* SHIFT(BitString *input, uint16_t output_bit_size, int shift_amount);

CUDA_HOSTDEV BitString* SHIFT_BY_VARIABLE_AMOUNT(BitString *input, uint16_t output_bit_size, int shift_direction);

CUDA_HOSTDEV BitString* right_rotate(BitString *b, uint16_t rotation_amount);
CUDA_HOSTDEV BitString* left_rotate(BitString *b, uint16_t rotation_amount);
CUDA_HOSTDEV BitString* ROTATE(BitString *input, uint16_t output_bit_size, int rotation_amount);

CUDA_HOSTDEV BitString* ROTATE_BY_VARIABLE_AMOUNT(BitString *input, uint16_t output_bit_size, int rotation_direction);

CUDA_HOSTDEV BitString* SBOX(BitString* input, uint16_t output_bit_size, uint64_t* sbox);

CUDA_HOSTDEV BitString* MIX_COLUMNS(BitString *input, uint64_t **matrix, uint64_t polynomial, uint16_t word_bit_size);

CUDA_HOSTDEV BitString* LINEAR_LAYER(BitString *input, uint8_t **matrix);

CUDA_HOSTDEV BitString* PADDING(BitString *input, uint16_t output_bit_size);