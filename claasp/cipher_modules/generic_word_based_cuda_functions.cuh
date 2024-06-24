#include <stdint.h>
#include <stdarg.h>
#include <string.h>

#ifdef __CUDACC__
#define CUDA_HOSTDEV __host__ __device__
#else
#define CUDA_HOSTDEV
#endif

#ifndef word_size
    #define word_size 64
    #define hex_word_format "%016lx"
#endif

#if word_size == 8
    #define Word uint8_t
    #define hex_word_format "%02x"
#elif word_size == 16
    #define Word uint16_t
    #define hex_word_format "%04x"
#elif word_size == 32
    #define Word uint32_t
    #define hex_word_format "%08x"
#elif word_size == 64
    #define Word uint64_t
    #define hex_word_format "%016lx"
#else
    #error Unexpected word size.
#endif

#define delete(...) delete_multiple_wordstrings(sizeof((WordString* []) {__VA_ARGS__}) / sizeof(WordString*), __VA_ARGS__)

typedef struct {
    Word *list;
    uint16_t string_size; //in words
} WordString;

CUDA_HOSTDEV void delete_multiple_wordstrings(int n, ...);
CUDA_HOSTDEV void delete_wordstring(WordString *w);

CUDA_HOSTDEV WordString* create_wordstring(uint16_t string_size, bool zero);
CUDA_HOSTDEV WordString* wordstring_from_hex_string(char *hex_digits, uint16_t string_size);

CUDA_HOSTDEV char* wordstring_to_hex_string(WordString* w);

CUDA_HOSTDEV void print_wordstring(WordString* b, uint8_t base);
CUDA_HOSTDEV void print_wordstring1(WordString* b, uint8_t base);

CUDA_HOSTDEV WordString* NOT(WordString *input);

CUDA_HOSTDEV WordString* XOR(WordString *input);
CUDA_HOSTDEV WordString* OR(WordString *input);
CUDA_HOSTDEV WordString* AND(WordString *input);

CUDA_HOSTDEV WordString* MODADD(WordString *input);
CUDA_HOSTDEV WordString* MODSUB(WordString *input);

CUDA_HOSTDEV WordString* LEFT_SHIFT(WordString *input, uint8_t shift_amount);
CUDA_HOSTDEV WordString* RIGHT_SHIFT(WordString *input, uint8_t shift_amount);

CUDA_HOSTDEV WordString* LEFT_ROTATE(WordString *input, uint8_t rotate_amount);
CUDA_HOSTDEV WordString* RIGHT_ROTATE(WordString *input, uint8_t rotate_amount);

CUDA_HOSTDEV WordString* LEFT_SHIFT_BY_VARIABLE_AMOUNT(WordString *input);
CUDA_HOSTDEV WordString* RIGHT_SHIFT_BY_VARIABLE_AMOUNT(WordString *input);

CUDA_HOSTDEV WordString* LEFT_ROTATE_BY_VARIABLE_AMOUNT(WordString *input);
CUDA_HOSTDEV WordString* RIGHT_ROTATE_BY_VARIABLE_AMOUNT(WordString *input);