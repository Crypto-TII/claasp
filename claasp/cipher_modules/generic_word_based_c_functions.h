#include <stdint.h>
#include <stdarg.h>
#include <string.h>

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

void delete_multiple_wordstrings(int n, ...);
void delete_wordstring(WordString *w);

WordString* create_wordstring(uint16_t string_size, bool zero);
WordString* wordstring_from_hex_string(char *hex_digits, uint16_t string_size);

char* wordstring_to_hex_string(WordString* w);

void print_wordstring(WordString* b, uint8_t base);

WordString* NOT(WordString *input);

WordString* XOR(WordString *input);
WordString* OR(WordString *input);
WordString* AND(WordString *input);

WordString* MODADD(WordString *input);
WordString* MODSUB(WordString *input);

WordString* LEFT_SHIFT(WordString *input, uint8_t shift_amount);
WordString* RIGHT_SHIFT(WordString *input, uint8_t shift_amount);

WordString* LEFT_ROTATE(WordString *input, uint8_t rotate_amount);
WordString* RIGHT_ROTATE(WordString *input, uint8_t rotate_amount);

WordString* LEFT_SHIFT_BY_VARIABLE_AMOUNT(WordString *input);
WordString* RIGHT_SHIFT_BY_VARIABLE_AMOUNT(WordString *input);

WordString* LEFT_ROTATE_BY_VARIABLE_AMOUNT(WordString *input);
WordString* RIGHT_ROTATE_BY_VARIABLE_AMOUNT(WordString *input);