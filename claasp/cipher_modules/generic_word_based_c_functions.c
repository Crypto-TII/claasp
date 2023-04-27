#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include "generic_word_based_c_functions.h"

void delete_multiple_wordstrings(int n, ...) {
    va_list args;
    va_start(args, n);

    for (int i = 0; i < n; i++)
        delete_wordstring(va_arg(args, WordString*));

    va_end(args);

}

void delete_wordstring(WordString *w) {
    free(w -> list);
    free(w);
}

WordString* create_wordstring(uint16_t string_size, bool zero) {
    WordString *w = malloc(sizeof(WordString));

    if (w == NULL) {
        printf("malloc() failed.");
        return NULL;
    }

    if (zero)
        w -> list = calloc(string_size, sizeof(Word));
    else
        w -> list = malloc(string_size * sizeof(Word));

    if (w -> list == NULL) {
        printf("malloc() failed.");
        free(w);
        return NULL;
    }

    w -> string_size = string_size;

    return w;
}

WordString* wordstring_from_hex_string(char *hex_digits, uint16_t string_size) {
    WordString *result = create_wordstring(string_size, false);
    uint16_t hex_length = strlen(hex_digits), k = string_size;
    uint8_t hex_symbols_per_word = word_size / 4;
    char app[hex_symbols_per_word];

    for (int i = hex_length - 1; i >= 1 + hex_symbols_per_word; i -= hex_symbols_per_word) {
        for (int j = 0; j < hex_symbols_per_word; j++)
            app[j] = hex_digits[i - (hex_symbols_per_word - 1 - j)];

        result -> list[--k] = strtoul(app, NULL, 16);
    }

    if ((hex_length - 2) % hex_symbols_per_word != 0) {
        for (int j = hex_symbols_per_word - ((hex_length - 2) % hex_symbols_per_word); j < hex_symbols_per_word; j++)
            app[j] = hex_digits[2 + j - (hex_symbols_per_word - ((hex_length - 2) % hex_symbols_per_word))];

        result -> list[--k] = strtoul(app + hex_symbols_per_word - ((hex_length - 2) % hex_symbols_per_word), NULL, 16);
    }

    return result;
}

char* wordstring_to_hex_string(WordString* w) {
    uint8_t hex_symbols_per_word = word_size / 4;
    char *str = malloc((w -> string_size * hex_symbols_per_word) + 3);
    str[(w -> string_size * hex_symbols_per_word) + 2] = '\0';

    if (str == NULL) {
        printf("malloc() failed");
        return NULL;
    }

    str = strcpy(str, "0x");

    for (int i = 0; i < w -> string_size; i++)
        sprintf(str + 2 + (i*hex_symbols_per_word), hex_word_format, (w -> list)[i]);

    return str;
}

void print_wordstring(WordString* b, uint8_t base) {
    char *str;

    switch (base) {
        /*case 2:
            str = wordstring_to_binary_string(b);
        case 10:
            str = wordstring_to_decimal_string(b);*/
        case 16:
            str = wordstring_to_hex_string(b);
            break;
        
        default:
            printf("Invalid base.\n");
            exit(-1);
    }

    printf("%s\n", str);
    free(str);
}

WordString* NOT(WordString *input) {

    WordString *result = create_wordstring(input -> string_size, true);

    for (int i = 0; i < input -> string_size; i++)
        result -> list[i] = ~(input -> list[i]);

    return result;
}

WordString* XOR(WordString *input) {

    WordString *result = create_wordstring(1, true);

    for (int i = 0; i < input -> string_size; i++)
        *(result -> list) ^= input -> list[i];

    return result;
}

WordString* OR(WordString *input) {

    WordString *result = create_wordstring(1, true);

    for (int i = 0; i < input -> string_size; i++)
        *(result -> list) |= input -> list[i];

    return result;
}

WordString* AND(WordString *input) {

    WordString *result = create_wordstring(1, false);
    *(result -> list) = input -> list[0];

    for (int i = 1; i < input -> string_size; i++)
        *(result -> list) &= input -> list[i];

    return result;
}

WordString* MODADD(WordString *input) {

    WordString *result = create_wordstring(1, true);

    for (int i = 0; i < input -> string_size; i++)
        *(result -> list) += input -> list[i];

    return result;
}

WordString* MODSUB(WordString *input) {

    WordString *result = create_wordstring(1, false);
    *(result -> list) = input -> list[0];

    for (int i = 1; i < input -> string_size; i++)
        *(result -> list) -= input -> list[i];

    return result;
}

WordString* LEFT_SHIFT(WordString *input, uint8_t shift_amount) {
    WordString *result = create_wordstring(1, false);
    *(result -> list) = *(input -> list) << shift_amount;

    return result;
}

WordString* RIGHT_SHIFT(WordString *input, uint8_t shift_amount) {
    WordString *result = create_wordstring(1, false);
    *(result -> list) = *(input -> list) >> shift_amount;

    return result;
}

WordString* LEFT_ROTATE(WordString *input, uint8_t rotate_amount) {
    WordString *result = create_wordstring(1, false);
    *(result -> list) = (*(input -> list) << rotate_amount) | (*(input -> list) >> (word_size - rotate_amount));

    return result;
}

WordString* RIGHT_ROTATE(WordString *input, uint8_t rotate_amount) {
    WordString *result = create_wordstring(1, false);
    *(result -> list) = (*(input -> list) >> rotate_amount) | (*(input -> list) << (word_size - rotate_amount));

    return result;
}

WordString* LEFT_SHIFT_BY_VARIABLE_AMOUNT(WordString *input) {
    return LEFT_SHIFT(input, input -> list[1] % word_size);
}

WordString* RIGHT_SHIFT_BY_VARIABLE_AMOUNT(WordString *input) {
    return RIGHT_SHIFT(input, input -> list[1] % word_size);
}

WordString* LEFT_ROTATE_BY_VARIABLE_AMOUNT(WordString *input) {
    return LEFT_ROTATE(input, input -> list[1] % word_size);
}

WordString* RIGHT_ROTATE_BY_VARIABLE_AMOUNT(WordString *input) {
    return RIGHT_ROTATE(input, input -> list[1] % word_size);
}