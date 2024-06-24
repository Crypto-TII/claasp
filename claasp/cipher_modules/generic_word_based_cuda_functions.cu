#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include "generic_word_based_cuda_functions.cuh"


// Device function to calculate the length of a string
CUDA_HOSTDEV size_t cuda_strlen(const char *str) {
    const char *s = str;
    while (*s) {
        s++;
    }
    return s - str;
}

CUDA_HOSTDEV int char_to_int(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'A' && c <= 'Z') {
        return c - 'A' + 10;
    } else if (c >= 'a' && c <= 'z') {
        return c - 'a' + 10;
    }
    return -1;
}

CUDA_HOSTDEV unsigned long cuda_strtoul(const char *str, char **endptr, int base) {
    unsigned long result = 0;
    int digit;
    while ((digit = char_to_int(*str)) >= 0 && digit < base) {
        result = result * base + digit;
        str++;
    }
    if (endptr) {
        *endptr = (char *)str;
    }
    return result;
}


CUDA_HOSTDEV void delete_multiple_wordstrings(int n, ...) {
    va_list args;
    va_start(args, n);

    for (int i = 0; i < n; i++)
        delete_wordstring(va_arg(args, WordString*));

    va_end(args);

}

CUDA_HOSTDEV void delete_wordstring(WordString *w) {
    free(w -> list);
    free(w);
}

CUDA_HOSTDEV WordString* create_wordstring(uint16_t string_size, bool zero) {
    WordString *w = (WordString *) malloc(sizeof(WordString));

    if (w == NULL) {
        printf("malloc() failed.");
        return NULL;
    }

    if (zero) {
        w -> list = (Word*)  malloc(string_size * sizeof(Word));
        memset(w -> list, 0, string_size * sizeof(Word));
    } else {
        w -> list = (Word*)  malloc(string_size * sizeof(Word));
        memset(w -> list, 0, string_size * sizeof(Word));
    }

    if (w -> list == NULL) {
        printf("malloc() failed.");
        free(w);
        return NULL;
    }

    w -> string_size = string_size;

    return w;
}

CUDA_HOSTDEV WordString* wordstring_from_hex_string(char *hex_digits, uint16_t string_size) {
    WordString *result = create_wordstring(string_size, false);
    uint16_t hex_length = cuda_strlen(hex_digits), k = string_size;
    uint8_t hex_symbols_per_word = word_size / 4;
    char * app = (char *)malloc(hex_symbols_per_word*sizeof(char));
    //char app[hex_symbols_per_word];

    for (int i = hex_length - 1; i >= 1 + hex_symbols_per_word; i -= hex_symbols_per_word) {
        for (int j = 0; j < hex_symbols_per_word; j++)
            app[j] = hex_digits[i - (hex_symbols_per_word - 1 - j)];

        result -> list[--k] = cuda_strtoul(app, NULL, 16);
    }

    if ((hex_length - 2) % hex_symbols_per_word != 0) {
        for (int j = hex_symbols_per_word - ((hex_length - 2) % hex_symbols_per_word); j < hex_symbols_per_word; j++)
            app[j] = hex_digits[2 + j - (hex_symbols_per_word - ((hex_length - 2) % hex_symbols_per_word))];

        result -> list[--k] = cuda_strtoul(app + hex_symbols_per_word - ((hex_length - 2) % hex_symbols_per_word), NULL, 16);
    }
    free(app);
    return result;
}


CUDA_HOSTDEV char* cuda_strcpy(char *dest, const char *src) {
    char *d = dest;
    const char *s = src;
    while ((*d++ = *s++) != '\0') {
        // copying each character from src to dest
    }
    return dest;
}

CUDA_HOSTDEV char* wordstring_to_hex_string(WordString* w) {
    uint8_t hex_symbols_per_word = word_size / 4;
    char *str = (char *)malloc((w -> string_size * hex_symbols_per_word) + 3);
    memset(str, 0, (w -> string_size * hex_symbols_per_word) + 3);
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


CUDA_HOSTDEV char* wordstring_to_hex_string1(WordString* w) {
    uint8_t hex_symbols_per_word = word_size / 4;
    char *str = (char *)malloc((w -> string_size * hex_symbols_per_word) + 3);
    str[(w -> string_size * hex_symbols_per_word) + 2] = '\0';

    if (str == NULL) {
        printf("malloc() failed");
        return NULL;
    }

    str = cuda_strcpy(str, "0x");
    printf("str: %s\n", str);

    for (int i = 0; i < w -> string_size; i++)
        sprintf(str + 2 + (i*hex_symbols_per_word), hex_word_format, (w -> list)[i]);

    return str;
}


CUDA_HOSTDEV void print_wordstring1(WordString* b, uint8_t base) {
    char *str;

    switch (base) {
        /*case 2:
            str = wordstring_to_binary_string(b);
        case 10:
            str = wordstring_to_decimal_string(b);*/
        case 16:
            str = wordstring_to_hex_string1(b);
            break;

        default:
            printf("Invalid base.\n");
            exit(-1);
    }

    printf("%s\n", str);
    free(str);
}

CUDA_HOSTDEV void print_wordstring(WordString* b, uint8_t base) {
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

CUDA_HOSTDEV WordString* NOT(WordString *input) {

    WordString *result = create_wordstring(input -> string_size, true);

    for (int i = 0; i < input -> string_size; i++)
        result -> list[i] = ~(input -> list[i]);

    return result;
}

CUDA_HOSTDEV WordString* XOR(WordString *input) {

    WordString *result = create_wordstring(1, true);

    for (int i = 0; i < input -> string_size; i++)
        *(result -> list) ^= input -> list[i];

    return result;
}

CUDA_HOSTDEV WordString* OR(WordString *input) {

    WordString *result = create_wordstring(1, true);

    for (int i = 0; i < input -> string_size; i++)
        *(result -> list) |= input -> list[i];

    return result;
}

CUDA_HOSTDEV WordString* AND(WordString *input) {

    WordString *result = create_wordstring(1, false);
    *(result -> list) = input -> list[0];

    for (int i = 1; i < input -> string_size; i++)
        *(result -> list) &= input -> list[i];

    return result;
}

CUDA_HOSTDEV WordString* MODADD(WordString *input) {

    WordString *result = create_wordstring(1, true);

    for (int i = 0; i < input -> string_size; i++)
        *(result -> list) += input -> list[i];

    return result;
}

CUDA_HOSTDEV WordString* MODSUB(WordString *input) {

    WordString *result = create_wordstring(1, false);
    *(result -> list) = input -> list[0];

    for (int i = 1; i < input -> string_size; i++)
        *(result -> list) -= input -> list[i];

    return result;
}

CUDA_HOSTDEV WordString* LEFT_SHIFT(WordString *input, uint8_t shift_amount) {
    WordString *result = create_wordstring(1, false);
    *(result -> list) = *(input -> list) << shift_amount;

    return result;
}

CUDA_HOSTDEV WordString* RIGHT_SHIFT(WordString *input, uint8_t shift_amount) {
    WordString *result = create_wordstring(1, false);
    *(result -> list) = *(input -> list) >> shift_amount;

    return result;
}

CUDA_HOSTDEV WordString* LEFT_ROTATE(WordString *input, uint8_t rotate_amount) {
    WordString *result = create_wordstring(1, false);
    *(result -> list) = (*(input -> list) << rotate_amount) | (*(input -> list) >> (word_size - rotate_amount));

    return result;
}

CUDA_HOSTDEV WordString* RIGHT_ROTATE(WordString *input, uint8_t rotate_amount) {
    WordString *result = create_wordstring(1, false);
    *(result -> list) = (*(input -> list) >> rotate_amount) | (*(input -> list) << (word_size - rotate_amount));

    return result;
}

CUDA_HOSTDEV WordString* LEFT_SHIFT_BY_VARIABLE_AMOUNT(WordString *input) {
    return LEFT_SHIFT(input, input -> list[1] % word_size);
}

CUDA_HOSTDEV WordString* RIGHT_SHIFT_BY_VARIABLE_AMOUNT(WordString *input) {
    return RIGHT_SHIFT(input, input -> list[1] % word_size);
}

CUDA_HOSTDEV WordString* LEFT_ROTATE_BY_VARIABLE_AMOUNT(WordString *input) {
    return LEFT_ROTATE(input, input -> list[1] % word_size);
}

CUDA_HOSTDEV WordString* RIGHT_ROTATE_BY_VARIABLE_AMOUNT(WordString *input) {
    return RIGHT_ROTATE(input, input -> list[1] % word_size);
}