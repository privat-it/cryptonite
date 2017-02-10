/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdlib.h>

#include "base64_utils_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "cryptonite/base64_utils_internal.c"

static char encoding_table[] = 
{
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/'
};

static char *dec_table = NULL;
static size_t mod_table[] = {0, 2, 1};

static void build_dec_table(void)
{
    char i = 0;
    dec_table = malloc(256);

    for (i = 0; i < 64; i++) {
        dec_table[(int) encoding_table[(int)i]] = i;
    }
}

char *base64_encode(const uint8_t *data, size_t input_length, size_t *output_length)
{
    uint32_t octet_a;
    uint32_t octet_b;
    uint32_t octet_c;
    uint32_t triple;
    size_t i, j;
    char *encoded_data = NULL;
    
    *output_length = ((input_length + 2) / 3) << 2;

    encoded_data = malloc(*output_length);
    
    if (encoded_data == NULL) {
        return NULL;
    }

    for (i = 0, j = 0; i < input_length;) {

        octet_a = i < input_length ? (uint8_t) data[i++] : 0;
        octet_b = i < input_length ? (uint8_t) data[i++] : 0;
        octet_c = i < input_length ? (uint8_t) data[i++] : 0;

        triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 18) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 12) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >>  6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >>  0) & 0x3F];
    }

    for (i = 0; i < mod_table[input_length % 3]; i++) {
        encoded_data[*output_length - 1 - i] = '=';
    }

    return encoded_data;
}

static void base64_cleanup(void)
{
    free(dec_table);
    dec_table = NULL;
}

static uint32_t set_data(char data)
{
    if (data == '=') {
        return 0;
    } else {
        return dec_table[(int)data];
    }
}

uint8_t *base64_decode(const char *data, size_t input_length, size_t *output_length)
{
    uint8_t *decoded_data = NULL;
    uint32_t sextet_a;
    uint32_t sextet_b;
    uint32_t sextet_c;
    uint32_t sextet_d;
    uint32_t triple;
    size_t i, j;
    
    if (dec_table == NULL) {
        build_dec_table();
    }

    if (input_length % 4 != 0) {
        return NULL;
    }
    
    *output_length = (input_length >> 2) * 3;
    if (data[input_length - 1] == '=') {
        (*output_length)--;
    }
    if (data[input_length - 2] == '=') {
        (*output_length)--;
    }

    decoded_data = malloc(*output_length);
    if (decoded_data == NULL) {
        return NULL;
    }

    j = 0;
    for (i = 0; i < input_length;) {
        sextet_a = set_data(data[i]);
        i++;
        sextet_b = set_data(data[i]);
        i++;
        sextet_c = set_data(data[i]);
        i++;
        sextet_d = set_data(data[i]);
        i++;
        
        triple = (sextet_a << (18)) + (sextet_b << (12))
                + (sextet_c << (6)) + (sextet_d << ( 0));

        if (j < *output_length) {
            decoded_data[j++] = (triple >> (16)) & 0xFF;
        }
        if (j < *output_length) {
            decoded_data[j++] = (triple >> ( 8)) & 0xFF;
        }
        if (j < *output_length) {
            decoded_data[j++] = (triple >> ( 0)) & 0xFF;
        }
    }
    
    base64_cleanup();
    
    return decoded_data;
}
