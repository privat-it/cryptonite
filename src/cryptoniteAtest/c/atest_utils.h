/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_ATEST_UTILS_H
#define CRYPTONITE_ATEST_UTILS_H

#include "test_utils.h"

#define PRINT_ERROR(print, count) if (error_count != count) {PR("%s : LINE: %u", __FILE__, __LINE__); print;}

int msg_print_atest(const char *name, const char *modes, const char *res);

#define ATEST_CORE(test_data, test_func, type_size)                     \
{                                                                       \
    size_t i = 0;                                                       \
    for (i = 0; i < sizeof (test_data) / type_size; i++) {              \
        test_func(&test_data[i]);                                       \
    }                                                                   \
}

typedef struct {
    char *data;
    char *hash;
} HashTestCtx;

typedef struct {
    char *data;
    char *key;
    char *expected;
} HmacTestCtx;

void print_hash_error(const char *name, const ByteArray *data);
void print_hmac_error(const char *name, const ByteArray *key, const ByteArray *data);
void print_cipher_error(const char *name, const ByteArray *key, const ByteArray *iv, const ByteArray *data);


#endif

