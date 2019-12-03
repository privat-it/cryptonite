/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "atest_utils.h"

int msg_print_atest(const char *name, const char *modes, const char *res)
{
    char *dot_buf_modes = NULL; //Массив точек после имени и до режимов.
    char *dot_buf_name = NULL; //Массив точек после режимов.
    size_t name_s;
    size_t modes_s;
    size_t res_s;
    int dot_count_name; //Для подсчета количества точек после названия алгоритма и перед режимами
    int dot_count_modes; // Для подсчета количества точек после режима и до результата
    int ret = RET_OK;

    modes_s = strlen(modes);
    name_s = strlen(name);
    res_s = strlen(res);

    if (name_s > 20) {
        return RET_INVALID_PARAM;
    }

    dot_count_name = (int)(20 - name_s);
    dot_count_modes = (int)(SIZE_STR - 20 - modes_s - res_s - 2);

    if (dot_count_modes < 0) {
        PR("Message total len > 80. Error.\n");
        ret = RET_INVALID_PARAM;
        goto cleanup;
    }

    dot_buf_name = &DOT_STRING80[DOT_STRING_SIZE - dot_count_name - 1];

    dot_buf_modes = &DOT_STRING80[DOT_STRING_SIZE - dot_count_modes - 1];

    if (modes_s != 0) {
        PR("%s%s%s%s%s", name, dot_buf_name, modes, dot_buf_modes, res);
    } else {
        PR("%s%s%s%s", name, dot_buf_name, dot_buf_modes, res);
    }
    PR("\n");
cleanup:

    return ret;
}

void print_hash_error(const char *name, const ByteArray *data)
{
    print_cipher_error(name, NULL, NULL, data);
}

void print_hmac_error(const char *name, const ByteArray *key, const ByteArray *data)
{
    print_cipher_error(name, key, NULL, data);
}

void print_cipher_error(const char *name, const ByteArray *key, const ByteArray *iv, const ByteArray *data)
{
    PR("\n%s\n", name);
    if (key) {
        PR("KEY: ");
        ba_print(stdout, key);
    }
    if (iv) {
        PR("IV: ");
        ba_print(stdout, iv);
    }
    PR("DATA: ");
    ba_print(stdout, data);
}
