/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdio.h>
#include <stdlib.h>

#include "xtest.h"

#define XTEST_LIB_NUM 3

typedef enum {
    MODE_16b = 16,
    MODE_32b = 32,
    MODE_64b = 64,
    MODE_256b = 256,
    MODE_1kb = 1 * 1024,
    MODE_8kb = 8 * 1024,
    MODE_2kb = 2 * 1024,
    MODE_4kb = 4 * 1024,
    MODE_32kb = 32 * 1024,
    MODE_256kb = 256 * 1024,
    MODE_4mb = 4 * 1024 * 1024,
    MODE_32mb = 32 * 1024 * 1024,
    MODE_256mb = 256 * 1024 * 1024,
} SizeMode;

int main(void)
{
    TableBuilder *ctx = NULL;
    XtestSt *xtest_ctx = NULL;

    LOOP_NUM = 5000;
    PR("\n+------------------------------------------------------------------------------+\n");
    PR("           CROSS TESTS (data = 2048 B, %d loops, 1 thread)                   \n", LOOP_NUM);
    PR("+------------------------------------------------------------------------------+\n");
    data_size_byte = MODE_2kb;
    xtest_ctx = rnd_generate(data_size_byte);
#if !(defined(__APPLE__) || defined(__arm__) || defined(__aarch64__) || (defined(__unix__) && !(__linux__)))
    ctx = table_builder_alloc(2);

    add_lib_name(ctx, "Libcppcrypto");
    add_lib_name(ctx, "Cryptonite");

    add_default_speed_measure(ctx, MB_STRING_VALUE);

    xtest_dstu7564(xtest_ctx, ctx);
    xtest_dstu7624(xtest_ctx, ctx);

    table_builder_free(ctx);
#endif /* __APPLE__ || __arm__ */

    ctx = table_builder_alloc(2);

    add_lib_name(ctx, "bee2");
    add_lib_name(ctx, "Cryptonite");

    add_default_speed_measure(ctx, OP_STRING_VALUE);
    xtest_dstu4145(ctx);

    table_builder_free(ctx);

     ctx = table_builder_alloc(XTEST_LIB_NUM);

    add_lib_name(ctx, "OpenSSL");
    add_lib_name(ctx, "Gcrypt");
    add_lib_name(ctx, "Cryptonite");


    add_default_speed_measure(ctx, MB_STRING_VALUE);
    /*Hashes*/
    xtest_md5(xtest_ctx, ctx);

    xtest_ripemd(xtest_ctx, ctx);

    xtest_gost34_311(xtest_ctx, ctx);

    xtest_sha(xtest_ctx, ctx);

    /*Ciphers*/
    xtest_des(xtest_ctx, ctx);

    xtest_gost28147(xtest_ctx, ctx);

    xtest_aes(xtest_ctx, ctx);

    add_default_speed_measure(ctx, OP_STRING_VALUE);
    xtest_rsa(ctx);
    xtest_ecdsa(ctx);

    table_builder_free(ctx);
    rnd_data_free(xtest_ctx);

LOOP_NUM = 1;
    PR("\n+------------------------------------------------------------------------------+\n");
    PR("                       CROSS TESTS (data = 4 MB, 1 thread)                       \n");
    PR("+------------------------------------------------------------------------------+\n");
    data_size_byte = MODE_4mb;
    xtest_ctx = rnd_generate(data_size_byte);

#if !(defined(__APPLE__) || defined(__arm__) || defined(__aarch64__) || (defined(__unix__) && !(__linux__)))
    ctx = table_builder_alloc(2);

    add_lib_name(ctx, "Libcppcrypto");
    add_lib_name(ctx, "Cryptonite");

    add_default_speed_measure(ctx, MB_STRING_VALUE);

    xtest_dstu7564(xtest_ctx, ctx);
    xtest_dstu7624(xtest_ctx, ctx);

    table_builder_free(ctx);
#endif

    ctx = table_builder_alloc(XTEST_LIB_NUM);

    add_lib_name(ctx, "OpenSSL");
    add_lib_name(ctx, "Gcrypt");
    add_lib_name(ctx, "Cryptonite");

    add_default_speed_measure(ctx, MB_STRING_VALUE);

    /*Hashes*/
    xtest_md5(xtest_ctx, ctx);

    xtest_ripemd(xtest_ctx, ctx);

    xtest_gost34_311(xtest_ctx, ctx);

    xtest_sha(xtest_ctx, ctx);

    /*Ciphers*/
    xtest_des(xtest_ctx, ctx);

    xtest_gost28147(xtest_ctx, ctx);

    xtest_aes(xtest_ctx, ctx);

    add_default_speed_measure(ctx, OP_STRING_VALUE);
    xtest_rsa(ctx);

    table_builder_free(ctx);
    rnd_data_free(xtest_ctx);

    return (error_count > 0) ? -1 : 0;
}

