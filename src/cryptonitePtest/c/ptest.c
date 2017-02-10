/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <time.h>

#include "ptest.h"

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
} SizeModePtest;

int main(void)
{
    /*Prepare for speed measure.*/
    {
        size_t i = 0;
        double time = clock();
        do {
            ++i;
            i <<= i;
            --i;
        } while (((clock() - time) / CLOCKS_PER_SEC) < 1);
    }

    THREADS_NUM = 1;

    TableBuilder *table_builder = NULL;

    table_builder = table_builder_alloc(1);
    LOOP_NUM = 5000;
    data_size_byte = MODE_2kb;
    PR("+------------------------------------------------------------------------------+\n");
    PR("       PERFORMANCE TESTS (BLOCK: 2 KB, LOOPS: %u, THREAD: %u thread)            \n", LOOP_NUM, THREADS_NUM);
    PR("+------------------------------------------------------------------------------+\n");

    add_lib_name(table_builder, "Cryptonite");
    add_default_speed_measure(table_builder, MB_STRING_VALUE);

    ptest_md5(table_builder);
    ptest_sha1(table_builder);
    ptest_gost34_311(table_builder);
    ptest_sha2(table_builder);
    ptest_dstu7564_hash(table_builder);

    ptest_des(table_builder);
    ptest_gost28147(table_builder);
    ptest_aes(table_builder);
    ptest_dstu7624_cipher(table_builder);

    ptest_sha2_hmac(table_builder);
    ptest_dstu7564_kmac(table_builder);

    ptest_rsa(table_builder);
    ptest_dstu4145(table_builder);
    ptest_ecdsa(table_builder);
    ptest_dsa(table_builder);

    THREADS_NUM = 8;
    PR("+------------------------------------------------------------------------------+\n");
    PR("       PERFORMANCE TESTS (BLOCK: 2 KB, LOOPS: %u, THREAD: %u thread)            \n", LOOP_NUM, THREADS_NUM);
    PR("+------------------------------------------------------------------------------+\n");

    ptest_md5(table_builder);
    ptest_sha1(table_builder);
    ptest_gost34_311(table_builder);
    ptest_sha2(table_builder);
    ptest_dstu7564_hash(table_builder);

    ptest_des(table_builder);
    ptest_gost28147(table_builder);
    ptest_aes(table_builder);
    ptest_dstu7624_cipher(table_builder);

    ptest_sha2_hmac(table_builder);
    ptest_dstu7564_kmac(table_builder);

    ptest_rsa(table_builder);
    ptest_dstu4145(table_builder);
    ptest_ecdsa(table_builder);
    ptest_dsa(table_builder);

    table_builder_free(table_builder);

    return (error_count > 0) ? -1 : 0;
}
